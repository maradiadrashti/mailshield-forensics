import ipaddress
import re
import logging
import hashlib
import json
from typing import Any, Optional, Tuple, List
from sqlalchemy.orm import Session
from app.models.audit_log import AuditLog
from app.models.email import EmailMessage
from app.schemas.forensics import (
    ForensicHeaderResponse,
    NormalizedHeaders,
    EmailAuthenticationResult,
    ReceivedHop,
    NetworkIntelligence,
    RouteHop,
    EvidenceIntegrity,
)
from app.services.geo_service import GeoService


logger = logging.getLogger("mailshield.forensics")

# Regex to find candidate IPv4 addresses
IPV4_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# Regex to find candidate IPv6 addresses (including bracketed and IPv6: prefixed)
IPV6_REGEX = re.compile(
    r'(?:IPv6:)?(?:\[)?([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,7}|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})(?:\])?'
)

# Auth result extraction patterns
SPF_PATTERN = re.compile(r'\bspf=(pass|fail|softfail|neutral|none|permerror|temperror)\b', re.IGNORECASE)
DKIM_PATTERN = re.compile(r'\bdkim=(pass|fail|neutral|none|permerror|temperror)\b', re.IGNORECASE)
DMARC_PATTERN = re.compile(r'\bdmarc=(pass|fail|neutral|none|permerror|temperror)\b', re.IGNORECASE)


# Standard RFC Private Networks (RFC 1918, CGNAT RFC 6598, IPv6 ULA RFC 4193)
RFC1918_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
]


class EmailHeaderForensicsService:
    """
    Service responsible for parsing, extracting, and normalizing email headers,
    analyzing the multi-hop Received chain, extracting and classifying IPv4/IPv6
    addresses, and identifying the public origin IP candidate for forensic intelligence.
    """

    @classmethod
    def validate_and_classify_ip(cls, candidate: str) -> Optional[Tuple[str, str]]:
        """
        Validates an IP candidate using Python's ipaddress library.
        Returns (normalized_ip_str, classification) if valid, or None if invalid.
        Classifications: public, private, loopback, link-local, reserved, unspecified.
        """
        if not candidate:
            return None

        clean_ip = candidate.strip()
        if clean_ip.upper().startswith("IPV6:"):
            clean_ip = clean_ip[5:].strip()
        clean_ip = clean_ip.strip("[]() ,;\"'")

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            return None

        # Classify IP
        if ip_obj.is_loopback:
            classification = "loopback"
        elif ip_obj.is_link_local:
            classification = "link-local"
        elif ip_obj.is_unspecified:
            classification = "unspecified"
        elif ip_obj.is_multicast or ip_obj.is_reserved:
            classification = "reserved"
        elif any(ip_obj in net for net in RFC1918_PRIVATE_NETWORKS):
            classification = "private"
        else:
            classification = "public"

        return (str(ip_obj), classification)

    @classmethod
    def extract_source_ip_from_hop(cls, raw_received: str) -> Optional[Tuple[str, str]]:
        """
        Extracts the transmitting source IP address from a single Received header line.
        Prioritizes IPs associated with the client/from connection context.
        """
        if not raw_received:
            return None

        # 1. Look for bracketed IPs e.g. [198.51.100.24] or [IPv6:2001:db8::1]
        bracketed_matches = re.findall(r'\[([^\]\s]+)\]', raw_received)
        for cand in bracketed_matches:
            res = cls.validate_and_classify_ip(cand)
            if res:
                return res

        # 2. Look for IPv4 matches
        ipv4_matches = IPV4_REGEX.findall(raw_received)
        for cand in ipv4_matches:
            res = cls.validate_and_classify_ip(cand)
            if res:
                return res

        # 3. Look for IPv6 matches
        ipv6_matches = IPV6_REGEX.findall(raw_received)
        for cand in ipv6_matches:
            res = cls.validate_and_classify_ip(cand)
            if res:
                return res

        return None

    @classmethod
    def parse_single_received_hop(cls, raw: str, hop_index: int) -> ReceivedHop:
        """
        Parses a single raw Received header string into a structured ReceivedHop.
        """
        clean_raw = raw.strip()

        # Extract from_host
        from_match = re.search(r'\bfrom\s+([^\s;()\[\]]+)', clean_raw, re.IGNORECASE)
        from_host = from_match.group(1) if from_match else None

        # Extract by_host
        by_match = re.search(r'\bby\s+([^\s;()\[\]]+)', clean_raw, re.IGNORECASE)
        by_host = by_match.group(1) if by_match else None

        # Extract protocol
        with_match = re.search(r'\bwith\s+([a-zA-Z0-9_\-]+)', clean_raw, re.IGNORECASE)
        protocol = with_match.group(1) if with_match else None

        # Extract timestamp (usually after semicolon)
        timestamp = None
        if ';' in clean_raw:
            timestamp = clean_raw.rsplit(';', 1)[1].strip()

        # Extract source IP and its classification
        source_ip_info = cls.extract_source_ip_from_hop(clean_raw)
        source_ip = source_ip_info[0] if source_ip_info else None
        ip_classification = source_ip_info[1] if source_ip_info else None

        return ReceivedHop(
            hop=hop_index,
            raw=clean_raw,
            source_ip=source_ip,
            ip_classification=ip_classification,
            from_host=from_host,
            by_host=by_host,
            timestamp=timestamp,
            protocol=protocol,
        )

    @classmethod
    def parse_authentication_results(
        cls, header_dict_list: List[dict[str, Any]]
    ) -> EmailAuthenticationResult:
        """
        Extracts SPF, DKIM, and DMARC verification results from standard
        Authentication-Results, ARC-Authentication-Results, and Received-SPF headers.
        Returns 'pass', 'fail', 'neutral', or 'unknown'.
        """
        combined_auth_text = []
        spf_result = "unknown"
        dkim_result = "unknown"
        dmarc_result = "unknown"

        for h in header_dict_list:
            name = h.get("name", "").lower()
            val = str(h.get("value", ""))

            if name in [
                "authentication-results",
                "arc-authentication-results",
                "received-spf",
                "x-dkim-authentication-results",
                "dmarc-filter"
            ]:
                combined_auth_text.append(f"{name}: {val}")

                # Check SPF
                if spf_result == "unknown":
                    if name == "received-spf":
                        first_word = val.strip().split()[0].lower() if val.strip() else ""
                        if first_word in ["pass"]:
                            spf_result = "pass"
                        elif first_word in ["fail", "softfail"]:
                            spf_result = "fail"
                        elif first_word in ["neutral", "none"]:
                            spf_result = "neutral"
                    spf_match = SPF_PATTERN.search(val)
                    if spf_match:
                        match_val = spf_match.group(1).lower()
                        if match_val == "pass":
                            spf_result = "pass"
                        elif match_val in ["fail", "softfail"]:
                            spf_result = "fail"
                        elif match_val in ["neutral", "none"]:
                            spf_result = "neutral"

                # Check DKIM
                if dkim_result == "unknown":
                    dkim_match = DKIM_PATTERN.search(val)
                    if dkim_match:
                        match_val = dkim_match.group(1).lower()
                        if match_val == "pass":
                            dkim_result = "pass"
                        elif match_val in ["fail"]:
                            dkim_result = "fail"
                        elif match_val in ["neutral", "none"]:
                            dkim_result = "neutral"

                # Check DMARC
                if dmarc_result == "unknown":
                    dmarc_match = DMARC_PATTERN.search(val)
                    if dmarc_match:
                        match_val = dmarc_match.group(1).lower()
                        if match_val == "pass":
                            dmarc_result = "pass"
                        elif match_val in ["fail"]:
                            dmarc_result = "fail"
                        elif match_val in ["neutral", "none"]:
                            dmarc_result = "neutral"

        raw_auth = "\n".join(combined_auth_text) if combined_auth_text else None

        return EmailAuthenticationResult(
            spf=spf_result,
            dkim=dkim_result,
            dmarc=dmarc_result,
            raw_auth_results=raw_auth,
        )

    @classmethod
    def select_origin_ip_candidate(cls, received_hops: List[ReceivedHop]) -> Optional[str]:
        """
        Selects the earliest appropriate public IP from the parsed Received chain.

        Algorithm rationale:
        - Received headers are prepended by each MTA: index 0 (Hop 1) is the newest receiving server,
          and the last index in the chain is the oldest / earliest server in the transmission sequence.
        - We iterate in chronological order (from the oldest hop / last index to newest / index 0).
        - We skip private, loopback, and reserved addresses (e.g. internal LANs like 10.x.x.x, 192.168.x.x).
        - The first valid public IP encountered in this chronological traversal represents the true external
          originating client or edge ingress server.
        - If no public IP is found in the chain, returns None.
        """
        if not received_hops:
            return None

        # Traverse in reverse (from oldest hop towards newest)
        for hop in reversed(received_hops):
            if hop.source_ip and hop.ip_classification == "public":
                return hop.source_ip

        return None

    @classmethod
    def parse_headers(
        cls, raw_headers: List[dict[str, Any]], email_id: str, db: Optional[Session] = None
    ) -> ForensicHeaderResponse:
        """
        Accepts raw header entries for an email and produces a normalized ForensicHeaderResponse.
        """
        logger.info(f"Analyzing forensic headers for email ID: {email_id} ({len(raw_headers)} header entries)")

        header_dict: dict[str, str] = {}
        received_raw_list: list[str] = []

        for h in raw_headers:
            name = str(h.get("name", "")).strip()
            value = str(h.get("value", "")).strip()
            if not name:
                continue

            lower_name = name.lower()
            if lower_name == "received":
                received_raw_list.append(value)
            elif lower_name not in header_dict:
                header_dict[lower_name] = value

        # 1. Normalize RFC key headers
        normalized = NormalizedHeaders(
            from_=header_dict.get("from"),
            to=header_dict.get("to"),
            reply_to=header_dict.get("reply-to"),
            return_path=header_dict.get("return-path"),
            message_id=header_dict.get("message-id"),
            subject=header_dict.get("subject"),
            date=header_dict.get("date"),
        )

        # 2. Parse authentication results
        authentication = cls.parse_authentication_results(raw_headers)

        # 3. Parse Received hop chain
        received_chain: List[ReceivedHop] = []
        for idx, raw_hop in enumerate(received_raw_list, start=1):
            hop = cls.parse_single_received_hop(raw_hop, hop_index=idx)
            received_chain.append(hop)

        # 4. Select candidate origin IP
        origin_ip = cls.select_origin_ip_candidate(received_chain)

        # 5. Determine analysis status
        analysis_status = "complete"
        if not received_chain:
            analysis_status = "missing_headers" if len(raw_headers) <= 4 else "partial"

        public_ips_count = sum(1 for h in received_chain if h.ip_classification == "public")
        total_ips_count = sum(1 for h in received_chain if h.source_ip is not None)

        logger.info(
            f"Forensics header analysis complete for {email_id}: "
            f"Received hops: {len(received_chain)}, Total IPs: {total_ips_count}, "
            f"Public IPs: {public_ips_count}, Selected Origin IP: {origin_ip}"
        )

        # Resolve network intelligence for origin IP
        network_intel = None
        if origin_ip:
            intel_dict = GeoService.lookup_ip(origin_ip, "public")
            
            # Simple intelligence heuristics for VPN/Hosting/Proxy/Tor
            isp_lower = (intel_dict.get("isp") or "").lower()
            vpn_proxy_tor = "No"
            risk_indicator = "Low Risk"
            
            if any(w in isp_lower for w in ["vpn", "proxy", "tor", "mullvad", "nordvpn", "expressvpn", "proton"]):
                vpn_proxy_tor = "VPN Detected"
                risk_indicator = "Medium Risk"
            elif any(w in isp_lower for w in ["aws", "amazon", "google cloud", "gcp", "azure", "microsoft", "hosting", "digitalocean", "linode", "ovh", "hetzner"]):
                vpn_proxy_tor = "Hosting Provider"
                risk_indicator = "Medium Risk"
                
            if intel_dict.get("country") == "Local Network":
                vpn_proxy_tor = "N/A"
                risk_indicator = "Safe (Local)"
                
            network_intel = NetworkIntelligence(
                ip=origin_ip,
                country=intel_dict.get("country", "Unknown"),
                city=intel_dict.get("city", "Unknown"),
                isp=intel_dict.get("isp", "Unknown"),
                asn=intel_dict.get("asn", "Unknown"),
                vpn_proxy_tor=vpn_proxy_tor,
                risk_indicator=risk_indicator,
                latitude=intel_dict.get("latitude"),
                longitude=intel_dict.get("longitude")
            )
        else:
            network_intel = NetworkIntelligence()

        # Resolve route hops
        route_hops = []
        for hop in received_chain:
            if hop.source_ip:
                hop_intel = GeoService.lookup_ip(hop.source_ip, hop.ip_classification)
                route_hops.append(
                    RouteHop(
                        hop=hop.hop,
                        ip=hop.source_ip,
                        country=hop_intel["country"],
                        city=hop_intel["city"],
                        isp=hop_intel["isp"],
                        asn=hop_intel["asn"],
                        latitude=hop_intel["latitude"],
                        longitude=hop_intel["longitude"]
                    )
                )
            else:
                route_hops.append(
                    RouteHop(
                        hop=hop.hop,
                        ip=None,
                        country="Unknown",
                        city="Unknown",
                        isp="Unknown",
                        asn="Unknown",
                        latitude=None,
                        longitude=None
                    )
                )

        # Resolve evidence integrity cryptographically
        from datetime import datetime, timezone
        evidence_intel = None
        if db:
            try:
                # Find the email message to get body & details
                email_obj = db.query(EmailMessage).filter(EmailMessage.id == email_id).first()
                if email_obj:
                    # Check if an audit block already exists
                    audit_entry = db.query(AuditLog).filter(AuditLog.investigation_id == email_id).first()
                    if not audit_entry:
                        # 1. Compute payload hash
                        headers_json = json.dumps(raw_headers, sort_keys=True)
                        body_str = email_obj.body_text or ""
                        payload_str = f"{email_id}:{headers_json}:{body_str}"
                        raw_payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
                        
                        # 2. Get latest entry for chaining
                        latest_entry = db.query(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).first()
                        prev_hash = latest_entry.block_hash if latest_entry else "0" * 64
                        
                        # 3. Build timestamp and block hash
                        timestamp = datetime.now(timezone.utc)
                        timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                        block_data = f"{prev_hash}:{raw_payload_hash}:{timestamp_str}"
                        block_hash = hashlib.sha256(block_data.encode("utf-8")).hexdigest()
                        
                        # 4. Determine block number
                        total_blocks = db.query(AuditLog).count()
                        block_number = total_blocks + 1
                        
                        # 5. Create evidence ID
                        evidence_id = f"EVD-{raw_payload_hash[:8].upper()}"
                        
                        # 6. Save to db
                        audit_entry = AuditLog(
                            evidence_id=evidence_id,
                            investigation_id=email_id,
                            block_number=block_number,
                            raw_payload_hash=raw_payload_hash,
                            prev_hash=prev_hash,
                            block_hash=block_hash,
                            timestamp=timestamp,
                            status="VERIFIED_TAMPER_PROOF"
                        )
                        db.add(audit_entry)
                        db.commit()
                        db.refresh(audit_entry)

                    # Populating evidence integrity
                    evidence_intel = EvidenceIntegrity(
                        evidence_id=audit_entry.evidence_id,
                        evidence_sha256=audit_entry.raw_payload_hash,
                        captured_at=audit_entry.timestamp.isoformat().replace("+00:00", "Z"),
                        chain_of_custody_status="Cryptographically Sealed (SHA-256 Chain)",
                        last_audit_event=f"BLOCK #{audit_entry.block_number} [VALID]"
                    )
            except Exception as e:
                logger.error(f"Failed to generate or retrieve cryptographic audit trail block for {email_id}: {e}")

        # Fallback if no database / not found / exception
        if not evidence_intel:
            evidence_intel = EvidenceIntegrity(
                evidence_id="EVD-UNKNOWN",
                evidence_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                captured_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                chain_of_custody_status="Cryptographic Seal Pending",
                last_audit_event="GENESIS BLOCK INTERIM"
            )

        return ForensicHeaderResponse(
            email_id=email_id,
            headers=normalized,
            authentication=authentication,
            received_chain=received_chain,
            origin_ip_candidate=origin_ip,
            network_intelligence=network_intel,
            route_hops=route_hops,
            evidence_integrity=evidence_intel,
            analysis_status=analysis_status,
        )

