import re
import logging
import hashlib
from typing import Any, List, Dict, Optional
from urllib.parse import urlparse
from app.ai.huggingface_client import HuggingFaceClient
from app.ai.url_analyzer import URLAnalyzer
from app.ai.misinformation_analyzer import MisinformationAnalyzer

logger = logging.getLogger("mailshield.scoring")

# Dangerous attachment extensions
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".msi", ".msp", ".hta", ".cpl", ".pif", ".com", ".gadget",
    ".app", ".dll", ".jar"
}

SCRIPT_EXTENSIONS = {
    ".vbs", ".js", ".ps1", ".bat", ".cmd", ".sh", ".py", ".php", ".wsf", ".hta"
}

SUSPICIOUS_ARCHIVE_EXTENSIONS = {
    ".iso", ".img", ".vhd", ".ace", ".cab", ".7z", ".tar.gz", ".xz"
}

SAFE_DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv",
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".zip"
}

DOUBLE_EXTENSION_PATTERN = re.compile(
    r'\.(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|txt|csv|rtf)\.(exe|scr|bat|cmd|ps1|vbs|js|hta|msi|pif|com|vbe|jar)$',
    re.IGNORECASE
)

MIME_TYPE_DANGEROUS = {
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-executable",
    "application/x-msdos-program",
    "application/x-msi",
    "application/x-bat",
    "application/x-sh",
    "application/x-vbs",
    "application/hta"
}

# Genuine high-risk extortion / credential harvesting / financial lure patterns
# (Must NOT trigger on normal academic announcements like 'mandatory course' or 'exam registration')
AUTHENTIC_LURE_PATTERNS = [
    re.compile(r'\b(?:wire\s+transfer|western\s+union|moneygram)\b', re.IGNORECASE),
    re.compile(r'\b(?:gift\s+card|apple\s+gift|steam\s+card|crypto\s+wallet|send\s+bitcoin)\b', re.IGNORECASE),
    re.compile(r'\b(?:verify\s+your\s+password|enter\s+your\s+credentials|login\s+to\s+unlock|confirm\s+your\s+banking)\b', re.IGNORECASE),
    re.compile(r'\b(?:account\s+(?:will\s+be|has\s+been)\s+(?:terminated|suspended|locked\s+permanently))\b', re.IGNORECASE),
    re.compile(r'\b(?:immediate\s+payment\s+required|unauthorized\s+login\s+detected\s+from)\b', re.IGNORECASE),
    re.compile(r'\b(?:remittance\s+advice|payment\s+overdue\s+invoice\s+#)\b', re.IGNORECASE)
]

SAFE_DOMAINS_WHITELIST = [
    "gmail.com", "google.com", "outlook.com", "microsoft.com", "github.com",
    "bmsit.in", "bmsit.ac.in", "kalantarart.org"
]


class ScoringEngine:
    CANDIDATE_LABELS = [
        "phishing email requesting credentials",
        "scam or invoice fraud requesting money",
        "social engineering or executive impersonation",
        "fake news or misinformation claims",
        "safe legitimate correspondence"
    ]

    # ----------------------------------------------------------------------
    # LAYER 1: ATTACHMENT, LINK, AND CONTENT SECURITY (0 - 100 Risk)
    # ----------------------------------------------------------------------
    @classmethod
    def analyze_layer1_content_security(
        cls,
        subject: str,
        body_text: str,
        links: list[str],
        attachments: list[dict],
        is_trusted_sender: bool,
        reasons: list[str],
        recommendations: list[str]
    ) -> tuple[int, list[str], dict[str, Any]]:
        """
        Layer 1: Attachment + Link + Content Security Analysis
        Produces layer1_risk (0 to 100).
        Benign attachments and clean URLs produce 0 risk.
        """
        layer_signals: list[str] = []
        layer_details: dict[str, Any] = {
            "has_suspicious_attachment": False,
            "has_suspicious_url": False,
            "has_credential_phishing": False,
            "attachment_risk": 0,
            "url_risk": 0,
            "content_risk": 0,
            "attachment_findings": [],
            "url_findings": [],
            "content_findings": []
        }

        attachment_risk = 0
        url_risk = 0
        content_risk = 0

        # --- A. Attachment Inspection ---
        for att in (attachments or []):
            fname = str(att.get("filename", "")).strip()
            mime = str(att.get("mime_type", "")).strip().lower()
            sha256 = att.get("sha256")

            if not fname:
                continue

            fname_lower = fname.lower()
            ext = "." + fname_lower.rsplit(".", 1)[-1] if "." in fname_lower else ""

            # Check 1: Double extension disguise (e.g. invoice.pdf.exe)
            if DOUBLE_EXTENSION_PATTERN.search(fname_lower):
                risk = 95
                signal = f"Dangerous double-extension attachment detected: '{fname}'"
                layer_signals.append(signal)
                reasons.append(signal)
                recommendations.append(f"Do NOT open attachment '{fname}'. Double extensions are used to conceal malware.")
                layer_details["has_suspicious_attachment"] = True
                layer_details["attachment_findings"].append({"file": fname, "threat": "double_extension"})
                attachment_risk = max(attachment_risk, risk)

            # Check 2: Direct executable file types (.exe, .scr, .bat, .ps1, etc.)
            elif ext in EXECUTABLE_EXTENSIONS:
                risk = 90
                signal = f"High-risk executable attachment detected: '{fname}' ({ext})"
                layer_signals.append(signal)
                reasons.append(signal)
                recommendations.append(f"Block executable attachment '{fname}'.")
                layer_details["has_suspicious_attachment"] = True
                layer_details["attachment_findings"].append({"file": fname, "threat": "executable"})
                attachment_risk = max(attachment_risk, risk)

            # Check 3: Dangerous script types (.vbs, .js, .py, etc.)
            elif ext in SCRIPT_EXTENSIONS:
                risk = 75
                signal = f"Suspicious script attachment detected: '{fname}' ({ext})"
                layer_signals.append(signal)
                reasons.append(signal)
                recommendations.append(f"Do NOT execute script attachment '{fname}'.")
                layer_details["has_suspicious_attachment"] = True
                layer_details["attachment_findings"].append({"file": fname, "threat": "script"})
                attachment_risk = max(attachment_risk, risk)

            # Check 4: Suspicious container/archive types (.iso, .img, .vhd, etc.)
            elif ext in SUSPICIOUS_ARCHIVE_EXTENSIONS:
                risk = 55
                signal = f"Suspicious disk image/container attachment detected: '{fname}' ({ext})"
                layer_signals.append(signal)
                reasons.append(signal)
                layer_details["has_suspicious_attachment"] = True
                layer_details["attachment_findings"].append({"file": fname, "threat": "archive"})
                attachment_risk = max(attachment_risk, risk)

            # Check 5: MIME type disguise anomaly (claims document but declared binary executable)
            if mime in MIME_TYPE_DANGEROUS and ext in SAFE_DOCUMENT_EXTENSIONS:
                risk = 90
                signal = f"MIME type disguise anomaly: attachment '{fname}' has dangerous MIME type '{mime}'"
                layer_signals.append(signal)
                reasons.append(signal)
                layer_details["has_suspicious_attachment"] = True
                layer_details["attachment_findings"].append({"file": fname, "threat": "mime_mismatch"})
                attachment_risk = max(attachment_risk, risk)

            # Normal document attachment (.pdf, .docx, .xlsx, .jpg, etc.) = 0 risk!
            if sha256:
                layer_details["attachment_findings"].append({"file": fname, "sha256": sha256})

        # --- B. Link / URL Security Analysis ---
        if links:
            url_max_score, url_reports, url_reasons, url_recs = URLAnalyzer.analyze_urls(links)
            url_risk = url_max_score
            for u_rep in url_reports:
                u_score = u_rep.get("risk_score", 0)
                u_host = u_rep.get("hostname", "")
                if u_score >= 80:
                    layer_details["has_suspicious_url"] = True
                    for r in u_rep.get("reasons", []):
                        if r not in layer_signals:
                            layer_signals.append(r)
                        if r not in reasons:
                            reasons.append(r)
                    for rec in u_rep.get("recommendations", []):
                        if rec not in recommendations:
                            recommendations.append(rec)

        # --- C. Content Language & Urgency Analysis ---
        subject_str = subject or ""
        body_str = body_text or ""
        full_content = f"{subject_str}\n{body_str}"

        # Search for authentic phishing lure patterns
        matched_lures = [p.pattern for p in AUTHENTIC_LURE_PATTERNS if p.search(full_content)]

        if matched_lures and not is_trusted_sender:
            content_risk = 75
            signal = "High-risk credential harvesting, payment coercion, or account termination threat language detected"
            layer_signals.append(signal)
            reasons.append(signal)
            recommendations.append("Be alert: email contains coercive threat language demanding immediate financial or credential action.")
            layer_details["has_credential_phishing"] = True
        else:
            content_risk = 0

        # Layer 1 Risk is the highest genuine threat vector identified in content
        layer1_risk = max(attachment_risk, url_risk, content_risk)

        layer_details["attachment_risk"] = attachment_risk
        layer_details["url_risk"] = url_risk
        layer_details["content_risk"] = content_risk
        layer_details["risk"] = layer1_risk

        if layer1_risk == 0:
            layer_signals.append("Content, links, and attachments verified clean (0 threat indicators)")

        if layer1_risk >= 75:
            status = "critical"
        elif layer1_risk >= 50:
            status = "elevated"
        elif layer1_risk >= 25:
            status = "suspicious"
        else:
            status = "safe"

        layer_details["status"] = status
        return layer1_risk, layer_signals, layer_details

    # ----------------------------------------------------------------------
    # LAYER 2: MAIL TRANSPORT PATH & HEADER FORENSICS (0 - 100 Risk)
    # ----------------------------------------------------------------------
    @classmethod
    def analyze_layer2_transport_forensics(
        cls,
        authentication: Any,
        network_intelligence: Any,
        route_hops: list,
        received_chain: list,
        raw_headers: list,
        clean_sender_domain: str,
        reasons: list[str],
        recommendations: list[str]
    ) -> tuple[int, list[str], dict[str, Any]]:
        """
        Layer 2: Mail Transport Path / Header / IP Forensic Analysis
        Produces layer2_risk (0 to 100).
        Normal passing SPF/DKIM/DMARC and normal public hops produce 0 risk.
        """
        layer_signals: list[str] = []
        layer_details: dict[str, Any] = {
            "has_impersonation": False,
            "has_header_spoofing": False,
            "origin_ip_candidate": network_intelligence.ip if network_intelligence else None,
            "hop_count": len(received_chain or route_hops or []),
            "auth_risk": 0,
            "routing_risk": 0,
            "header_risk": 0,
            "risk": 0
        }

        auth_risk = 0
        routing_risk = 0
        header_risk = 0

        # --- A. Authentication Results (SPF, DKIM, DMARC) ---
        spf = (authentication.spf if authentication else "unknown").lower()
        dkim = (authentication.dkim if authentication else "unknown").lower()
        dmarc = (authentication.dmarc if authentication else "unknown").lower()

        auth_summary = f"SPF: {spf.upper()}, DKIM: {dkim.upper()}, DMARC: {dmarc.upper()}"
        layer_signals.append(auth_summary)

        # SPF or DKIM Hard Fail is a cryptographic failure indicating spoofing
        if spf == "fail" or dkim == "fail" or dmarc == "fail":
            auth_risk = 70
            signal = f"Cryptographic authentication failure: {auth_summary}"
            layer_signals.append(signal)
            reasons.append("Cryptographic authentication failed (SPF, DKIM, or DMARC Fail)")
            recommendations.append("Email failed sender authentication. Domain identity cannot be cryptographically verified.")
            layer_details["has_header_spoofing"] = True
        elif spf == "pass" and dkim == "pass":
            # BENIGN: 0 risk!
            auth_risk = 0
        elif spf == "pass" or dkim == "pass":
            # Passing SPF or DKIM = 0 risk
            auth_risk = 0
        else:
            # Sub-optimal alignment (none/unknown/neutral) on standard email is low uncertainty, not critical threat
            auth_risk = 15
            signal = "Sub-optimal authentication alignment: missing or neutral DKIM/DMARC records"
            layer_signals.append(signal)

        # --- B. Received Hops & Routing ---
        hop_count = len(received_chain or route_hops or [])
        if hop_count > 0:
            layer_signals.append(f"{hop_count} Received hop{'s' if hop_count != 1 else ''} analyzed")

        # Origin IP Candidate & Network Intelligence
        if network_intelligence and network_intelligence.ip:
            ip_val = network_intelligence.ip
            isp_val = (network_intelligence.isp or "").lower()
            vpn_val = (network_intelligence.vpn_proxy_tor or "").lower()
            country_val = network_intelligence.country or "Unknown"

            layer_signals.append(f"Origin IP candidate: {ip_val} ({country_val})")

            # Check for genuine bulletproof / Tor / VPN exit node infrastructure
            is_vpn_tor = "vpn" in vpn_val or "tor" in vpn_val or "vpn" in isp_val or "tor" in isp_val
            is_bulletproof = any(w in isp_val for w in ["bulletproof", "m247", "packethub", "darknet"])

            if is_vpn_tor or is_bulletproof:
                routing_risk = 60
                signal = "Anonymized transport route detected (VPN/Tor exit or bulletproof hosting provider)"
                layer_signals.append(signal)
                reasons.append(signal)
                layer_details["has_impersonation"] = True
            else:
                # Normal public cloud / residential / ISP IP is NEUTRAL = 0 risk!
                routing_risk = 0

        # --- C. Header Inconsistencies & Impersonation ---
        if raw_headers:
            header_map = {str(h.get("name", "")).lower(): str(h.get("value", "")) for h in raw_headers}
            from_hdr = header_map.get("from", "").lower()
            return_path = header_map.get("return-path", "").lower()
            reply_to = header_map.get("reply-to", "").lower()

            # Check Return-Path vs From domain mismatch
            if return_path and from_hdr:
                from_domain = from_hdr.split("@")[-1].strip(">").strip() if "@" in from_hdr else ""
                rp_domain = return_path.split("@")[-1].strip(">").strip() if "@" in return_path else ""
                if from_domain and rp_domain and from_domain != rp_domain:
                    # Ignore legitimate email service providers and bounce handlers
                    is_legit_esp = any(b in rp_domain for b in [
                        "bnc", "bounce", "mailchimp", "sendgrid", "amazonses", "google",
                        "postmark", "zendesk", "freshdesk", "hubspot", "salesforce"
                    ])
                    if not is_legit_esp:
                        header_risk = 50
                        signal = f"Return-Path domain mismatch: claims '{from_domain}' but returns to '{rp_domain}'"
                        layer_signals.append(signal)
                        reasons.append(signal)
                        layer_details["has_header_spoofing"] = True

            # Check Reply-To diversion
            if reply_to and from_hdr:
                from_domain = from_hdr.split("@")[-1].strip(">").strip() if "@" in from_hdr else ""
                reply_domain = reply_to.split("@")[-1].strip(">").strip() if "@" in reply_to else ""
                if from_domain and reply_domain and from_domain != reply_domain:
                    is_legit_reply = any(b in reply_domain for b in ["zendesk", "freshdesk", "google", "microsoft"])
                    if not is_legit_reply:
                        header_risk = max(header_risk, 45)
                        signal = f"Reply-To diversion: replies redirect to external domain '{reply_domain}'"
                        layer_signals.append(signal)
                        reasons.append(signal)
                        layer_details["has_impersonation"] = True

        layer2_risk = min(100, max(auth_risk, routing_risk, header_risk))

        layer_details["auth_risk"] = auth_risk
        layer_details["routing_risk"] = routing_risk
        layer_details["header_risk"] = header_risk
        layer_details["risk"] = layer2_risk

        if layer2_risk >= 75:
            status = "critical"
        elif layer2_risk >= 50:
            status = "elevated"
        elif layer2_risk >= 25:
            status = "suspicious"
        else:
            status = "safe"

        layer_details["status"] = status
        return layer2_risk, layer_signals, layer_details

    # ----------------------------------------------------------------------
    # LAYER 3: AI BEHAVIORAL & HISTORICAL ANALYSIS (0 - 100 Risk)
    # ----------------------------------------------------------------------
    @classmethod
    def analyze_layer3_behavioral_ai(
        cls,
        subject: str,
        body_text: str,
        sender: str,
        historical_emails: Optional[list],
        is_trusted_sender: bool,
        reasons: list[str],
        recommendations: list[str]
    ) -> tuple[int, list[str], dict[str, Any]]:
        """
        Layer 3: AI Behavioral / Historical Analysis
        Produces layer3_risk (0 to 100).
        New senders return insufficient_history with 0 risk.
        Known consistent senders return known_sender with 0 risk.
        """
        layer_signals: list[str] = []
        layer_details: dict[str, Any] = {
            "has_history": False,
            "history_count": 0,
            "historical_status": "insufficient_history",
            "has_behavioral_anomaly": False,
            "risk": 0
        }

        subject_str = subject or ""
        body_str = body_text or ""
        full_content = f"{subject_str}\n{body_str}"

        history_list = historical_emails or []
        history_count = len(history_list)

        layer3_risk = 0

        if history_count == 0:
            # NO SENDER HISTORY: Insufficient history -> NEUTRAL (0 risk)
            layer_details["has_history"] = False
            layer_details["history_count"] = 0
            layer_details["historical_status"] = "insufficient_history"
            signal = "Insufficient sender history (First-time sender: 0 prior messages observed in database)"
            layer_signals.append(signal)

            # Check if this first-time sender is using authentic phishing/extortion lures
            has_lures = any(p.search(full_content) for p in AUTHENTIC_LURE_PATTERNS)
            if has_lures:
                layer3_risk = 60
                sig_urge = "First-time sender exhibiting immediate credential harvesting / payment demand pattern"
                layer_signals.append(sig_urge)
                reasons.append(sig_urge)
            else:
                # Normal first-time sender = 0 risk!
                layer3_risk = 0

        else:
            # KNOWN SENDER: Real baseline comparison
            layer_details["has_history"] = True
            layer_details["history_count"] = history_count
            layer_details["historical_status"] = "known_sender"

            # Check if historical emails were routine and calm
            hist_urgency_count = sum(
                1 for h in history_list
                if any(p.search(f"{getattr(h, 'subject', '')} {getattr(h, 'body_text', '')}") for p in AUTHENTIC_LURE_PATTERNS)
            )

            is_historically_calm = (hist_urgency_count == 0)
            current_has_lures = any(p.search(full_content) for p in AUTHENTIC_LURE_PATTERNS)

            # Anomaly: Known sender historically calm suddenly sends extortion/credential phishing
            if is_historically_calm and current_has_lures:
                layer3_risk = 75
                signal = f"Sender behavior differs from historical baseline: sudden urgency/coercion spike across {history_count} previous interactions"
                layer_signals.append(signal)
                reasons.append(signal)
                recommendations.append("Known sender is exhibiting unprecedented urgency. Verify identity via an independent communication channel.")
                layer_details["has_behavioral_anomaly"] = True
            else:
                # Normal consistent behavior with known sender = 0 risk!
                layer3_risk = 0
                signal = f"Known sender with consistent communication history ({history_count} prior messages; no behavioral anomaly)"
                layer_signals.append(signal)

        layer_details["risk"] = layer3_risk

        if layer3_risk >= 75:
            status = "critical"
        elif layer3_risk >= 50:
            status = "elevated"
        elif layer3_risk >= 25:
            status = "suspicious"
        else:
            status = "safe"

        layer_details["status"] = status
        return layer3_risk, layer_signals, layer_details

    # ----------------------------------------------------------------------
    # MASTER DETERMINISTIC THREAT ASSESSMENT ENGINE
    # ----------------------------------------------------------------------
    @classmethod
    def analyze_email(
        cls,
        sender: str,
        recipient: str,
        subject: str,
        body_text: str,
        links: list[str],
        attachments: list[dict],
        is_trusted_sender: bool = False,
        authentication: any = None,
        network_intelligence: any = None,
        route_hops: list = None,
        received_chain: list = None,
        raw_headers: list = None,
        historical_emails: list = None
    ) -> dict:
        reasons: list[str] = []
        recommendations: list[str] = []

        # Extract domains
        clean_sender_email = sender.strip().lower()
        match = re.search(r'<([^>]+)>', clean_sender_email)
        if match:
            clean_sender_email = match.group(1).strip().lower()
        clean_sender_domain = clean_sender_email.split("@")[-1] if "@" in clean_sender_email else clean_sender_email

        geo_isp = (network_intelligence.isp or "").lower() if network_intelligence else ""

        is_whitelisted_sender = (
            any(clean_sender_domain == wd or clean_sender_domain.endswith("." + wd) for wd in SAFE_DOMAINS_WHITELIST)
            or any(clean_sender_domain.endswith(suf) for suf in [".edu", ".ac.in", ".edu.in", ".nic.in", ".gov.in", ".gov"])
            or any(w in geo_isp for w in ["google", "microsoft", "academic", "university", "education"])
        )

        auth_passed = False
        if authentication:
            auth_passed = (
                (authentication.spf or "").lower() == "pass"
                and (authentication.dkim or "").lower() == "pass"
            )

        is_trusted_or_whitelisted = (is_whitelisted_sender and auth_passed) or is_trusted_sender

        # ------------------------------------------------------------------
        # EXECUTE THREE REAL EVIDENCE LAYERS (0 - 100 Risk Each)
        # ------------------------------------------------------------------
        # Layer 1: Content, Link & Attachment Security
        l1_risk, l1_signals, l1_details = cls.analyze_layer1_content_security(
            subject=subject,
            body_text=body_text,
            links=links or [],
            attachments=attachments or [],
            is_trusted_sender=is_trusted_or_whitelisted,
            reasons=reasons,
            recommendations=recommendations
        )

        # Layer 2: Mail Transport Path & Header Forensics
        l2_risk, l2_signals, l2_details = cls.analyze_layer2_transport_forensics(
            authentication=authentication,
            network_intelligence=network_intelligence,
            route_hops=route_hops or [],
            received_chain=received_chain or [],
            raw_headers=raw_headers or [],
            clean_sender_domain=clean_sender_domain,
            reasons=reasons,
            recommendations=recommendations
        )

        # Layer 3: AI Behavioral & Historical Analysis
        l3_risk, l3_signals, l3_details = cls.analyze_layer3_behavioral_ai(
            subject=subject,
            body_text=body_text,
            sender=clean_sender_email,
            historical_emails=historical_emails or [],
            is_trusted_sender=is_trusted_or_whitelisted,
            reasons=reasons,
            recommendations=recommendations
        )

        # ------------------------------------------------------------------
        # FORMULA (STEP 9):
        # final_score = (layer1_risk * 0.45) + (layer2_risk * 0.20) + (layer3_risk * 0.35)
        # ------------------------------------------------------------------
        weighted_score = (l1_risk * 0.45) + (l2_risk * 0.20) + (l3_risk * 0.35)
        overall_score = min(100, max(0, int(round(weighted_score))))

        # Confidence
        if l3_details.get("has_history"):
            base_confidence = 0.95
        elif is_trusted_or_whitelisted:
            base_confidence = 0.94
        else:
            base_confidence = 0.88

        # Severity Tier
        if overall_score >= 75:
            severity = "critical"
        elif overall_score >= 50:
            severity = "high"
        elif overall_score >= 25:
            severity = "low"
        else:
            severity = "safe"

        # ------------------------------------------------------------------
        # DYNAMIC EVIDENCE-BASED PRIMARY VERDICT (STEP 12)
        # ------------------------------------------------------------------
        if overall_score < 25:
            verdict = "No Significant Threat Detected"
        else:
            if l1_details.get("has_suspicious_attachment"):
                verdict = "Malicious Attachment Detected"
            elif l1_details.get("has_suspicious_url"):
                verdict = "Suspicious URL Detected"
            elif l2_details.get("has_impersonation") or l2_details.get("has_header_spoofing"):
                verdict = "Possible Impersonation"
            elif l3_details.get("has_behavioral_anomaly"):
                verdict = "Sender Behavior Anomaly"
            elif l1_details.get("has_credential_phishing") or (l1_risk >= 60 and l2_risk >= 50):
                verdict = "Phishing"
            elif overall_score >= 75:
                verdict = "Critical Threat"
            elif overall_score >= 50:
                verdict = "Suspicious Email"
            else:
                verdict = "Low Risk Suspicious"

        threat_type = verdict

        if not recommendations:
            recommendations.append("Email appears clean. Standard browsing caution applies.")

        # Compute layer point contributions for UI breakdown:
        # Layer 1 max: 40 pts, Layer 2 max: 25 pts, Layer 3 max: 35 pts
        l1_ui_score = int(round(l1_risk * 0.40))
        l2_ui_score = int(round(l2_risk * 0.25))
        l3_ui_score = int(round(l3_risk * 0.35))

        layers_breakdown = {
            "content_security": {
                "score": l1_ui_score,
                "max_score": 40,
                "risk": l1_risk,
                "status": l1_details["status"],
                "signals": l1_signals,
                "details": l1_details
            },
            "transport_forensics": {
                "score": l2_ui_score,
                "max_score": 25,
                "risk": l2_risk,
                "status": l2_details["status"],
                "signals": l2_signals,
                "details": l2_details
            },
            "behavioral_ai": {
                "score": l3_ui_score,
                "max_score": 35,
                "risk": l3_risk,
                "status": l3_details["status"],
                "signals": l3_signals,
                "has_history": l3_details.get("has_history", False),
                "history_count": l3_details.get("history_count", 0),
                "historical_status": l3_details.get("historical_status", "insufficient_history"),
                "details": l3_details
            }
        }

        breakdown = {
            "auth_score": l2_ui_score,
            "geo_score": 0,
            "url_score": l1_ui_score,
            "nlp_score": l3_ui_score,
            "header_score": l2_ui_score,

            "layers": layers_breakdown,
            "verdict": verdict,
            "severity": severity,

            "phishing_score": l1_ui_score,
            "scam_score": l2_ui_score,
            "misinformation_score": 0,
            "social_engineering_score": l3_ui_score
        }

        unique_reasons = list(dict.fromkeys(reasons))
        unique_recs = list(dict.fromkeys(recommendations))
        _, url_reports, _, _ = URLAnalyzer.analyze_urls(links or [])

        return {
            "risk_score": overall_score,
            "confidence": base_confidence,
            "threat_type": threat_type,
            "verdict": verdict,
            "severity": severity,
            "reasons": unique_reasons,
            "recommendations": unique_recs,
            "breakdown": breakdown,
            "layers": layers_breakdown,
            "url_reports": url_reports
        }
