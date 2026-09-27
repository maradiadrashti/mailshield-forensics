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

# Legitimate bounce/ESP domains — return-path mismatches from these are NOT spoofing
LEGITIMATE_ESP_DOMAINS = [
    "bnc", "bounce", "mailchimp", "sendgrid", "amazonses", "google",
    "postmark", "zendesk", "freshdesk", "hubspot", "salesforce",
    "constantcontact", "campaignmonitor", "mailgun", "sparkpost"
]

# Legitimate reply-to service domains
LEGITIMATE_REPLY_DOMAINS = [
    "zendesk", "freshdesk", "google", "microsoft", "gmail", "googlegroups"
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
            layer_details["url_findings"] = url_reports
            for u_rep in url_reports:
                u_score = u_rep.get("risk_score", 0)
                if u_score >= 60:  # Threshold: flag suspicious URLs (60+), not just critical (80+)
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

        # --- D. Misinformation & Factual Integrity Analysis ---
        misinfo_result = MisinformationAnalyzer.analyze_text(body_str, subject_str)
        credibility = misinfo_result.get("credibility_score", 100)
        suspicious_sentences = misinfo_result.get("suspicious_sentences", [])
        misinfo_evidence = misinfo_result.get("evidence", [])
        misinfo_risk = 0

        if credibility < 75 or suspicious_sentences:
            misinfo_risk = min(100, max(0, 100 - credibility))
            for ss in suspicious_sentences:
                sig = f"Suspicious claim flagged: \"{ss.get('sentence', '')[:80]}...\" ({ss.get('risk', 'Unverified')})"
                if sig not in layer_signals:
                    layer_signals.append(sig)
                if ss.get('risk') not in reasons:
                    reasons.append(f"Unverified or manipulative claim: {ss.get('risk')}")
            for ev in misinfo_evidence:
                if ev not in reasons:
                    reasons.append(ev)
            recommendations.append("Content contains sensationalist or unverified claims. Independently verify factual integrity before forwarding.")
            layer_details["has_misinformation"] = True
            layer_details["misinformation_findings"] = suspicious_sentences
            layer_details["credibility_score"] = credibility
        else:
            layer_details["has_misinformation"] = False
            layer_details["credibility_score"] = 100
            layer_details["misinformation_findings"] = []

        layer_details["misinfo_risk"] = misinfo_risk

        # Layer 1 Composite: primary threat vector wins, secondary vectors add 15% bonus corroboration
        primary_risk = max(attachment_risk, url_risk)
        secondary_risk = max(content_risk, misinfo_risk)
        if primary_risk > 0 and secondary_risk > 0:
            layer1_risk = min(100, primary_risk + int(secondary_risk * 0.15))
        elif primary_risk > 0:
            layer1_risk = primary_risk
        elif secondary_risk > 0:
            layer1_risk = secondary_risk
        else:
            layer1_risk = 0

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

        # Tiered auth failure: dual fail is strongest cryptographic spoofing indicator
        if spf == "fail" and dkim == "fail":
            auth_risk = 90
            signal = f"Both SPF and DKIM failed — strong cryptographic spoofing indicator: {auth_summary}"
            layer_signals.append(signal)
            reasons.append("Dual authentication failure (SPF+DKIM fail) — strong spoofing signal")
            recommendations.append("Email failed both SPF and DKIM. Domain identity unverifiable — treat as spoofed.")
            layer_details["has_header_spoofing"] = True
        elif spf == "fail" or dkim == "fail":
            auth_risk = 70
            failing = "SPF" if spf == "fail" else "DKIM"
            signal = f"{failing} authentication failed: {auth_summary}"
            layer_signals.append(signal)
            reasons.append(f"Cryptographic authentication failure ({failing} fail)")
            recommendations.append(f"Email failed {failing} authentication. Sender domain may be spoofed.")
            layer_details["has_header_spoofing"] = True
        elif dmarc == "fail":
            auth_risk = 60
            layer_signals.append(f"DMARC policy failure detected: {auth_summary}")
            reasons.append("DMARC policy failure — domain alignment check failed")
            layer_details["has_header_spoofing"] = True
        elif spf == "pass" and dkim == "pass":
            # Fully authenticated — 0 auth risk
            auth_risk = 0
            layer_signals.append("Sender fully authenticated (SPF pass + DKIM pass)")
        elif spf == "pass" or dkim == "pass":
            # Partial pass — minimal concern
            auth_risk = 5
            layer_signals.append(f"Partial authentication: {auth_summary}")
        else:
            # Neither passed — minor uncertainty
            auth_risk = 15
            signal = "Incomplete authentication records (SPF/DKIM unknown or neutral)"
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

            # Only flag genuine anonymization infrastructure — NOT normal cloud hosting or email providers
            # Gmail, Google Cloud, AWS SES, Microsoft are all legitimate email routing infrastructure
            is_vpn_tor = (
                "vpn detected" in vpn_val
                or "tor" in vpn_val
                or any(w in isp_val for w in ["mullvad", "nordvpn", "expressvpn", "proton vpn", "torproject"])
            )
            is_bulletproof = any(w in isp_val for w in ["bulletproof", "packethub", "darknet", "m247"])

            if is_vpn_tor:
                routing_risk = 60
                signal = f"VPN/Tor anonymized routing detected from IP {ip_val}"
                layer_signals.append(signal)
                reasons.append(signal)
                layer_details["has_impersonation"] = True
            elif is_bulletproof:
                routing_risk = 50
                signal = f"Bulletproof/abusive hosting provider detected: {network_intelligence.isp}"
                layer_signals.append(signal)
                reasons.append(signal)
                layer_details["has_impersonation"] = True
            else:
                # Normal ISP, cloud, or residential IP = 0 routing risk
                routing_risk = 0

        # --- C. Header Inconsistencies & Envelope Spoofing ---
        if raw_headers:
            header_map = {str(h.get("name", "")).lower(): str(h.get("value", "")) for h in raw_headers}
            from_hdr = header_map.get("from", "").lower()
            return_path = header_map.get("return-path", "").lower()
            reply_to = header_map.get("reply-to", "").lower()

            def _extract_domain(addr: str) -> str:
                """Correctly extract domain from RFC 5322 'Name <user@domain>' or bare addresses."""
                if "<" in addr and ">" in addr:
                    addr = addr.split("<")[1].split(">")[0]
                if "@" in addr:
                    return addr.split("@")[-1].strip().rstrip(">").strip()
                return ""

            from_domain = _extract_domain(from_hdr)
            rp_domain = _extract_domain(return_path)
            reply_domain = _extract_domain(reply_to)

            # Check Return-Path vs From domain mismatch
            if from_domain and rp_domain and from_domain != rp_domain:
                if not any(b in rp_domain for b in LEGITIMATE_ESP_DOMAINS):
                    header_risk = max(header_risk, 50)
                    signal = f"Return-Path domain mismatch: From '{from_domain}' but bounces to '{rp_domain}'"
                    layer_signals.append(signal)
                    reasons.append(signal)
                    recommendations.append("Return-Path domain differs from sender — possible spoofing.")
                    layer_details["has_header_spoofing"] = True

            # Check Reply-To diversion — replies being silently redirected to attacker
            if from_domain and reply_domain and from_domain != reply_domain:
                if not any(b in reply_domain for b in LEGITIMATE_REPLY_DOMAINS):
                    header_risk = max(header_risk, 55)
                    signal = f"Reply-To diversion: replies redirected to external domain '{reply_domain}'"
                    layer_signals.append(signal)
                    reasons.append(signal)
                    recommendations.append(f"CAUTION: Replies go to '{reply_domain}', not the sender's domain.")
                    layer_details["has_impersonation"] = True

        # Composite Layer 2: Primary threat vector (auth, header, or routing) plus corroboration
        primary_l2 = max(auth_risk, header_risk, routing_risk)
        # Find secondary indicator if any
        sub_indicators = sorted([auth_risk, header_risk, routing_risk], reverse=True)
        secondary_l2 = sub_indicators[1] if len(sub_indicators) > 1 else 0

        if primary_l2 > 0 and secondary_l2 > 0:
            layer2_risk = min(100, primary_l2 + int(secondary_l2 * 0.15))
        else:
            layer2_risk = primary_l2

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
        links: list[str],
        attachments: list[dict],
        historical_emails: Optional[list],
        historical_results: Optional[list] = None,
        impersonation_candidates: Optional[list] = None,
        is_trusted_sender: bool = False,
        reasons: list[str] = None,
        recommendations: list[str] = None
    ) -> tuple[int, list[str], dict[str, Any]]:
        """
        Layer 3: AI Behavioral / Historical Analysis (0 - 100 Risk)
        Performs real-time multi-dimensional comparison against the user's previous email corpus:
        - Prior communication count & historical threat/safety baseline
        - Display Name Impersonation / Business Email Compromise (BEC) detection
        - Attachment behavioral shift (e.g. unexpected attachments from non-attachment sender)
        - Link / Destination domain novelty against sender history
        - Urgency & coercion sentiment deviation from calm baseline
        - Zero-shot transformer NLP threat classification
        """
        if reasons is None:
            reasons = []
        if recommendations is None:
            recommendations = []

        layer_signals: list[str] = []
        layer_details: dict[str, Any] = {
            "has_history": False,
            "history_count": 0,
            "historical_status": "insufficient_history",
            "has_behavioral_anomaly": False,
            "has_impersonation_anomaly": False,
            "risk": 0
        }

        subject_str = subject or ""
        body_str = body_text or ""
        full_content = f"{subject_str}\n{body_str}"

        history_list = historical_emails or []
        history_count = len(history_list)
        layer3_risk = 0

        # ------------------------------------------------------------------
        # 1. Historical Communication Count & Risk Profile
        # ------------------------------------------------------------------
        if history_count == 0:
            layer_details["has_history"] = False
            layer_details["history_count"] = 0
            layer_details["historical_status"] = "insufficient_history"
            signal = "Insufficient sender history (First-time sender: 0 prior messages observed in database)"
            layer_signals.append(signal)

            # Check if this first-time sender is using authentic phishing/extortion lures
            has_lures = any(p.search(full_content) for p in AUTHENTIC_LURE_PATTERNS)
            if has_lures:
                layer3_risk = max(layer3_risk, 65)
                sig_urge = "First-time sender exhibiting immediate credential harvesting / payment demand pattern"
                layer_signals.append(sig_urge)
                reasons.append(sig_urge)
                layer_details["has_behavioral_anomaly"] = True
        else:
            layer_details["has_history"] = True
            layer_details["history_count"] = history_count
            layer_details["historical_status"] = "known_sender"

            # Check prior analysis results to establish historical risk baseline
            past_scores = [
                r.risk_score for r in (historical_results or [])
                if hasattr(r, 'risk_score') and r.risk_score is not None
            ]
            if past_scores:
                avg_risk = sum(past_scores) / len(past_scores)
                layer_details["historical_avg_risk"] = round(avg_risk, 1)
                if avg_risk < 25 and len(past_scores) >= 1:
                    layer_signals.append(
                        f"Historical safety baseline: {history_count} previous email(s) analyzed with low risk (avg: {int(avg_risk)}/100, verified safe)"
                    )
                elif avg_risk >= 50:
                    repeat_risk = int(avg_risk * 0.7)
                    layer3_risk = max(layer3_risk, repeat_risk)
                    sig = f"Repeat threat pattern: sender has history of flagged emails in database (historical avg risk: {int(avg_risk)}/100)"
                    layer_signals.append(sig)
                    reasons.append(sig)
                    layer_details["has_behavioral_anomaly"] = True
            else:
                layer_signals.append(f"Known sender with {history_count} previous interaction(s) recorded in inbox history")

        # ------------------------------------------------------------------
        # 2. Real-Time Display Name Impersonation / BEC Detection
        # ------------------------------------------------------------------
        if impersonation_candidates:
            known_senders = list(dict.fromkeys(
                getattr(c, 'sender', '') for c in impersonation_candidates if getattr(c, 'sender', '')
            ))
            if known_senders:
                clean_disp = sender.split("<")[0].strip().strip('"').strip("'") if "<" in sender else sender
                bec_sig = (
                    f"Executive/Display Name Spoofing: display name '{clean_disp}' was previously used by "
                    f"legitimate contact ({known_senders[0]}), but current message originates from unrecognized address '{sender}'"
                )
                layer_signals.append(bec_sig)
                reasons.append(bec_sig)
                recommendations.append(
                    "CRITICAL: Suspected Business Email Compromise (BEC). Verify sender identity independently before replying or trusting content."
                )
                layer3_risk = max(layer3_risk, 85)
                layer_details["has_impersonation_anomaly"] = True
                layer_details["has_behavioral_anomaly"] = True

        # ------------------------------------------------------------------
        # 3. Attachment Baseline Behavioral Anomaly (requires 3+ emails for reliable baseline)
        # ------------------------------------------------------------------
        current_att_count = len(attachments or [])
        if history_count >= 3 and current_att_count > 0:
            hist_att_count = 0
            for h in history_list:
                hist_atts = getattr(h, "attachments", None)
                if hist_atts and isinstance(hist_atts, list):
                    hist_att_count += len(hist_atts)
            if hist_att_count == 0:
                att_sig = (
                    f"Unprecedented attachment: sender has 0 attachments across {history_count} prior emails, "
                    f"but now delivers {current_att_count} file(s)"
                )
                layer_signals.append(att_sig)
                reasons.append(att_sig)
                recommendations.append("Sender has never sent attachments before. Heightened caution before opening files.")
                layer3_risk = max(layer3_risk, 45)
                layer_details["has_behavioral_anomaly"] = True
                layer_details["attachment_anomaly"] = {
                    "current_count": current_att_count, "historical_count": 0, "history_emails": history_count
                }

        # ------------------------------------------------------------------
        # 4. Link / Destination Domain Novelty Anomaly
        # ------------------------------------------------------------------
        if history_count >= 2 and links:
            current_domains = set()
            for u in links:
                try:
                    loc = urlparse(u).netloc.lower()
                    if loc:
                        current_domains.add(loc)
                except Exception:
                    pass
            hist_domains = set()
            for h in history_list:
                hist_links = getattr(h, "links", None)
                if hist_links and isinstance(hist_links, list):
                    for u in hist_links:
                        try:
                            loc = urlparse(u).netloc.lower()
                            if loc:
                                hist_domains.add(loc)
                        except Exception:
                            pass
            novel_domains = [
                d for d in current_domains
                if d not in hist_domains and not URLAnalyzer.is_known_safe_infrastructure(d)
            ]
            if novel_domains:
                domain_sig = f"Unseen external link: email directs to domain '{novel_domains[0]}' never observed in prior communications with this sender"
                layer_signals.append(domain_sig)
                reasons.append(domain_sig)
                layer3_risk = max(layer3_risk, 40)
                layer_details["has_behavioral_anomaly"] = True

        # ------------------------------------------------------------------
        # 5. Urgency & Coercion Sentiment Spike vs Historical Baseline
        # ------------------------------------------------------------------
        if history_count > 0:
            hist_urgency = sum(
                1 for h in history_list
                if any(p.search(f"{getattr(h, 'subject', '')} {getattr(h, 'body_text', '')}") for p in AUTHENTIC_LURE_PATTERNS)
            )
            current_has_lures = any(p.search(full_content) for p in AUTHENTIC_LURE_PATTERNS)
            if hist_urgency == 0 and current_has_lures:
                urge_sig = f"Sudden urgency spike: sender tone differs significantly from calm historical baseline ({history_count} prior calm emails)"
                layer_signals.append(urge_sig)
                reasons.append(urge_sig)
                recommendations.append("Known sender is exhibiting unprecedented urgency. Verify identity via an independent communication channel.")
                layer3_risk = max(layer3_risk, 75)
                layer_details["has_behavioral_anomaly"] = True
            elif current_has_lures:
                layer3_risk = max(layer3_risk, 60)

        # ------------------------------------------------------------------
        # 6. AI NLP Zero-Shot Threat Classification (HuggingFace / Heuristics)
        # ------------------------------------------------------------------
        try:
            hf_scores = HuggingFaceClient.classify_text(full_content, cls.CANDIDATE_LABELS)
            if hf_scores:
                phish_prob = hf_scores.get("phishing email requesting credentials", 0.0)
                scam_prob = hf_scores.get("scam or invoice fraud requesting money", 0.0)
                soc_prob = hf_scores.get("social engineering or executive impersonation", 0.0)
                max_threat_prob = max(phish_prob, scam_prob, soc_prob)
                if max_threat_prob >= 0.70:
                    nlp_sig = f"AI transformer classifier detected high threat probability ({int(max_threat_prob * 100)}%)"
                    layer_signals.append(nlp_sig)
                    layer3_risk = max(layer3_risk, int(max_threat_prob * 80))
                    layer_details["nlp_threat_probability"] = round(max_threat_prob, 2)
        except Exception as e:
            logger.debug(f"HuggingFace inference skipped: {e}")

        # Final Layer 3 status & details
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
        historical_emails: list = None,
        historical_results: list = None,
        impersonation_candidates: list = None
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

        # Layer 3: AI Behavioral & Historical Analysis (real previous emails comparison)
        l3_risk, l3_signals, l3_details = cls.analyze_layer3_behavioral_ai(
            subject=subject,
            body_text=body_text,
            sender=clean_sender_email,
            links=links or [],
            attachments=attachments or [],
            historical_emails=historical_emails or [],
            historical_results=historical_results or [],
            impersonation_candidates=impersonation_candidates or [],
            is_trusted_sender=is_trusted_or_whitelisted,
            reasons=reasons,
            recommendations=recommendations
        )

        # ------------------------------------------------------------------
        # COMPOSITE THREAT WEIGHTING:
        # Standard weighted composite: L1 (45%), L2 (20%), L3 (35%)
        # Dominance Floor: Severe single-vector threats (e.g., malware, spoofing, BEC)
        # must never be masked to zero or 'safe' by absence of signals in other layers.
        # ------------------------------------------------------------------
        weighted_score = (l1_risk * 0.45) + (l2_risk * 0.20) + (l3_risk * 0.35)

        max_layer_risk = max(l1_risk, l2_risk, l3_risk)
        if max_layer_risk >= 80:
            dominant_floor = int(max_layer_risk * 0.65)
        elif max_layer_risk >= 50:
            dominant_floor = int(max_layer_risk * 0.50)
        elif max_layer_risk >= 30:
            dominant_floor = int(max_layer_risk * 0.40)
        else:
            dominant_floor = 0

        overall_score = min(100, max(0, int(round(weighted_score)), dominant_floor))

        # Confidence: highest when we have analyzed historical baseline, lowest for first-time senders
        if l3_details.get("historical_analyzed_count", 0) >= 3:
            base_confidence = 0.97
        elif l3_details.get("has_history"):
            base_confidence = 0.95
        elif is_trusted_or_whitelisted:
            base_confidence = 0.93
        else:
            base_confidence = 0.88

        # Severity Tier
        if overall_score >= 75:
            severity = "critical"
        elif overall_score >= 50:
            severity = "high"
        elif overall_score >= 25:
            severity = "medium"
        else:
            severity = "safe"

        # ------------------------------------------------------------------
        # EVIDENCE-BASED PRIMARY VERDICT (priority chain: BEC > Payload > Auth > Behavioral)
        # ------------------------------------------------------------------
        if overall_score < 20:
            verdict = "No Significant Threat Detected"
        elif l3_details.get("has_impersonation_anomaly"):
            verdict = "Executive Impersonation (BEC)"
        elif l1_details.get("has_suspicious_attachment"):
            verdict = "Malicious Attachment Detected"
        elif l1_details.get("has_suspicious_url"):
            verdict = "Suspicious URL / Phishing Link"
        elif l2_details.get("has_header_spoofing") and l2_details.get("auth_risk", 0) >= 60:
            verdict = "Email Authentication Spoofing"
        elif l1_details.get("has_misinformation"):
            verdict = "Misinformation / Fraud Content"
        elif l2_details.get("has_impersonation") or l2_details.get("has_header_spoofing"):
            verdict = "Header / Envelope Spoofing"
        elif l3_details.get("urgency_spike"):
            verdict = "Behavioral Anomaly — Urgency Spike"
        elif l3_details.get("has_behavioral_anomaly"):
            verdict = "Sender Behavior Anomaly"
        elif l1_details.get("has_credential_phishing"):
            verdict = "Credential Phishing Attempt"
        elif overall_score >= 75:
            verdict = "Critical Threat"
        elif overall_score >= 50:
            verdict = "Suspicious Email"
        else:
            verdict = "Low Risk Suspicious"

        threat_type = verdict

        if not recommendations:
            recommendations.append("Email appears clean. Standard browsing caution applies.")

        # UI breakdown scores — MUST match the composite formula weights exactly (45/20/35)
        # L1 max contribution: 45 pts | L2 max: 20 pts | L3 max: 35 pts  (total: 100)
        l1_ui_score = int(round(l1_risk * 0.45))   # Max 45
        l2_ui_score = int(round(l2_risk * 0.20))   # Max 20
        l3_ui_score = int(round(l3_risk * 0.35))   # Max 35

        layers_breakdown = {
            "content_security": {
                "score": l1_ui_score,
                "max_score": 45,
                "risk": l1_risk,
                "status": l1_details["status"],
                "signals": l1_signals,
                "details": l1_details
            },
            "transport_forensics": {
                "score": l2_ui_score,
                "max_score": 20,
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

        # Threat category subscores — each reflects its actual forensic weight contribution
        phishing_subscore = (
            int(round(max(l1_details.get("url_risk", 0), l1_details.get("content_risk", 0)) * 0.45))
            if (l1_details.get("has_credential_phishing") or l1_details.get("has_suspicious_url")) else 0
        )
        scam_subscore = (
            l2_ui_score
            if (l2_details.get("has_impersonation") or l2_details.get("has_header_spoofing")) else 0
        )
        misinfo_subscore = int(round(l1_details.get("misinfo_risk", 0) * 0.45))
        social_subscore = (
            l3_ui_score
            if (l3_details.get("has_behavioral_anomaly") or l3_details.get("has_impersonation_anomaly")) else 0
        )

        breakdown = {
            "auth_score": l2_ui_score,
            "geo_score": int(round(l2_details.get("routing_risk", 0) * 0.20)),
            "url_score": int(round(l1_details.get("url_risk", 0) * 0.45)),
            "nlp_score": l3_ui_score,
            "header_score": int(round(l2_details.get("header_risk", 0) * 0.20)),

            "layers": layers_breakdown,
            "verdict": verdict,
            "severity": severity,

            "phishing_score": phishing_subscore,
            "scam_score": scam_subscore,
            "misinformation_score": misinfo_subscore,
            "social_engineering_score": social_subscore,

            # Raw layer scores stored for debugging/transparency
            "layer1_risk": l1_risk,
            "layer2_risk": l2_risk,
            "layer3_risk": l3_risk,
            "weighted_score": round(weighted_score, 2)
        }

        unique_reasons = list(dict.fromkeys(reasons))
        unique_recs = list(dict.fromkeys(recommendations))

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
            # Reuse url_findings from Layer 1 (already computed — no duplicate API call)
            "url_reports": l1_details.get("url_findings", [])
        }
