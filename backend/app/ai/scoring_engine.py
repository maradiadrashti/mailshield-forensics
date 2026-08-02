from app.ai.huggingface_client import HuggingFaceClient
from app.ai.url_analyzer import URLAnalyzer
from app.ai.misinformation_analyzer import MisinformationAnalyzer


class ScoringEngine:
    CANDIDATE_LABELS = [
        "phishing email requesting credentials",
        "scam or invoice fraud requesting money",
        "social engineering or executive impersonation",
        "fake news or misinformation claims",
        "safe legitimate correspondence"
    ]

    @classmethod
    def analyze_email(
        cls,
        sender: str,
        recipient: str,
        subject: str,
        body_text: str,
        links: list[str],
        attachments: list[dict],
        is_trusted_sender: bool = False
    ) -> dict:
        full_text = f"Subject: {subject}\nSender: {sender}\nBody: {body_text}"
        reasons: list[str] = []
        recommendations: list[str] = []

        # 1. Misinformation Analysis
        misinfo_report = MisinformationAnalyzer.analyze_text(body_text, subject)
        if misinfo_report["credibility_score"] < 50:
            reasons.extend(misinfo_report["evidence"])

        # 2. Query HuggingFace NLP Model
        hf_results = HuggingFaceClient.classify_text(full_text, cls.CANDIDATE_LABELS)
        
        phishing_nlp = int(hf_results.get("phishing email requesting credentials", 0.0) * 100)
        scam_nlp = int(hf_results.get("scam or invoice fraud requesting money", 0.0) * 100)
        social_eng_nlp = int(hf_results.get("social engineering or executive impersonation", 0.0) * 100)
        misinfo_nlp = max(
            int(hf_results.get("fake news or misinformation claims", 0.0) * 100),
            100 - misinfo_report["credibility_score"]
        )

        # 3. Multi-Vector URL Threat Analysis
        url_score, url_reports, url_reasons, url_recs = URLAnalyzer.analyze_urls(links)
        reasons.extend(url_reasons)
        recommendations.extend(url_recs)

        # 4. Local Rule & Heuristic Analysis
        sender_lower = sender.lower()
        subject_lower = subject.lower()
        body_lower = body_text.lower() if body_text else ""

        # Check Sender Domain Spoofing
        if "paypal" in sender_lower and not sender_lower.endswith("@paypal.com"):
            phishing_nlp = max(phishing_nlp, 92)
            reasons.append(f"Sender address '{sender}' uses a domain mismatch to impersonate PayPal")
        elif "google" in sender_lower and not sender_lower.endswith("@google.com") and "accounts" in sender_lower:
            phishing_nlp = max(phishing_nlp, 88)
            reasons.append(f"Sender address '{sender}' uses a domain mismatch to impersonate Google Accounts")

        # Check Urgency & Coercion Signals
        urgency_words = ["urgent", "immediately", "account closure", "suspended", "24 hours", "action required"]
        matched_urgency = [w for w in urgency_words if w in subject_lower or w in body_lower]
        if matched_urgency:
            phishing_nlp = max(phishing_nlp, 75)
            social_eng_nlp = max(social_eng_nlp, 70)
            reasons.append(f"Contains high-urgency coercion phrases: '{', '.join(matched_urgency)}'")

        # Check Financial / Gift Card Request Signals
        gift_card_words = ["gift card", "apple card", "wire transfer", "western union", "overdue invoice"]
        matched_finance = [w for w in gift_card_words if w in subject_lower or w in body_lower]
        if matched_finance:
            scam_nlp = max(scam_nlp, 85)
            social_eng_nlp = max(social_eng_nlp, 80)
            reasons.append(f"Solicits direct financial transfers or gift cards: '{', '.join(matched_finance)}'")

        # Check Dangerous Attachments
        for att in attachments:
            fname = att.get("filename", "").lower()
            if fname.endswith(".exe") or fname.endswith(".bat") or fname.endswith(".scr") or ".exe" in fname:
                scam_nlp = max(scam_nlp, 95)
                phishing_nlp = max(phishing_nlp, 90)
                reasons.append(f"Contains dangerous executable attachment: '{att.get('filename')}'")

        # Calculate Final Category Breakdown & Overall Risk Score
        breakdown = {
            "phishing_score": min(phishing_nlp, 100),
            "scam_score": min(scam_nlp, 100),
            "url_score": min(url_score, 100),
            "misinformation_score": min(misinfo_nlp, 100),
            "social_engineering_score": min(social_eng_nlp, 100)
        }

        overall_score = max(
            breakdown["phishing_score"],
            breakdown["scam_score"],
            breakdown["url_score"],
            breakdown["misinformation_score"],
            breakdown["social_engineering_score"]
        )

        # Determine Threat Type Category
        if overall_score < 30:
            threat_type = "Safe"
            confidence = 0.95
            if not reasons:
                reasons.append("Sender, body content, and links match standard non-malicious patterns")
        elif breakdown["phishing_score"] == overall_score:
            threat_type = "Phishing"
            confidence = 0.91
        elif breakdown["url_score"] == overall_score:
            threat_type = "Suspicious URL"
            confidence = 0.89
        elif breakdown["scam_score"] == overall_score:
            threat_type = "Scam"
            confidence = 0.88
        elif breakdown["social_engineering_score"] == overall_score:
            threat_type = "Social Engineering"
            confidence = 0.86
        else:
            threat_type = "Misinformation"
            confidence = 0.82

        if is_trusted_sender:
            reasons.append("Sender verified as a Trusted Sender. Threat score reduced.")
            if overall_score >= 80:
                overall_score = 60
            elif overall_score >= 40:
                overall_score = 40
            else:
                overall_score = 5
                threat_type = "Safe"

        # Deduplicate reasons & recommendations
        unique_reasons = list(dict.fromkeys(reasons))
        unique_recs = list(dict.fromkeys(recommendations))

        return {
            "risk_score": overall_score,
            "confidence": confidence,
            "threat_type": threat_type,
            "reasons": unique_reasons,
            "recommendations": unique_recs,
            "breakdown": breakdown,
            "url_reports": url_reports,
            "misinformation_detail": misinfo_report
        }
