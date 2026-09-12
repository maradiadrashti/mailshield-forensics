import unittest
from types import SimpleNamespace
from app.ai.scoring_engine import ScoringEngine
from app.schemas.forensics import EmailAuthenticationResult, NetworkIntelligence


class TestThreeLayerThreatScoring(unittest.TestCase):
    """
    Tests for the 3-Layer Explainable Threat Assessment Engine:
    - Layer 1: Content / Link / Attachment Security (45%)
    - Layer 2: Mail Transport Path / Forensics (20%)
    - Layer 3: AI Behavioral / Historical Analysis (35%)
    """

    def test_1_normal_dean_email_low_score(self):
        """
        TEST 1: Normal email from college Dean (dean.aa@bmsit.in)
        - Passing SPF, DKIM, DMARC
        - Multiple Received hops from university/Google mail infra
        - Public origin IP
        - Normal institutional URLs (bmsit.ac.in)
        - Clean PDF attachment
        -> Low score (0 - 20)
        -> Verdict: 'No Significant Threat Detected'
        """
        auth = EmailAuthenticationResult(spf="pass", dkim="pass", dmarc="pass")
        geo = NetworkIntelligence(
            ip="209.85.220.41",
            country="United States",
            city="Mountain View",
            isp="Google LLC",
            asn="AS15169",
            vpn_proxy_tor="No"
        )
        history = [
            SimpleNamespace(subject="Academic calendar 2026", body_text="Classes commence next week.", date="2026-08-01"),
            SimpleNamespace(subject="Course registration guidelines", body_text="Please register on VTU portal.", date="2026-08-15")
        ]

        result = ScoringEngine.analyze_email(
            sender="dean.aa@bmsit.in",
            recipient="student@bmsit.in",
            subject="Circular: Commencement of Even Semester Classes",
            body_text="All students are requested to report to classes starting Monday. Mandatory attendance policy applies.",
            links=["https://bmsit.ac.in/academic-calendar", "https://forms.gle/xyz123"],
            attachments=[{"filename": "Academic_Schedule_2026.pdf", "mime_type": "application/pdf", "size": 150000}],
            is_trusted_sender=False,
            authentication=auth,
            network_intelligence=geo,
            route_hops=[{"hop": 1, "ip": "209.85.220.41"}, {"hop": 2, "ip": "142.251.222.1"}],
            historical_emails=history
        )

        self.assertLessEqual(result["risk_score"], 20)
        self.assertEqual(result["verdict"], "No Significant Threat Detected")
        self.assertEqual(result["severity"], "safe")
        self.assertEqual(result["layers"]["content_security"]["risk"], 0)
        self.assertEqual(result["layers"]["transport_forensics"]["risk"], 0)
        self.assertEqual(result["layers"]["behavioral_ai"]["risk"], 0)

    def test_2_normal_gmail_email_low_score(self):
        """
        TEST 2: Normal Gmail email from colleague
        -> Low score (< 20)
        -> Verdict: 'No Significant Threat Detected'
        """
        auth = EmailAuthenticationResult(spf="pass", dkim="pass", dmarc="pass")
        geo = NetworkIntelligence(
            ip="209.85.128.0",
            country="United States",
            city="Mountain View",
            isp="Google LLC",
            asn="AS15169",
            vpn_proxy_tor="No"
        )

        result = ScoringEngine.analyze_email(
            sender="johndoe@gmail.com",
            recipient="user@domain.com",
            subject="Meeting notes and slides",
            body_text="Hi, here are the slides from our afternoon sync. Let me know what you think.",
            links=["https://docs.google.com/presentation/d/12345"],
            attachments=[],
            is_trusted_sender=False,
            authentication=auth,
            network_intelligence=geo
        )

        self.assertLessEqual(result["risk_score"], 20)
        self.assertEqual(result["verdict"], "No Significant Threat Detected")
        self.assertEqual(result["severity"], "safe")

    def test_3_normal_university_email_low_score(self):
        """
        TEST 3: Normal university email with academic notices
        -> Low score (< 20)
        """
        auth = EmailAuthenticationResult(spf="pass", dkim="pass", dmarc="pass")
        geo = NetworkIntelligence(ip="128.0.0.1", country="United States", city="Cambridge", isp="Harvard University", asn="AS100", vpn_proxy_tor="No")

        result = ScoringEngine.analyze_email(
            sender="principal@bmsit.in",
            recipient="faculty@bmsit.in",
            subject="Faculty meeting announcement",
            body_text="There will be a faculty council meeting in the auditorium.",
            links=["https://bmsit.in/events"],
            attachments=[],
            is_trusted_sender=False,
            authentication=auth,
            network_intelligence=geo
        )

        self.assertLessEqual(result["risk_score"], 20)
        self.assertEqual(result["verdict"], "No Significant Threat Detected")

    def test_4_new_legitimate_sender_low_neutral_not_critical(self):
        """
        TEST 4: New sender with zero history, passing auth, clean content
        -> Insufficient history (0 behavioral penalty)
        -> Low / neutral score (< 20), NOT critical
        """
        auth = EmailAuthenticationResult(spf="pass", dkim="pass", dmarc="pass")
        geo = NetworkIntelligence(ip="198.51.100.1", country="United States", city="New York", isp="DigitalOcean", asn="AS14061", vpn_proxy_tor="No")

        result = ScoringEngine.analyze_email(
            sender="contact@new-partner-agency.com",
            recipient="developer@company.com",
            subject="Project collaboration inquiry",
            body_text="Hello, we would love to explore collaborating on your upcoming open source project.",
            links=["https://new-partner-agency.com/about"],
            attachments=[],
            is_trusted_sender=False,
            authentication=auth,
            network_intelligence=geo,
            historical_emails=[]
        )

        self.assertLessEqual(result["risk_score"], 20)
        self.assertEqual(result["layers"]["behavioral_ai"]["historical_status"], "insufficient_history")
        self.assertEqual(result["layers"]["behavioral_ai"]["risk"], 0)
        self.assertEqual(result["verdict"], "No Significant Threat Detected")

    def test_5_suspicious_url_elevated_score(self):
        """
        TEST 5: Suspicious typosquatting URL in email
        -> Elevated threat score
        -> Verdict: 'Suspicious URL Detected'
        """
        auth = EmailAuthenticationResult(spf="pass", dkim="pass", dmarc="pass")

        result = ScoringEngine.analyze_email(
            sender="security@paypal-notice.com",
            recipient="victim@company.com",
            subject="Security Notice Regarding Your Account",
            body_text="Please review the recent login attempt on your account.",
            links=["http://paypal-security-check-update.com/login"],
            attachments=[],
            is_trusted_sender=False,
            authentication=auth
        )

        self.assertGreaterEqual(result["risk_score"], 25)
        self.assertEqual(result["verdict"], "Suspicious URL Detected")
        self.assertTrue(result["layers"]["content_security"]["details"]["has_suspicious_url"])
        self.assertGreater(result["layers"]["content_security"]["risk"], 0)

    def test_6_malicious_attachment_elevated_high_score(self):
        """
        TEST 6: Malicious executable / double-extension attachment
        -> Elevated / high score
        -> Verdict: 'Malicious Attachment Detected'
        """
        auth = EmailAuthenticationResult(spf="pass", dkim="pass", dmarc="pass")

        result = ScoringEngine.analyze_email(
            sender="billing@partner-vendor.com",
            recipient="finance@company.com",
            subject="Invoice for immediate payment",
            body_text="Please find the attached invoice document.",
            links=[],
            attachments=[
                {
                    "filename": "invoice_payment_receipt.pdf.exe",
                    "mime_type": "application/x-msdownload",
                    "size": 45020,
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }
            ],
            is_trusted_sender=False,
            authentication=auth
        )

        self.assertGreaterEqual(result["risk_score"], 40)
        self.assertEqual(result["verdict"], "Malicious Attachment Detected")
        self.assertTrue(result["layers"]["content_security"]["details"]["has_suspicious_attachment"])
        self.assertGreaterEqual(result["layers"]["content_security"]["risk"], 80)

    def test_7_spf_dkim_dmarc_failure_elevated_score(self):
        """
        TEST 7: SPF, DKIM, and DMARC failures
        -> Transport forensics layer elevated
        -> Verdict: 'Possible Impersonation' or elevated threat
        """
        auth = EmailAuthenticationResult(spf="fail", dkim="fail", dmarc="fail")

        result = ScoringEngine.analyze_email(
            sender="billing@company-internal.com",
            recipient="finance@company-internal.com",
            subject="Status update",
            body_text="Checking in on the status of project deliverables.",
            links=[],
            attachments=[],
            is_trusted_sender=False,
            authentication=auth
        )

        self.assertGreater(result["layers"]["transport_forensics"]["risk"], 50)
        self.assertIn("Cryptographic authentication failure", " ".join(result["layers"]["transport_forensics"]["signals"]))

    def test_8_known_sender_normal_history_low_score(self):
        """
        TEST 8: Known sender with strong history of normal communication
        -> Behavioral risk = 0
        -> Overall safe verdict
        """
        auth = EmailAuthenticationResult(spf="pass", dkim="pass", dmarc="pass")
        historical_emails = [
            SimpleNamespace(subject="Project roadmap sync", body_text="Let's meet tomorrow at 10 AM.", date="2026-09-01"),
            SimpleNamespace(subject="Quarterly review", body_text="Thanks for the update.", date="2026-08-25"),
            SimpleNamespace(subject="Sprint planning", body_text="Tasks have been assigned in Jira.", date="2026-08-15"),
        ]

        result = ScoringEngine.analyze_email(
            sender="colleague@company.com",
            recipient="user@company.com",
            subject="Team lunch sync",
            body_text="Are we having lunch at the cafeteria today?",
            links=[],
            attachments=[],
            is_trusted_sender=True,
            authentication=auth,
            historical_emails=historical_emails
        )

        self.assertEqual(result["layers"]["behavioral_ai"]["risk"], 0)
        self.assertEqual(result["layers"]["behavioral_ai"]["historical_status"], "known_sender")
        self.assertEqual(result["layers"]["behavioral_ai"]["history_count"], 3)
        self.assertEqual(result["verdict"], "No Significant Threat Detected")

    def test_9_known_sender_abnormal_behavior_elevated_score(self):
        """
        TEST 9: Known sender suddenly exhibiting unprecedented urgency / wire transfer demand
        -> Behavioral risk increases significantly
        -> Verdict: 'Sender Behavior Anomaly'
        """
        auth = EmailAuthenticationResult(spf="pass", dkim="pass", dmarc="pass")
        historical_emails = [
            SimpleNamespace(subject="Weekly design review", body_text="Attached are the slide decks.", date="2026-09-01"),
            SimpleNamespace(subject="Meeting notes", body_text="Here are the action items.", date="2026-08-20"),
        ]

        result = ScoringEngine.analyze_email(
            sender="colleague@company.com",
            recipient="user@company.com",
            subject="IMMEDIATE ACTION REQUIRED: Account Suspended Wire Transfer",
            body_text="Immediate action required: wire transfer funds to avoid account termination and verify credentials immediately.",
            links=[],
            attachments=[],
            is_trusted_sender=False,
            authentication=auth,
            historical_emails=historical_emails
        )

        self.assertTrue(result["layers"]["behavioral_ai"]["has_history"])
        self.assertTrue(result["layers"]["behavioral_ai"]["details"]["has_behavioral_anomaly"])
        self.assertGreaterEqual(result["layers"]["behavioral_ai"]["risk"], 50)
        self.assertEqual(result["verdict"], "Sender Behavior Anomaly")

    def test_10_multiple_strong_indicators_critical_score(self):
        """
        TEST 10: Multiple strong indicators across layers
        (Failed auth + Tor/VPN origin IP + Malicious URL + Double-ext attachment + Coercive lure)
        -> High / Critical threat score (>= 75)
        """
        auth = EmailAuthenticationResult(spf="fail", dkim="fail", dmarc="fail")
        geo = NetworkIntelligence(
            ip="185.220.101.5",
            country="Russia",
            city="Moscow",
            isp="Bulletproof Tor Exit Host",
            asn="AS99999",
            vpn_proxy_tor="Yes"
        )

        result = ScoringEngine.analyze_email(
            sender="admin@bankofamerica-secure-update.com",
            recipient="victim@company.com",
            subject="CRITICAL: Unauthorized Wire Transfer Detected - Immediate Action Required",
            body_text="Immediate action required: verify credentials or your wire transfer of $50,000 will be finalized.",
            links=["http://bankofamerica-security-portal-verify.xyz/login"],
            attachments=[
                {
                    "filename": "wire_reversal_form.doc.scr",
                    "mime_type": "application/x-msdownload",
                    "size": 12000
                }
            ],
            is_trusted_sender=False,
            authentication=auth,
            network_intelligence=geo
        )

        self.assertGreaterEqual(result["risk_score"], 75)
        self.assertEqual(result["severity"], "critical")
        self.assertIn(result["verdict"], ["Malicious Attachment Detected", "Suspicious URL Detected", "Phishing"])


if __name__ == "__main__":
    unittest.main()
