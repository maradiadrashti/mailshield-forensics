import unittest
from app.ai.scoring_engine import ScoringEngine
from app.schemas.forensics import EmailAuthenticationResult, NetworkIntelligence

class TestWeightedScoring(unittest.TestCase):
    def test_whitelist_known_safe_sender(self):
        """
        Verify that whitelisted senders with valid SPF/DKIM alignment get a Safe score of 0.
        """
        auth = EmailAuthenticationResult(spf="pass", dkim="pass", dmarc="pass")
        geo = NetworkIntelligence(ip="8.8.8.8", country="United States", city="Mountain View", isp="Google LLC", asn="AS15169", vpn_proxy_tor="No", latitude=37.4, longitude=-122.0)
        
        result = ScoringEngine.analyze_email(
            sender="dean@university.edu",
            recipient="student@university.edu",
            subject="Urgent: Hackathon Invitation",
            body_text="Verify your team details now to save your slot.",
            links=["https://university.edu/hackathon"],
            attachments=[],
            is_trusted_sender=False,
            authentication=auth,
            network_intelligence=geo
        )
        
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["verdict"], "No Significant Threat Detected")

    def test_urgency_suppression_institutional(self):
        """
        Verify that urgency phrases from institutional (.edu) domains are suppressed if auth passes.
        """
        auth = EmailAuthenticationResult(spf="pass", dkim="pass", dmarc="unknown")
        geo = NetworkIntelligence(ip="128.0.0.1", country="United States", city="Boston", isp="University Network", asn="AS100", vpn_proxy_tor="No")
        
        result = ScoringEngine.analyze_email(
            sender="dean@university.edu",
            recipient="student@university.edu",
            subject="Urgent: Hackathon Invitation",
            body_text="Verify details now.",
            links=[],
            attachments=[],
            is_trusted_sender=False,
            authentication=auth,
            network_intelligence=geo
        )
        
        # In 3-layer engine: SPF/DKIM pass gives 0 penalty for transport, content urgency suppressed
        self.assertLess(result["risk_score"], 25)
        self.assertEqual(result["verdict"], "No Significant Threat Detected")
        self.assertIn("layers", result)

    def test_weighted_scoring_suspicious_combo(self):
        """
        Verify math calculations for a dangerous malicious combo.
        """
        auth = EmailAuthenticationResult(spf="fail", dkim="fail", dmarc="fail")
        geo = NetworkIntelligence(ip="203.0.113.5", country="Romania", city="Bucharest", isp="Normal ISP", asn="AS300", vpn_proxy_tor="No")
        
        result = ScoringEngine.analyze_email(
            sender="billing@netflix-secure.us",
            recipient="user@domain.com",
            subject="Immediate Action Required: Card Declined",
            body_text="Immediate action required: log in to update card.",
            links=["http://netflixbillingalertupdateloginsecure.com/login"],
            attachments=[],
            is_trusted_sender=False,
            authentication=auth,
            network_intelligence=geo
        )
        
        # Total is high risk (score >= 50)
        self.assertGreaterEqual(result["risk_score"], 50)
        self.assertIn(result["verdict"], ["Suspicious URL Detected", "Phishing", "Malicious Email", "Possible Impersonation"])
        self.assertEqual(result["layers"]["content_security"]["status"], "critical")


if __name__ == "__main__":
    unittest.main()
