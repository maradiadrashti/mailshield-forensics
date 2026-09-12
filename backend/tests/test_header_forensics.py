import unittest
from app.services.email_header_forensics_service import EmailHeaderForensicsService
from app.schemas.forensics import ForensicHeaderResponse


class TestEmailHeaderForensics(unittest.TestCase):
    def test_1_normal_multihop_email(self):
        """
        Test 1 — Normal multi-hop email
        Multiple Received headers with public IPs.
        Verify:
        * all hops detected
        * IPs extracted
        * hop order preserved
        * public/private classification works
        """
        raw_headers = [
            {"name": "From", "value": "support@github.com"},
            {"name": "To", "value": "analyst@example.com"},
            {"name": "Subject", "value": "GitHub Security Alert"},
            {"name": "Date", "value": "Mon, 24 Aug 2026 10:00:00 +0000"},
            {"name": "Message-ID", "value": "<github-alert-12345@github.com>"},
            {"name": "Authentication-Results", "value": "mx.google.com; dkim=pass header.i=@github.com; spf=pass; dmarc=pass"},
            # Hop 1 (top-most / newest MTA - Google MX receiving from intermediate relay)
            {
                "name": "Received",
                "value": "from mail-out-1.github.com (mail-out-1.github.com. [140.82.112.5]) by mx.google.com with ESMTPS id abc123; Mon, 24 Aug 2026 10:00:00 +0000"
            },
            # Hop 2 (earlier MTA - sending server origin)
            {
                "name": "Received",
                "value": "from edge-mta.github.net (edge.github.net [192.30.252.204]) by mail-out-1.github.com with ESMTP id def456; Mon, 24 Aug 2026 09:59:55 +0000"
            }
        ]

        result: ForensicHeaderResponse = EmailHeaderForensicsService.parse_headers(raw_headers, email_id="test_msg_001")

        self.assertEqual(result.email_id, "test_msg_001")
        self.assertEqual(result.headers.from_, "support@github.com")
        self.assertEqual(result.headers.subject, "GitHub Security Alert")
        self.assertEqual(result.authentication.spf, "pass")
        self.assertEqual(result.authentication.dkim, "pass")
        self.assertEqual(result.authentication.dmarc, "pass")

        # Verify all hops detected and order preserved
        self.assertEqual(len(result.received_chain), 2)
        self.assertEqual(result.received_chain[0].hop, 1)
        self.assertEqual(result.received_chain[0].source_ip, "140.82.112.5")
        self.assertEqual(result.received_chain[0].ip_classification, "public")

        self.assertEqual(result.received_chain[1].hop, 2)
        self.assertEqual(result.received_chain[1].source_ip, "192.30.252.204")
        self.assertEqual(result.received_chain[1].ip_classification, "public")

        # Origin candidate should be the earliest public hop (Hop 2: 192.30.252.204)
        self.assertEqual(result.origin_ip_candidate, "192.30.252.204")

    def test_2_private_ip_handling(self):
        """
        Test 2 — Private IP
        Received header containing: 10.x.x.x or 192.168.x.x
        Verify it is classified as private and is NOT selected as the geographic origin.
        """
        raw_headers = [
            {"name": "From", "value": "finance@corp.internal"},
            {"name": "Subject", "value": "Internal Payroll Update"},
            # Hop 1: External gateway (public IP)
            {
                "name": "Received",
                "value": "from mail.external-relay.com (unknown [198.51.100.42]) by mx.google.com with ESMTPS; Sun, 23 Aug 2026 12:05:00 +0000"
            },
            # Hop 2: Internal corporate server (private IP 10.0.1.25)
            {
                "name": "Received",
                "value": "from internal-node.lan ([10.0.1.25]) by mail.external-relay.com with ESMTP id ghk789; Sun, 23 Aug 2026 12:04:00 +0000"
            },
            # Hop 3: Desktop client (private IP 192.168.1.50)
            {
                "name": "Received",
                "value": "from [192.168.1.50] by internal-node.lan with HTTP; Sun, 23 Aug 2026 12:03:00 +0000"
            }
        ]

        result: ForensicHeaderResponse = EmailHeaderForensicsService.parse_headers(raw_headers, email_id="test_private_msg")

        self.assertEqual(len(result.received_chain), 3)

        # Check classifications
        self.assertEqual(result.received_chain[0].source_ip, "198.51.100.42")
        self.assertEqual(result.received_chain[0].ip_classification, "public")

        self.assertEqual(result.received_chain[1].source_ip, "10.0.1.25")
        self.assertEqual(result.received_chain[1].ip_classification, "private")

        self.assertEqual(result.received_chain[2].source_ip, "192.168.1.50")
        self.assertEqual(result.received_chain[2].ip_classification, "private")

        # Origin candidate MUST NOT be the private IPs 192.168.1.50 or 10.0.1.25;
        # it must be the earliest public IP in the chain (Hop 1: 198.51.100.42)
        self.assertEqual(result.origin_ip_candidate, "198.51.100.42")

    def test_3_ipv6_extraction(self):
        """
        Test 3 — IPv6
        Verify valid IPv6 extraction and classification.
        """
        raw_headers = [
            {"name": "From", "value": "no-reply@ipv6-service.net"},
            {
                "name": "Received",
                "value": "from mail.ipv6-service.net ([IPv6:2001:db8:85a3::8a2e:370:7334]) by mx.google.com with ESMTPS; Sat, 22 Aug 2026 08:00:00 +0000"
            },
            {
                "name": "Received",
                "value": "from [2607:f8b0:4864:20::72f] by mail.ipv6-service.net with SMTP id xyz; Sat, 22 Aug 2026 07:58:00 +0000"
            }
        ]

        result: ForensicHeaderResponse = EmailHeaderForensicsService.parse_headers(raw_headers, email_id="test_ipv6_msg")

        self.assertEqual(len(result.received_chain), 2)
        self.assertEqual(result.received_chain[0].source_ip, "2001:db8:85a3::8a2e:370:7334")
        self.assertEqual(result.received_chain[1].source_ip, "2607:f8b0:4864:20::72f")
        self.assertEqual(result.origin_ip_candidate, "2607:f8b0:4864:20::72f")

    def test_4_no_received_header(self):
        """
        Test 4 — No Received header
        Return an empty received chain and origin_ip_candidate = None.
        """
        raw_headers = [
            {"name": "From", "value": "draft@example.com"},
            {"name": "To", "value": "someone@example.com"},
            {"name": "Subject", "value": "Draft without transport headers"}
        ]

        result: ForensicHeaderResponse = EmailHeaderForensicsService.parse_headers(raw_headers, email_id="test_no_headers")

        self.assertEqual(result.received_chain, [])
        self.assertIsNone(result.origin_ip_candidate)
        self.assertEqual(result.authentication.spf, "unknown")
        self.assertEqual(result.authentication.dkim, "unknown")
        self.assertEqual(result.authentication.dmarc, "unknown")

    def test_5_malformed_ip_resilience(self):
        """
        Test 5 — Malformed IP
        Do not crash the parser when encountering broken or deceptive IP strings.
        """
        raw_headers = [
            {"name": "From", "value": "attacker@evil.com"},
            # Malformed octets (> 255) and garbage strings
            {
                "name": "Received",
                "value": "from evil-host.com ([999.888.777.666]) by relay.com; 24 Aug 2026"
            },
            {
                "name": "Received",
                "value": "from corrupt-host ([not:an:ip:address]) by relay.com id 999; 24 Aug 2026"
            },
            # Valid public hop before the corruption
            {
                "name": "Received",
                "value": "from valid-mta.com ([203.0.113.100]) by corrupt-host; 24 Aug 2026"
            }
        ]

        result: ForensicHeaderResponse = EmailHeaderForensicsService.parse_headers(raw_headers, email_id="test_malformed")

        self.assertEqual(len(result.received_chain), 3)
        # Hop 1 and 2 should safely have source_ip=None without crashing
        self.assertIsNone(result.received_chain[0].source_ip)
        self.assertIsNone(result.received_chain[1].source_ip)
        # Hop 3 should succeed
        self.assertEqual(result.received_chain[2].source_ip, "203.0.113.100")
        self.assertEqual(result.origin_ip_candidate, "203.0.113.100")

    def test_7_complex_mta_chain_and_origin_selection(self):
        """
        Test 7 — Realistic MTA transport chain (Google MX -> SendGrid -> Internal ingress)
        Verifies chronological hop parsing and origin candidate extraction.
        """
        raw_headers = [
            {"name": "From", "value": "\"Security Team\" <security@alerts-service.com>"},
            {"name": "To", "value": "user@gmail.com"},
            {"name": "Subject", "value": "Account Security Notification"},
            {"name": "Message-ID", "value": "<sec-msg-999@alerts-service.com>"},
            {"name": "Date", "value": "Mon, 24 Aug 2026 14:22:00 +0000"},
            {"name": "ARC-Authentication-Results", "value": "i=1; mx.google.com; dkim=pass header.i=@alerts-service.com; spf=pass (google.com: domain of bounce@alerts-service.com designates 167.89.10.20 as permitted sender) smtp.mailfrom=bounce@alerts-service.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=alerts-service.com"},
            # Hop 1 (Final receiver: Google MTA)
            {
                "name": "Received",
                "value": "by 2002:a05:600c:2184:b0:433:a58c:31a4 with SMTP id ... for <user@gmail.com>; Mon, 24 Aug 2026 07:22:05 -0700 (PDT)"
            },
            # Hop 2 (Google MX receiving from SendGrid public IP)
            {
                "name": "Received",
                "value": "from o1.ptr9823.alerts-service.com (o1.ptr9823.alerts-service.com. [167.89.10.20]) by mx.google.com with ESMTPS id q12si... for <user@gmail.com>; Mon, 24 Aug 2026 07:22:04 -0700 (PDT)"
            },
            # Hop 3 (SendGrid internal relay receiving from customer backend private IP)
            {
                "name": "Received",
                "value": "from client-backend.internal ([10.240.0.14]) by o1.ptr9823.alerts-service.com with ESMTP id sg_8291; Mon, 24 Aug 2026 14:22:01 +0000"
            }
        ]

        result = EmailHeaderForensicsService.parse_headers(raw_headers, email_id="test_mta_chain")

        self.assertEqual(len(result.received_chain), 3)
        self.assertEqual(result.authentication.spf, "pass")
        self.assertEqual(result.authentication.dkim, "pass")
        self.assertEqual(result.authentication.dmarc, "pass")

        # Hop 2 is public (167.89.10.20), Hop 3 is private (10.240.0.14)
        self.assertEqual(result.received_chain[1].source_ip, "167.89.10.20")
        self.assertEqual(result.received_chain[1].ip_classification, "public")
        self.assertEqual(result.received_chain[2].source_ip, "10.240.0.14")
        self.assertEqual(result.received_chain[2].ip_classification, "private")

        # Origin candidate should correctly be the SendGrid public egress server (167.89.10.20)
        self.assertEqual(result.origin_ip_candidate, "167.89.10.20")

    def test_8_auth_variations_fail_and_neutral(self):
        """
        Test 8 — Authentication failure & softfail detection
        """
        raw_headers = [
            {"name": "From", "value": "spammer@spoofed-bank.com"},
            {"name": "Received-SPF", "value": "softfail (google.com: domain of transitioning spammer@spoofed-bank.com does not designate 185.220.101.5 as permitted sender)"},
            {"name": "Authentication-Results", "value": "mx.google.com; dkim=fail (signature did not verify); dmarc=fail action=none header.from=spoofed-bank.com"}
        ]

        result = EmailHeaderForensicsService.parse_headers(raw_headers, email_id="test_auth_fail")
        self.assertEqual(result.authentication.spf, "fail")
        self.assertEqual(result.authentication.dkim, "fail")
        self.assertEqual(result.authentication.dmarc, "fail")

    def test_6_real_email_database_query(self):
        """
        Test 6 — Real Gmail/DB email query
        Tests the forensic header service against an existing email in the database.
        """
        from app.database.session import SessionLocal
        from app.models.email import EmailMessage
        from app.models.user import User

        db = SessionLocal()
        try:
            email = db.query(EmailMessage).first()
            if email:
                user = db.query(User).filter(User.id == email.user_id).first()
                if user:
                    from app.controllers.forensics_controller import ForensicsController
                    res = ForensicsController.get_email_forensic_headers(db, user, email.id)
                    self.assertEqual(res.email_id, email.id)
                    self.assertIsNotNone(res.headers.from_)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
