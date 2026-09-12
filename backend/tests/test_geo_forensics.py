import unittest
from app.services.geo_service import GeoService
from app.services.email_header_forensics_service import EmailHeaderForensicsService
from app.schemas.forensics import ForensicHeaderResponse

class TestGeoForensics(unittest.TestCase):
    def test_geo_service_lookup_public_ip(self):
        """
        Verify that a public IP lookup returns valid geographic info.
        For instance, 8.8.8.8 should resolve to Google LLC (or similar) and United States.
        """
        result = GeoService.lookup_ip("8.8.8.8", "public")
        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["country"], "United States")
        self.assertTrue(result["asn"].startswith("AS"))
        self.assertIn("Google", result["isp"])
        self.assertIsNotNone(result["latitude"])
        self.assertIsNotNone(result["longitude"])

    def test_geo_service_lookup_private_ip(self):
        """
        Verify that private/local IPs are handled gracefully and bypass GeoLite lookup.
        """
        result = GeoService.lookup_ip("192.168.1.1", "private")
        self.assertEqual(result["ip"], "192.168.1.1")
        self.assertEqual(result["country"], "Local Network")
        self.assertEqual(result["city"], "Local Network")
        self.assertIn("Private Address", result["isp"])
        self.assertEqual(result["asn"], "Private Range")
        self.assertIsNone(result["latitude"])
        self.assertIsNone(result["longitude"])

    def test_geo_service_lookup_invalid_ip(self):
        """
        Verify that lookup for invalid IPs or failed database reads fall back gracefully.
        """
        result = GeoService.lookup_ip("invalid-ip-string", "public")
        self.assertEqual(result["country"], "Unknown")
        self.assertEqual(result["city"], "Unknown")
        self.assertEqual(result["isp"], "Unknown")
        self.assertEqual(result["asn"], "Unknown")
        self.assertIsNone(result["latitude"])
        self.assertIsNone(result["longitude"])

    def test_email_header_forensics_geo_population(self):
        """
        Test that parse_headers populates network_intelligence and route_hops correctly.
        """
        raw_headers = [
            {"name": "From", "value": "test@google.com"},
            {"name": "To", "value": "target@example.com"},
            {"name": "Subject", "value": "Test Subject"},
            {
                "name": "Received",
                "value": "from mail.google.com (mail.google.com [8.8.8.8]) by mx.google.com with ESMTPS; Mon, 24 Aug 2026 10:00:00 +0000"
            },
            {
                "name": "Received",
                "value": "from [192.168.1.100] by mail.google.com with SMTP; Mon, 24 Aug 2026 09:59:00 +0000"
            }
        ]

        result: ForensicHeaderResponse = EmailHeaderForensicsService.parse_headers(raw_headers, email_id="test_msg_geo")

        self.assertIsNotNone(result.network_intelligence)
        self.assertEqual(result.network_intelligence.ip, "8.8.8.8")
        self.assertEqual(result.network_intelligence.country, "United States")

        self.assertEqual(len(result.route_hops), 2)
        # Hop 1: 8.8.8.8 (Public)
        self.assertEqual(result.route_hops[0].hop, 1)
        self.assertEqual(result.route_hops[0].ip, "8.8.8.8")
        self.assertEqual(result.route_hops[0].country, "United States")
        
        # Hop 2: 192.168.1.100 (Private)
        self.assertEqual(result.route_hops[1].hop, 2)
        self.assertEqual(result.route_hops[1].ip, "192.168.1.100")
        self.assertEqual(result.route_hops[1].country, "Local Network")
        self.assertEqual(result.route_hops[1].city, "Local Network")
        self.assertIsNone(result.route_hops[1].latitude)
