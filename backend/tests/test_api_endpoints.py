import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.database.session import SessionLocal
from app.models.user import User
from app.models.email import EmailMessage
from app.auth.jwt import create_access_token


class TestForensicsAPIEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.db = SessionLocal()
        cls.user = cls.db.query(User).first()
        cls.email = cls.db.query(EmailMessage).first()
        if cls.user:
            cls.token = create_access_token(data={"sub": cls.user.id, "email": cls.user.email})
        else:
            cls.token = None

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_unauthorized_access(self):
        """Verify that unauthenticated requests to forensic headers endpoint are rejected with 401."""
        response = self.client.get("/api/v1/forensics/emails/some-msg-id/headers")
        self.assertEqual(response.status_code, 401)

    def test_not_found_email(self):
        """Verify 404 when requested email doesn't exist."""
        if not self.token:
            self.skipTest("No test user found in DB")
        headers = {"Authorization": f"Bearer {self.token}"}
        response = self.client.get("/api/v1/forensics/emails/non-existent-msg-id/headers", headers=headers)
        self.assertEqual(response.status_code, 404)

    def test_authenticated_forensic_header_endpoint(self):
        """Verify successful response and schema structure from forensic headers endpoint."""
        if not self.token or not self.email:
            self.skipTest("No test user or email found in DB")
        headers = {"Authorization": f"Bearer {self.token}"}
        response = self.client.get(f"/api/v1/forensics/emails/{self.email.id}/headers", headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["email_id"], self.email.id)
        self.assertIn("headers", data)
        self.assertIn("authentication", data)
        self.assertIn("received_chain", data)
        self.assertIn("origin_ip_candidate", data)
        self.assertIn("analysis_status", data)

    def test_alias_route_endpoint(self):
        """Verify alias route /api/v1/emails/{email_id}/forensics/headers works identically."""
        if not self.token or not self.email:
            self.skipTest("No test user or email found in DB")
        headers = {"Authorization": f"Bearer {self.token}"}
        response = self.client.get(f"/api/v1/emails/{self.email.id}/forensics/headers", headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["email_id"], self.email.id)


if __name__ == "__main__":
    unittest.main()
