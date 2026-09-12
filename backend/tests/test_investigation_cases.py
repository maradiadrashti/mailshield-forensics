import unittest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from app.main import app
from app.database.session import SessionLocal
from app.models.user import User
from app.models.email import EmailMessage
from app.models.investigation import Investigation
from app.models.analysis_result import AnalysisResult
from app.auth.jwt import create_access_token


class TestInvestigationCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        # Create primary test user A
        cls.user_a = User(
            id=str(uuid.uuid4()),
            email=f"investigator_{uuid.uuid4().hex[:6]}@test.com",
            name="Primary Investigator",
            google_id=f"google_{uuid.uuid4().hex[:8]}"
        )
        cls.db.add(cls.user_a)

        # Create secondary test user B for isolation testing
        cls.user_b = User(
            id=str(uuid.uuid4()),
            email=f"isolate_{uuid.uuid4().hex[:6]}@test.com",
            name="Isolated User B",
            google_id=f"google_{uuid.uuid4().hex[:8]}"
        )
        cls.db.add(cls.user_b)
        cls.db.commit()

        # Create test emails for user A
        cls.email_1 = EmailMessage(
            id=f"msg_test_{uuid.uuid4().hex[:8]}",
            user_id=cls.user_a.id,
            sender="billing@netflix-fake.com",
            recipient=cls.user_a.email,
            subject="Urgent: Payment Failed",
            body_text="Please update your card immediately.",
            date=datetime.now(timezone.utc),
            links=["http://netflix-fake-login.xyz/login"],
            attachments=[],
            raw_headers=[{"name": "From", "value": "billing@netflix-fake.com"}]
        )
        cls.email_2 = EmailMessage(
            id=f"msg_test_{uuid.uuid4().hex[:8]}",
            user_id=cls.user_a.id,
            sender="dean@bmsit.in",
            recipient=cls.user_a.email,
            subject="Academic Calendar Circular",
            body_text="All classes resume on Monday.",
            date=datetime.now(timezone.utc),
            links=["https://bmsit.ac.in"],
            attachments=[],
            raw_headers=[{"name": "From", "value": "dean@bmsit.in"}]
        )
        cls.db.add(cls.email_1)
        cls.db.add(cls.email_2)
        cls.db.commit()

        cls.token_a = create_access_token(data={"sub": cls.user_a.id, "email": cls.user_a.email})
        cls.token_b = create_access_token(data={"sub": cls.user_b.id, "email": cls.user_b.email})
        cls.headers_a = {"Authorization": f"Bearer {cls.token_a}"}
        cls.headers_b = {"Authorization": f"Bearer {cls.token_b}"}

    @classmethod
    def tearDownClass(cls):
        try:
            cls.db.query(Investigation).filter(Investigation.user_id.in_([cls.user_a.id, cls.user_b.id])).delete(synchronize_session=False)
            cls.db.query(AnalysisResult).filter(AnalysisResult.user_id.in_([cls.user_a.id, cls.user_b.id])).delete(synchronize_session=False)
            cls.db.query(EmailMessage).filter(EmailMessage.user_id.in_([cls.user_a.id, cls.user_b.id])).delete(synchronize_session=False)
            cls.db.query(User).filter(User.id.in_([cls.user_a.id, cls.user_b.id])).delete(synchronize_session=False)
            cls.db.commit()
        except Exception:
            pass
        cls.db.close()

    def test_1_open_investigation_creates_case(self):
        """
        TEST 1: User opens an investigation for an email message
        -> Creates persistent investigation in DB
        -> Triggers 3-layer threat scoring
        -> Returns complete case details
        """
        response = self.client.post(
            "/api/v1/forensics/investigations",
            json={"email_id": self.email_1.id, "notes": "Initial threat triage"},
            headers=self.headers_a
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("id", data)
        self.assertEqual(data["email_id"], self.email_1.id)
        self.assertEqual(data["subject"], "Urgent: Payment Failed")
        self.assertIn(data["status"], ["open", "in_progress"])
        self.assertGreaterEqual(data["score"], 0)
        self.assertIn("verdict", data)

        # Verify DB persistence
        inv = self.db.query(Investigation).filter(Investigation.id == data["id"]).first()
        self.assertIsNotNone(inv)
        self.assertEqual(inv.user_id, self.user_a.id)
        self.assertEqual(inv.email_id, self.email_1.id)

    def test_2_duplicate_prevention(self):
        """
        TEST 2: Opening the same investigation twice MUST NOT create two investigations.
        One real email = one investigation.
        """
        # Call open first time
        res1 = self.client.post(
            "/api/v1/forensics/investigations",
            json={"email_id": self.email_1.id},
            headers=self.headers_a
        )
        self.assertEqual(res1.status_code, 200)
        inv1_id = res1.json()["id"]

        # Call open second time for the exact same email
        res2 = self.client.post(
            "/api/v1/forensics/investigations",
            json={"email_id": self.email_1.id},
            headers=self.headers_a
        )
        self.assertEqual(res2.status_code, 200)
        inv2_id = res2.json()["id"]

        # IDs must be identical
        self.assertEqual(inv1_id, inv2_id)

        # Database must only have 1 investigation for email_1
        count = self.db.query(Investigation).filter(
            Investigation.email_id == self.email_1.id, Investigation.user_id == self.user_a.id
        ).count()
        self.assertEqual(count, 1)

    def test_3_list_investigations_and_metrics(self):
        """
        TEST 3: List investigations endpoint returns real database metrics
        """
        # Open investigation for second email (Dean email)
        self.client.post(
            "/api/v1/forensics/investigations",
            json={"email_id": self.email_2.id},
            headers=self.headers_a
        )

        response = self.client.get("/api/v1/forensics/investigations", headers=self.headers_a)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertIn("metrics", data)
        self.assertIn("investigations", data)
        metrics = data["metrics"]
        self.assertEqual(metrics["total_investigations"], 2)
        self.assertGreaterEqual(metrics["dangerous_count"] + metrics["suspicious_count"], 0)
        self.assertEqual(len(data["investigations"]), 2)

    def test_4_user_isolation(self):
        """
        TEST 4: User B must not see or access User A's investigations.
        """
        # User B queries investigations list -> must be 0
        res_list = self.client.get("/api/v1/forensics/investigations", headers=self.headers_b)
        self.assertEqual(res_list.status_code, 200)
        data = res_list.json()
        self.assertEqual(data["metrics"]["total_investigations"], 0)
        self.assertEqual(len(data["investigations"]), 0)

        # User B attempts to access User A's email directly -> 404
        res_detail = self.client.get(f"/api/v1/forensics/investigations/{self.email_1.id}", headers=self.headers_b)
        self.assertEqual(res_detail.status_code, 404)

    def test_5_get_single_investigation(self):
        """
        TEST 5: Retrieve single investigation by UUID or email ID
        """
        res = self.client.get(f"/api/v1/forensics/investigations/{self.email_1.id}", headers=self.headers_a)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["email_id"], self.email_1.id)

        # Also retrieve by investigation UUID
        res_by_uuid = self.client.get(f"/api/v1/forensics/investigations/{data['id']}", headers=self.headers_a)
        self.assertEqual(res_by_uuid.status_code, 200)
        self.assertEqual(res_by_uuid.json()["id"], data["id"])

    def test_6_report_generation_tracking(self):
        """
        TEST 6: Downloading PDF report updates report_generated = True on investigation
        """
        res = self.client.get(f"/api/v1/investigations/{self.email_1.id}/report", headers=self.headers_a)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["content-type"], "application/pdf")

        # Verify report_generated metric is updated
        inv_res = self.client.get(f"/api/v1/forensics/investigations/{self.email_1.id}", headers=self.headers_a)
        self.assertEqual(inv_res.status_code, 200)
        self.assertTrue(inv_res.json()["report_generated"])

    def test_7_open_non_existent_email_returns_404(self):
        """
        TEST 7: Attempting to open an investigation for a non-existent email returns 404
        """
        res = self.client.post(
            "/api/v1/forensics/investigations",
            json={"email_id": "non_existent_random_id_12345"},
            headers=self.headers_a
        )
        self.assertEqual(res.status_code, 404)


if __name__ == "__main__":
    unittest.main()
