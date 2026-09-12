import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.base import Base
from app.models.user import User
from app.models.oauth_token import OAuthToken
from app.models.email import EmailMessage
from app.services.auth_service import AuthService
from app.services.gmail_service import GmailService


class TestOAuthAutomaticRefresh(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create in-memory SQLite database for isolated test execution
        cls.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(cls.engine)
        cls.Session = sessionmaker(bind=cls.engine)

    def setUp(self):
        self.db = self.Session()
        # Create a test user
        self.user = User(
            id="test-user-id-123",
            email="analyst@mailshield.ai",
            name="Security Analyst",
            google_id="google-user-123"
        )
        self.db.add(self.user)
        self.db.commit()

    def tearDown(self):
        self.db.query(OAuthToken).delete()
        self.db.query(EmailMessage).delete()
        self.db.query(User).delete()
        self.db.commit()
        self.db.close()

    def test_valid_unexpired_access_token(self):
        """
        IF access token exists AND has not expired:
        return existing access token without contacting Google token endpoint.
        """
        future_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        token_record = OAuthToken(
            user_id=self.user.id,
            access_token="valid_active_google_access_token",
            refresh_token="valid_refresh_token_abc",
            expires_at=future_expiry
        )
        self.db.add(token_record)
        self.db.commit()

        with patch("requests.post") as mock_post:
            token = AuthService.get_valid_google_access_token(self.db, self.user.id, force_refresh=False)
            self.assertEqual(token, "valid_active_google_access_token")
            # Must NOT make an HTTP request if unexpired
            mock_post.assert_not_called()

    def test_expired_access_token_triggers_automatic_refresh(self):
        """
        IF access token is expired:
        backend automatically calls Google token endpoint, updates DB, and returns new access token.
        """
        past_expiry = datetime.now(timezone.utc) - timedelta(minutes=10)
        token_record = OAuthToken(
            user_id=self.user.id,
            access_token="expired_access_token_123",
            refresh_token="valid_refresh_token_xyz",
            expires_at=past_expiry
        )
        self.db.add(token_record)
        self.db.commit()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "brand_new_refreshed_access_token",
            "expires_in": 3600,
            "token_type": "Bearer"
        }

        with patch("requests.post", return_value=mock_response) as mock_post:
            token = AuthService.get_valid_google_access_token(self.db, self.user.id, force_refresh=False)
            self.assertEqual(token, "brand_new_refreshed_access_token")
            mock_post.assert_called_once()

            # Verify token record was updated in database
            updated_token = self.db.query(OAuthToken).filter(OAuthToken.user_id == self.user.id).first()
            self.assertEqual(updated_token.access_token, "brand_new_refreshed_access_token")
            exp = updated_token.expires_at
            if exp and exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            self.assertGreater(exp, datetime.now(timezone.utc))

    def test_near_expiration_buffer_triggers_refresh(self):
        """
        A token expiring within the 60-second safety buffer triggers refresh proactively.
        """
        near_expiry = datetime.now(timezone.utc) + timedelta(seconds=30)
        token_record = OAuthToken(
            user_id=self.user.id,
            access_token="almost_expired_token",
            refresh_token="valid_refresh_token_xyz",
            expires_at=near_expiry
        )
        self.db.add(token_record)
        self.db.commit()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "refreshed_buffer_token",
            "expires_in": 3600
        }

        with patch("requests.post", return_value=mock_response) as mock_post:
            token = AuthService.get_valid_google_access_token(self.db, self.user.id, force_refresh=False)
            self.assertEqual(token, "refreshed_buffer_token")
            mock_post.assert_called_once()

    def test_missing_refresh_token_raises_auth_error(self):
        """
        IF access token is expired AND no refresh token exists:
        return an authentication error requiring the user to reconnect Google.
        """
        past_expiry = datetime.now(timezone.utc) - timedelta(minutes=10)
        token_record = OAuthToken(
            user_id=self.user.id,
            access_token="expired_token_no_refresh",
            refresh_token=None,
            expires_at=past_expiry
        )
        self.db.add(token_record)
        self.db.commit()

        with self.assertRaises(HTTPException) as ctx:
            AuthService.get_valid_google_access_token(self.db, self.user.id, force_refresh=False)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("refresh token not found", ctx.exception.detail.lower())

    def test_refresh_failure_from_google_raises_401(self):
        """
        IF Google token endpoint returns 400/401 on refresh:
        raise 401 authentication error requiring reconnect.
        """
        past_expiry = datetime.now(timezone.utc) - timedelta(minutes=10)
        token_record = OAuthToken(
            user_id=self.user.id,
            access_token="expired_token",
            refresh_token="revoked_refresh_token",
            expires_at=past_expiry
        )
        self.db.add(token_record)
        self.db.commit()

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "invalid_grant"}

        with patch("requests.post", return_value=mock_response):
            with self.assertRaises(HTTPException) as ctx:
                AuthService.get_valid_google_access_token(self.db, self.user.id, force_refresh=False)
            self.assertEqual(ctx.exception.status_code, 401)

    def test_gmail_401_retry_flow(self):
        """
        If a Gmail API request returns HTTP 401:
        invalidate/refresh the access token, obtain fresh token, and retry the request once.
        """
        token_record = OAuthToken(
            user_id=self.user.id,
            access_token="initial_access_token",
            refresh_token="good_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        self.db.add(token_record)
        self.db.commit()

        # Step 1: Initial Gmail request returns 401
        res_401 = MagicMock()
        res_401.status_code = 401
        res_401.text = "Unauthorized"

        # Step 2: Google token refresh succeeds
        res_refresh = MagicMock()
        res_refresh.status_code = 200
        res_refresh.json.return_value = {"access_token": "new_refreshed_access_token", "expires_in": 3600}

        # Step 3: Retry Gmail request succeeds (empty list of messages)
        res_200 = MagicMock()
        res_200.status_code = 200
        res_200.json.return_value = {"messages": []}

        with patch("requests.get", side_effect=[res_401, res_200]) as mock_get:
            with patch("requests.post", return_value=res_refresh) as mock_post:
                count = GmailService.sync_user_emails(self.db, self.user, limit=10)
                self.assertEqual(count, 0)
                # Verify Gmail API was called twice (initial + retry)
                self.assertEqual(mock_get.call_count, 2)
                # Verify refresh endpoint was called
                mock_post.assert_called_once()

    def test_gmail_401_retry_failure_aborts_without_infinite_loop(self):
        """
        If Gmail request returns 401 and retry also returns 401:
        raise 401 error and do not loop indefinitely.
        """
        token_record = OAuthToken(
            user_id=self.user.id,
            access_token="initial_access_token",
            refresh_token="good_refresh_token",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        self.db.add(token_record)
        self.db.commit()

        res_401 = MagicMock()
        res_401.status_code = 401
        res_401.text = "Unauthorized"

        res_refresh = MagicMock()
        res_refresh.status_code = 200
        res_refresh.json.return_value = {"access_token": "new_refreshed_access_token", "expires_in": 3600}

        with patch("requests.get", side_effect=[res_401, res_401]) as mock_get:
            with patch("requests.post", return_value=res_refresh):
                with self.assertRaises(HTTPException) as ctx:
                    GmailService.sync_user_emails(self.db, self.user, limit=10)
                self.assertEqual(ctx.exception.status_code, 401)
                self.assertEqual(mock_get.call_count, 2)

    def test_demo_mode_bypasses_live_sync_cleanly(self):
        """
        In Demo / Preview Mode (demo_ tokens):
        sync_user_emails gracefully skips live Gmail API calls without error.
        """
        demo_user = User(
            id="demo-user-id-999",
            email="demo.user@mailshield.ai",
            name="Security Analyst (Demo User)",
            google_id="google_demo_1092837465"
        )
        demo_token = OAuthToken(
            user_id=demo_user.id,
            access_token="demo_google_access_token_xyz123",
            refresh_token="demo_google_refresh_token_abc789",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        self.db.add(demo_user)
        self.db.add(demo_token)
        self.db.commit()

        with patch("requests.get") as mock_get:
            count = GmailService.sync_user_emails(self.db, demo_user, limit=20)
            self.assertEqual(count, 0)
            mock_get.assert_not_called()


    def test_new_message_ingestion_and_forensic_availability(self):
        """
        When a new email is detected:
        - Persist EmailMessage
        - Store raw headers, links, snippet
        - Make it immediately available for forensic analysis
        """
        from app.services.email_header_forensics_service import EmailHeaderForensicsService
        
        token_record = OAuthToken(
            user_id=self.user.id,
            access_token="valid_access_token_for_new_mail",
            refresh_token="valid_refresh_token_for_new_mail",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        self.db.add(token_record)
        self.db.commit()

        # Mock list messages endpoint
        res_list = MagicMock()
        res_list.status_code = 200
        res_list.json.return_value = {"messages": [{"id": "gmail_msg_1001", "threadId": "thread_1001"}]}

        # Mock get message detail endpoint
        res_detail = MagicMock()
        res_detail.status_code = 200
        res_detail.json.return_value = {
            "id": "gmail_msg_1001",
            "threadId": "thread_1001",
            "snippet": "Urgent security update required",
            "payload": {
                "headers": [
                    {"name": "From", "value": "security@alert-service.com"},
                    {"name": "To", "value": self.user.email},
                    {"name": "Subject", "value": "Action Required: Verify Account"},
                    {"name": "Date", "value": "Wed, 12 Sep 2026 12:00:00 +0000"},
                    {"name": "Received", "value": "from mail.suspicious.com ([198.51.100.25]) by mx.google.com with ESMTPS; Wed, 12 Sep 2026 12:00:00 +0000"},
                    {"name": "Authentication-Results", "value": "mx.google.com; spf=pass (google.com: domain of security@alert-service.com designates 198.51.100.25 as permitted sender) smtp.mailfrom=security@alert-service.com; dkim=pass header.i=@alert-service.com"}
                ],
                "mimeType": "text/plain",
                "body": {"data": "UGxlYXNlIHZlcmlmeSB5b3VyIGFjY291bnQgaW1tZWRpYXRlbHkgYXQgaHR0cHM6Ly9waGlzaC1leGFtcGxlLmNvbS9sb2dpbg=="}
            }
        }

        with patch("requests.get", side_effect=[res_list, res_detail]):
            with patch("app.services.ai_service.AIService.analyze_email_by_id"):
                count = GmailService.sync_user_emails(self.db, self.user, limit=20)
                self.assertEqual(count, 1)

        # Verify email is saved in database
        saved_email = self.db.query(EmailMessage).filter(EmailMessage.id == "gmail_msg_1001").first()
        self.assertIsNotNone(saved_email)
        self.assertEqual(saved_email.subject, "Action Required: Verify Account")
        self.assertEqual(saved_email.sender, "security@alert-service.com")
        self.assertIn("https://phish-example.com/login", saved_email.links)
        self.assertEqual(len(saved_email.raw_headers), 6)

        # Verify Header Forensics immediately parses and analyzes the newly ingested email
        from app.controllers.forensics_controller import ForensicsController
        forensic_result = ForensicsController.get_email_forensic_headers(self.db, self.user, "gmail_msg_1001")
        self.assertEqual(forensic_result.email_id, "gmail_msg_1001")
        self.assertEqual(forensic_result.authentication.spf, "pass")
        self.assertEqual(forensic_result.authentication.dkim, "pass")
        self.assertEqual(forensic_result.origin_ip_candidate, "198.51.100.25")

    def test_duplicate_messages_are_not_duplicated_in_database(self):
        """
        Running sync multiple times encounters existing message IDs and skips re-downloading/duplicating them.
        """
        token_record = OAuthToken(
            user_id=self.user.id,
            access_token="valid_token_idempotent",
            refresh_token="valid_refresh_token_idempotent",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        self.db.add(token_record)
        
        # Pre-seed existing message in DB
        existing_email = EmailMessage(
            id="gmail_msg_existing",
            user_id=self.user.id,
            sender="boss@corp.com",
            recipient=self.user.email,
            subject="Quarterly Review",
            date=datetime.now(timezone.utc)
        )
        self.db.add(existing_email)
        self.db.commit()

        # Gmail returns the existing message ID
        res_list = MagicMock()
        res_list.status_code = 200
        res_list.json.return_value = {"messages": [{"id": "gmail_msg_existing", "threadId": "thread_1"}]}

        with patch("requests.get", return_value=res_list) as mock_get:
            count = GmailService.sync_user_emails(self.db, self.user, limit=20)
            self.assertEqual(count, 0)
            # Only list endpoint called, detail endpoint NOT called
            self.assertEqual(mock_get.call_count, 1)

        # Database should still contain exactly 1 copy of this message
        total_in_db = self.db.query(EmailMessage).filter(EmailMessage.id == "gmail_msg_existing").count()
        self.assertEqual(total_in_db, 1)

    def test_background_sync_worker_syncs_connected_users(self):
        """
        Background sync worker automatically discovers connected Google accounts and invokes sync.
        """
        from app.services.gmail_sync_worker import _sync_all_connected_users
        
        token_record = OAuthToken(
            user_id=self.user.id,
            access_token="valid_token_for_worker",
            refresh_token="valid_refresh_token_for_worker",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        self.db.add(token_record)
        self.db.commit()

        with patch("app.services.gmail_sync_worker.SessionLocal", return_value=self.db):
            with patch.object(GmailService, "sync_user_emails", return_value=3) as mock_sync:
                _sync_all_connected_users()
                mock_sync.assert_called_once()


if __name__ == "__main__":
    unittest.main()

