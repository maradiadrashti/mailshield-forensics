import unittest
import json
import hashlib
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.base import Base
from app.models.email import EmailMessage
from app.models.audit_log import AuditLog
from app.services.email_header_forensics_service import EmailHeaderForensicsService
from app.schemas.forensics import ForensicHeaderResponse

class TestEvidenceIntegrity(unittest.TestCase):
    def setUp(self):
        # Create SQLite in-memory database for isolated unit testing
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = SessionLocal()
        Base.metadata.create_all(bind=self.engine)

        # Populate sample staging email
        self.email = EmailMessage(
            id="test_integrity_msg_001",
            user_id="test-user-uuid",
            sender="spoofed@paypal-security.com",
            recipient="victim@domain.com",
            subject="Action Required: Account Suspended",
            date=datetime.now(timezone.utc),
            body_text="Dear customer, please verify your credentials.",
            body_html="<p>Dear customer, please verify your credentials.</p>",
            links=["http://phishing-paypal.com/login"],
            attachments=[],
            raw_headers=[
                {"name": "From", "value": "spoofed@paypal-security.com"},
                {"name": "To", "value": "victim@domain.com"},
                {"name": "Subject", "value": "Action Required: Account Suspended"},
                {
                    "name": "Received",
                    "value": "from attacker-relay.com (attacker.com [198.51.100.99]) by mx.google.com with ESMTPS; Mon, 24 Aug 2026 12:00:00 +0000"
                }
            ]
        )
        self.db.add(self.email)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_cryptographic_evidence_integrity_creation(self):
        """
        Verify that evidence_integrity is generated, linked, and saved in SQLite as an AuditLog block.
        """
        result: ForensicHeaderResponse = EmailHeaderForensicsService.parse_headers(
            self.email.raw_headers, email_id=self.email.id, db=self.db
        )

        # Check returned integrity fields
        self.assertIsNotNone(result.evidence_integrity)
        self.assertTrue(result.evidence_integrity.evidence_id.startswith("EVD-"))
        self.assertEqual(result.evidence_integrity.last_audit_event, "BLOCK #1 [VALID]")
        self.assertEqual(result.evidence_integrity.chain_of_custody_status, "Cryptographically Sealed (SHA-256 Chain)")

        # Verify record exists in SQLite
        audit_block = self.db.query(AuditLog).filter(AuditLog.investigation_id == self.email.id).first()
        self.assertIsNotNone(audit_block)
        self.assertEqual(audit_block.block_number, 1)
        self.assertEqual(audit_block.prev_hash, "0" * 64)
        self.assertEqual(audit_block.raw_payload_hash, result.evidence_integrity.evidence_sha256)

        # Calculate payload hash manually to verify correctness
        headers_json = json.dumps(self.email.raw_headers, sort_keys=True)
        payload_str = f"{self.email.id}:{headers_json}:{self.email.body_text}"
        expected_payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        self.assertEqual(audit_block.raw_payload_hash, expected_payload_hash)

    def test_audit_log_hash_chaining(self):
        """
        Verify successive AuditLog blocks are chained cryptographically via prev_hash -> block_hash linking.
        """
        # Block 1
        EmailHeaderForensicsService.parse_headers(self.email.raw_headers, email_id=self.email.id, db=self.db)
        block1 = self.db.query(AuditLog).filter(AuditLog.block_number == 1).first()

        # Add a second email
        email2 = EmailMessage(
            id="test_integrity_msg_002",
            user_id="test-user-uuid",
            sender="secure@github.com",
            recipient="victim@domain.com",
            subject="GitHub MFA Alert",
            date=datetime.now(timezone.utc),
            body_text="A login was detected from a new IP.",
            raw_headers=[
                {"name": "From", "value": "secure@github.com"},
                {"name": "Received", "value": "from github-out.com ([140.82.112.1]) by mx.google.com; Mon, 24 Aug 2026 12:10:00 +0000"}
            ]
        )
        self.db.add(email2)
        self.db.commit()

        # Block 2
        EmailHeaderForensicsService.parse_headers(email2.raw_headers, email_id=email2.id, db=self.db)
        block2 = self.db.query(AuditLog).filter(AuditLog.block_number == 2).first()

        self.assertIsNotNone(block1)
        self.assertIsNotNone(block2)
        self.assertEqual(block2.prev_hash, block1.block_hash)
        
        # Verify block_hash calculation matches: prev_hash + payload_hash + timestamp
        timestamp_str = block2.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        expected_block2_data = f"{block1.block_hash}:{block2.raw_payload_hash}:{timestamp_str}"
        expected_block2_hash = hashlib.sha256(expected_block2_data.encode("utf-8")).hexdigest()
        self.assertEqual(block2.block_hash, expected_block2_hash)
