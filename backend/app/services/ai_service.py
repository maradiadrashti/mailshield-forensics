from datetime import datetime, timezone
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.email import EmailMessage
from app.models.analysis_result import AnalysisResult
from app.ai.scoring_engine import ScoringEngine


class AIService:
    @classmethod
    def analyze_email_by_id(cls, db: Session, user: User, email_id: str, force: bool = False) -> AnalysisResult:
        email = db.query(EmailMessage).filter(
            EmailMessage.id == email_id, EmailMessage.user_id == user.id
        ).first()

        if not email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Email message with ID '{email_id}' was not found."
            )

        # Check if trusted sender
        from app.models.trusted_sender import TrustedSender
        import re

        clean_sender_email = email.sender.strip().lower()
        match = re.search(r'<([^>]+)>', clean_sender_email)
        if match:
            clean_sender_email = match.group(1).strip().lower()

        clean_sender_domain = clean_sender_email.split("@")[-1] if "@" in clean_sender_email else clean_sender_email

        # Query user's trusted senders/domains
        trusted_records = db.query(TrustedSender).filter(
            TrustedSender.user_id == user.id
        ).all()

        is_trusted = False
        for rec in trusted_records:
            val = rec.value.strip().lower()
            if rec.type == "email" and val == clean_sender_email:
                is_trusted = True
                break
            elif rec.type == "domain" and val == clean_sender_domain:
                is_trusted = True
                break

        # Check existing result first to avoid redundant heavy analysis / API calls
        existing_result = db.query(AnalysisResult).filter(
            AnalysisResult.email_id == email.id, AnalysisResult.user_id == user.id
        ).first()

        if existing_result and not force:
            if existing_result.is_trusted_sender == is_trusted:
                return existing_result
            force = True

        # Run AI & Scoring Engine Analysis
        analysis_data = ScoringEngine.analyze_email(
            sender=email.sender,
            recipient=email.recipient,
            subject=email.subject,
            body_text=email.body_text or "",
            links=email.links or [],
            attachments=email.attachments or [],
            is_trusted_sender=is_trusted
        )

        if existing_result:
            existing_result.risk_score = analysis_data["risk_score"]
            existing_result.confidence = analysis_data["confidence"]
            existing_result.threat_type = analysis_data["threat_type"]
            existing_result.is_trusted_sender = is_trusted
            existing_result.reasons = analysis_data["reasons"]
            existing_result.recommendations = analysis_data["recommendations"]
            existing_result.breakdown = analysis_data["breakdown"]
            existing_result.analyzed_at = datetime.now(timezone.utc)
            result = existing_result
        else:
            result = AnalysisResult(
                email_id=email.id,
                user_id=user.id,
                risk_score=analysis_data["risk_score"],
                confidence=analysis_data["confidence"],
                threat_type=analysis_data["threat_type"],
                is_trusted_sender=is_trusted,
                reasons=analysis_data["reasons"],
                recommendations=analysis_data["recommendations"],
                breakdown=analysis_data["breakdown"]
            )
            db.add(result)

        db.commit()
        db.refresh(result)
        return result

    @classmethod
    def get_analysis_by_email_id(cls, db: Session, user: User, email_id: str) -> AnalysisResult:
        result = db.query(AnalysisResult).filter(
            AnalysisResult.email_id == email_id, AnalysisResult.user_id == user.id
        ).first()

        if not result:
            # If not yet analyzed, run analysis on demand
            return cls.analyze_email_by_id(db, user, email_id)

        return result

    @classmethod
    def batch_analyze_inbox(cls, db: Session, user: User) -> tuple[int, int, list[AnalysisResult]]:
        emails = db.query(EmailMessage).filter(EmailMessage.user_id == user.id).all()
        results = []
        high_risk_count = 0

        for email in emails:
            res = cls.analyze_email_by_id(db, user, email.id)
            results.append(res)
            if res.risk_score >= 60:
                high_risk_count += 1

        return len(results), high_risk_count, results

    @classmethod
    def sync_trusted_sender_emails(cls, db: Session, user: User) -> None:
        """
        Re-scans all emails for a user to ensure their `is_trusted_sender` status
        and AI threat/risk scores are correctly synced with the user's current trusted senders.
        """
        emails = db.query(EmailMessage).filter(EmailMessage.user_id == user.id).all()
        for email in emails:
            cls.analyze_email_by_id(db, user, email.id, force=True)
