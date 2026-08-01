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

        # Check existing result first to avoid redundant heavy analysis / API calls
        existing_result = db.query(AnalysisResult).filter(
            AnalysisResult.email_id == email.id, AnalysisResult.user_id == user.id
        ).first()

        if existing_result and not force:
            return existing_result

        # Run AI & Scoring Engine Analysis
        analysis_data = ScoringEngine.analyze_email(
            sender=email.sender,
            recipient=email.recipient,
            subject=email.subject,
            body_text=email.body_text or "",
            links=email.links or [],
            attachments=email.attachments or []
        )

        if existing_result:
            existing_result.risk_score = analysis_data["risk_score"]
            existing_result.confidence = analysis_data["confidence"]
            existing_result.threat_type = analysis_data["threat_type"]
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
