import logging
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.user import User
from app.models.email import EmailMessage
from app.models.analysis_result import AnalysisResult
from app.models.investigation import Investigation
from app.schemas.forensics import (
    InvestigationItem,
    InvestigationMetrics,
    InvestigationListResponse,
)
from app.services.ai_service import AIService

logger = logging.getLogger("mailshield.investigation_service")


class InvestigationService:
    @staticmethod
    def _to_item(
        investigation: Investigation,
        email: EmailMessage,
        analysis: Optional[AnalysisResult] = None
    ) -> InvestigationItem:
        score = analysis.risk_score if analysis else 0
        verdict = analysis.verdict if analysis else "No Significant Threat Detected"
        severity = analysis.severity if analysis else ("safe" if score < 25 else "high")
        
        # Calculate threat level label for UI
        if score >= 75 or severity == "critical":
            threat_level = "critical"
        elif score >= 50 or severity == "high":
            threat_level = "high"
        elif score >= 25 or severity in ["suspicious", "elevated", "low"]:
            threat_level = "suspicious"
        else:
            threat_level = "safe"

        # Date formatting
        date_iso = email.date.isoformat() if email.date else datetime.now(timezone.utc).isoformat()
        created_iso = investigation.created_at.isoformat() if investigation.created_at else datetime.now(timezone.utc).isoformat()
        updated_iso = investigation.updated_at.isoformat() if investigation.updated_at else datetime.now(timezone.utc).isoformat()

        return InvestigationItem(
            id=investigation.id,
            email_id=email.id,
            gmail_message_id=email.id,
            sender=email.sender,
            recipient=email.recipient,
            subject=email.subject or "(No Subject)",
            date=date_iso,
            snippet=email.snippet,
            score=score,
            risk_score=score,
            verdict=verdict,
            threat_level=threat_level,
            severity=severity,
            status=investigation.status,
            report_generated=investigation.report_generated,
            notes=investigation.notes,
            created_at=created_iso,
            updated_at=updated_iso
        )

    @classmethod
    def create_or_get_investigation(
        cls,
        db: Session,
        user: User,
        email_id: str,
        notes: Optional[str] = None
    ) -> InvestigationItem:
        """
        Creates a new persistent investigation for a real email, or returns the existing one.
        Ensures AI threat analysis is run using the 3-layer deterministic engine.
        Prevents duplicate investigations for the same email.
        """
        # 1. Resolve email message belonging to this user
        email = db.query(EmailMessage).filter(
            EmailMessage.id == email_id, EmailMessage.user_id == user.id
        ).first()

        # If not found by direct email_id, check if email_id is actually an existing investigation ID
        if not email:
            existing_inv = db.query(Investigation).filter(
                Investigation.id == email_id, Investigation.user_id == user.id
            ).first()
            if existing_inv:
                email = db.query(EmailMessage).filter(
                    EmailMessage.id == existing_inv.email_id, EmailMessage.user_id == user.id
                ).first()

        if not email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Email message with ID '{email_id}' was not found in your mailbox."
            )

        # 2. Check if an investigation already exists for this email and user
        investigation = db.query(Investigation).filter(
            Investigation.email_id == email.id, Investigation.user_id == user.id
        ).first()

        # 3. Ensure AI threat analysis is up-to-date
        analysis = db.query(AnalysisResult).filter(
            AnalysisResult.email_id == email.id, AnalysisResult.user_id == user.id
        ).first()
        if not analysis:
            analysis = AIService.analyze_email_by_id(db, user, email.id)

        # 4. If investigation does not exist, create and persist it
        if not investigation:
            investigation = Investigation(
                user_id=user.id,
                email_id=email.id,
                status="open",
                notes=notes,
                report_generated=False
            )
            db.add(investigation)
            db.commit()
            db.refresh(investigation)
            logger.info(f"Created persistent Investigation '{investigation.id}' for email '{email.id}'")
        else:
            if notes and not investigation.notes:
                investigation.notes = notes
                db.commit()
                db.refresh(investigation)

        return cls._to_item(investigation, email, analysis)

    @classmethod
    def get_user_investigations(
        cls,
        db: Session,
        user: User,
        status_filter: Optional[str] = None,
        search: Optional[str] = None
    ) -> InvestigationListResponse:
        """
        Fetches all real persistent investigations for the authenticated user,
        calculates authentic metrics, and returns the list.
        """
        query = db.query(Investigation, EmailMessage, AnalysisResult).join(
            EmailMessage, Investigation.email_id == EmailMessage.id
        ).outerjoin(
            AnalysisResult, AnalysisResult.email_id == EmailMessage.id
        ).filter(
            Investigation.user_id == user.id
        )

        if status_filter and status_filter.strip() != "":
            query = query.filter(Investigation.status == status_filter.strip())

        query = query.order_by(desc(Investigation.created_at))
        rows = query.all()

        items: List[InvestigationItem] = []
        dangerous_count = 0
        suspicious_count = 0
        reports_generated_count = 0

        for inv, email, analysis in rows:
            # If analysis is missing, run it on the fly
            if not analysis:
                try:
                    analysis = AIService.analyze_email_by_id(db, user, email.id)
                except Exception as e:
                    logger.warning(f"Failed on-the-fly analysis for email {email.id}: {e}")
                    analysis = None

            item = cls._to_item(inv, email, analysis)

            # Apply in-memory search filter if provided
            if search and search.strip():
                term = search.strip().lower()
                matches = (
                    term in item.subject.lower()
                    or term in item.sender.lower()
                    or term in item.verdict.lower()
                    or term in item.id.lower()
                    or term in item.email_id.lower()
                )
                if not matches:
                    continue

            items.append(item)

            # Metric Calculations
            if item.score >= 75 or item.severity == "critical":
                dangerous_count += 1
            elif item.score >= 25 or item.severity in ["high", "suspicious", "elevated"]:
                suspicious_count += 1

            if inv.report_generated:
                reports_generated_count += 1

        metrics = InvestigationMetrics(
            total_investigations=len(items) if not search else len(rows),
            dangerous_count=dangerous_count,
            suspicious_count=suspicious_count,
            reports_generated_count=reports_generated_count
        )

        return InvestigationListResponse(
            metrics=metrics,
            investigations=items,
            total=len(items)
        )

    @classmethod
    def get_investigation_by_id(
        cls,
        db: Session,
        user: User,
        investigation_id_or_email_id: str
    ) -> InvestigationItem:
        """
        Retrieves an investigation by either its investigation UUID or email message ID.
        If an investigation does not yet exist for a valid user email, creates it.
        """
        # Try investigation UUID first
        inv = db.query(Investigation).filter(
            Investigation.id == investigation_id_or_email_id,
            Investigation.user_id == user.id
        ).first()

        if not inv:
            # Try email message ID
            inv = db.query(Investigation).filter(
                Investigation.email_id == investigation_id_or_email_id,
                Investigation.user_id == user.id
            ).first()

        if inv:
            email = db.query(EmailMessage).filter(
                EmailMessage.id == inv.email_id, EmailMessage.user_id == user.id
            ).first()
            analysis = db.query(AnalysisResult).filter(
                AnalysisResult.email_id == inv.email_id, AnalysisResult.user_id == user.id
            ).first()
            if not analysis:
                analysis = AIService.analyze_email_by_id(db, user, inv.email_id)
            return cls._to_item(inv, email, analysis)

        # If not found as investigation, check if it's a real email and auto-create
        return cls.create_or_get_investigation(db, user, investigation_id_or_email_id)

    @classmethod
    def mark_report_generated(cls, db: Session, user: User, email_id_or_inv_id: str) -> None:
        """
        Marks an investigation as having generated an audit report.
        """
        inv = db.query(Investigation).filter(
            (Investigation.id == email_id_or_inv_id) | (Investigation.email_id == email_id_or_inv_id),
            Investigation.user_id == user.id
        ).first()

        if inv:
            inv.report_generated = True
            db.commit()
