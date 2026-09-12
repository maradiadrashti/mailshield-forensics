from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.email import EmailMessage
from app.models.investigation import Investigation
from app.schemas.forensics import (
    ForensicHeaderResponse,
    InvestigationItem,
    InvestigationListResponse,
    OpenInvestigationRequest,
)
from app.services.gmail_service import GmailService
from app.services.email_header_forensics_service import EmailHeaderForensicsService
from app.services.investigation_service import InvestigationService


class ForensicsController:
    @staticmethod
    def get_email_forensic_headers(
        db: Session, user: User, email_id: str
    ) -> ForensicHeaderResponse:
        """
        Retrieves, verifies ownership, extracts raw headers, and parses forensic
        header intelligence for a specific email message or investigation.
        """
        # Resolve by email ID
        email = db.query(EmailMessage).filter(
            EmailMessage.id == email_id, EmailMessage.user_id == user.id
        ).first()

        # If not found directly, check if email_id is an investigation ID
        if not email:
            inv = db.query(Investigation).filter(
                Investigation.id == email_id, Investigation.user_id == user.id
            ).first()
            if inv:
                email = db.query(EmailMessage).filter(
                    EmailMessage.id == inv.email_id, EmailMessage.user_id == user.id
                ).first()

        if not email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Email message with ID '{email_id}' was not found."
            )

        # Retrieve raw headers (cached or live via Gmail API)
        raw_headers = GmailService.fetch_raw_message_headers(db, user, email.id)

        # Parse and normalize headers through forensic parser
        return EmailHeaderForensicsService.parse_headers(raw_headers, email_id=email.id, db=db)

    @staticmethod
    def list_investigations(
        db: Session,
        user: User,
        status_filter: Optional[str] = None,
        search: Optional[str] = None
    ) -> InvestigationListResponse:
        """
        Retrieves the authenticated user's forensic investigations with true evidence-based metrics.
        """
        return InvestigationService.get_user_investigations(
            db=db, user=user, status_filter=status_filter, search=search
        )

    @staticmethod
    def open_investigation(
        db: Session,
        user: User,
        req: OpenInvestigationRequest
    ) -> InvestigationItem:
        """
        Creates or retrieves a persistent investigation case for a real email message.
        """
        return InvestigationService.create_or_get_investigation(
            db=db, user=user, email_id=req.email_id, notes=req.notes
        )

    @staticmethod
    def get_investigation_detail(
        db: Session,
        user: User,
        investigation_id_or_email_id: str
    ) -> InvestigationItem:
        """
        Retrieves full details for a single investigation case.
        """
        return InvestigationService.get_investigation_by_id(
            db=db, user=user, investigation_id_or_email_id=investigation_id_or_email_id
        )
