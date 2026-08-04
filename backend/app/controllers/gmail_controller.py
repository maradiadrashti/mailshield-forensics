import math
from datetime import datetime, timezone
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.email import EmailMessage
from app.schemas.gmail import (
    EmailMessageResponse,
    PaginatedEmailResponse,
    EmailSyncResponse,
)
from app.services.gmail_service import GmailService


class GmailController:
    @staticmethod
    def sync_emails(db: Session, user: User, limit: int = 20) -> EmailSyncResponse:
        count = GmailService.sync_user_emails(db, user, limit=limit)
        return EmailSyncResponse(
            message=f"Successfully synced {count} new email messages from Gmail.",
            count=count,
            synced_at=datetime.now(timezone.utc).isoformat()
        )

    @staticmethod
    def get_emails(
        db: Session,
        user: User,
        page: int = 1,
        size: int = 20,
        search: str | None = None
    ) -> PaginatedEmailResponse:
        # Always run sync to check for new real-time emails on page 1 load
        if page == 1:
            try:
                GmailService.sync_user_emails(db, user, limit=size)
            except HTTPException as http_err:
                raise http_err
            except Exception as sync_err:
                print(f"Warning: Auto-sync on page 1 load failed: {sync_err}")

        items, total = GmailService.get_paginated_emails(
            db=db, user=user, page=page, size=size, search=search
        )
        pages = math.ceil(total / size) if total > 0 else 1

        return PaginatedEmailResponse(
            items=[EmailMessageResponse.model_validate(item) for item in items],
            total=total,
            page=page,
            size=size,
            pages=pages
        )

    @staticmethod
    def get_email_by_id(db: Session, user: User, email_id: str) -> EmailMessageResponse:
        email = db.query(EmailMessage).filter(
            EmailMessage.id == email_id, EmailMessage.user_id == user.id
        ).first()

        if not email:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Email message with ID '{email_id}' was not found."
            )

        return EmailMessageResponse.model_validate(email)
