from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.auth.dependencies import get_current_user
from app.models.user import User
from app.schemas.gmail import (
    PaginatedEmailResponse,
    EmailMessageResponse,
    EmailSyncResponse,
)
from app.controllers.gmail_controller import GmailController

router = APIRouter(prefix="/gmail", tags=["Gmail API"])


@router.get(
    "/messages",
    response_model=PaginatedEmailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get paginated list of user emails with extracted links and attachments"
)
async def list_messages(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=50, description="Items per page"),
    search: Optional[str] = Query(None, description="Search query by sender, subject or content"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return GmailController.get_emails(db, current_user, page=page, size=size, search=search)


@router.post(
    "/sync",
    response_model=EmailSyncResponse,
    status_code=status.HTTP_200_OK,
    summary="Sync latest emails from Gmail API"
)
async def sync_messages(
    limit: int = Query(20, ge=1, le=50, description="Max messages to fetch"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return GmailController.sync_emails(db, current_user, limit=limit)


@router.get(
    "/messages/{email_id}",
    response_model=EmailMessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Get full details for a specific email message"
)
async def get_message(
    email_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return GmailController.get_email_by_id(db, current_user, email_id)
