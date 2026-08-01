from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class AttachmentMeta(BaseModel):
    filename: str
    mime_type: str = "application/octet-stream"
    size: int = 0  # Bytes


class EmailMessageResponse(BaseModel):
    id: str
    thread_id: str | None = None
    sender: str
    recipient: str
    subject: str
    date: datetime
    snippet: str | None = None
    body_text: str | None = None
    body_html: str | None = None
    links: list[str] = Field(default_factory=list)
    attachments: list[AttachmentMeta] = Field(default_factory=list)
    fetched_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PaginatedEmailResponse(BaseModel):
    items: list[EmailMessageResponse]
    total: int
    page: int
    size: int
    pages: int


class EmailSyncResponse(BaseModel):
    message: str = "Gmail sync complete"
    count: int
    synced_at: str
