from datetime import datetime, timezone
import uuid
from sqlalchemy import String, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column
from app.database.base import Base

class AuditLog(Base):
    """
    Tamper-evident audit log table representing a hash chain of custody block.
    """
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    evidence_id: Mapped[str] = mapped_column(String(32), nullable=False)
    investigation_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    block_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    raw_payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    block_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    status: Mapped[str] = mapped_column(String(64), default="VERIFIED_TAMPER_PROOF")
