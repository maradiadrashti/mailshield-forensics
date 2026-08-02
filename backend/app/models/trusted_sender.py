from datetime import datetime, timezone
import uuid
from sqlalchemy import String, DateTime, ForeignKey, UniqueConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base


class TrustedSender(Base):
    __tablename__ = "trusted_senders"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type: Mapped[str] = mapped_column(String(50), nullable=False)  # "email" or "domain"
    value: Mapped[str] = mapped_column(String(255), nullable=False, index=True)  # email address or domain name (lowercase)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship to user
    user = relationship("User", back_populates="trusted_senders")

    # Composite uniqueness constraint to prevent duplicate trust policies
    __table_args__ = (
        UniqueConstraint("user_id", "type", "value", name="uq_user_trusted_sender"),
    )
