from datetime import datetime, timezone
import uuid
from typing import Any
from sqlalchemy import String, Integer, Float, DateTime, ForeignKey, JSON, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    email_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("email_messages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    
    # MailShield AI Indicators
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)  # 0 (safe) to 100 (extreme danger)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)  # 0.0 to 1.0
    threat_type: Mapped[str] = mapped_column(String(50), nullable=False)  # Phishing, Scam, Suspicious URL, Misinformation, Social Engineering, Safe
    is_trusted_sender: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Explainable AI Fields
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommendations: Mapped[list[str]] = mapped_column(JSON, default=list)
    breakdown: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    
    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    email: Mapped["EmailMessage"] = relationship("EmailMessage")
    user: Mapped["User"] = relationship("User")
