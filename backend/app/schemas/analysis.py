from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class LayerBreakdown(BaseModel):
    score: int = Field(default=0, ge=0, le=100)
    max_score: int = Field(default=100, ge=0, le=100)
    status: str = Field(default="safe", description="safe, suspicious, elevated, critical")
    signals: list[str] = Field(default_factory=list)
    has_history: Optional[bool] = None
    history_count: Optional[int] = None
    details: dict[str, Any] = Field(default_factory=dict)


class ThreeLayerBreakdown(BaseModel):
    content_security: LayerBreakdown
    transport_forensics: LayerBreakdown
    behavioral_ai: LayerBreakdown


class ThreatBreakdown(BaseModel):
    phishing_score: int = Field(default=0, ge=0, le=100)
    scam_score: int = Field(default=0, ge=0, le=100)
    url_score: int = Field(default=0, ge=0, le=100)
    misinformation_score: int = Field(default=0, ge=0, le=100)
    social_engineering_score: int = Field(default=0, ge=0, le=100)
    layers: Optional[ThreeLayerBreakdown] = None


class AnalysisResultResponse(BaseModel):
    id: str
    email_id: str
    user_id: str
    risk_score: int = Field(..., ge=0, le=100, description="MailShield Risk Score from 0 (safe) to 100 (high threat)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="AI Confidence probability level")
    threat_type: str = Field(..., description="Categorized threat label or primary verdict")
    verdict: Optional[str] = Field(default=None, description="Dynamic evidence-based primary verdict")
    severity: Optional[str] = Field(default=None, description="Severity tier: safe, low, high, critical")
    is_trusted_sender: bool = Field(default=False, description="Whether the sender is verified as a Trusted Sender")
    reasons: list[str] = Field(default_factory=list, description="Explainable evidentiary reasons for score")
    recommendations: list[str] = Field(default_factory=list, description="Actionable security mitigation advice")
    breakdown: ThreatBreakdown
    layers: Optional[ThreeLayerBreakdown] = None
    analyzed_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BatchAnalysisResponse(BaseModel):
    analyzed_count: int
    high_risk_count: int
    results: list[AnalysisResultResponse]

