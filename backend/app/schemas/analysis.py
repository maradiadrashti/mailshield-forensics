from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class ThreatBreakdown(BaseModel):
    phishing_score: int = Field(..., ge=0, le=100)
    scam_score: int = Field(..., ge=0, le=100)
    url_score: int = Field(..., ge=0, le=100)
    misinformation_score: int = Field(..., ge=0, le=100)
    social_engineering_score: int = Field(..., ge=0, le=100)


class AnalysisResultResponse(BaseModel):
    id: str
    email_id: str
    user_id: str
    risk_score: int = Field(..., ge=0, le=100, description="MailShield Risk Score from 0 (safe) to 100 (high threat)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="AI Confidence probability level")
    threat_type: str = Field(..., description="Categorized threat label")
    reasons: list[str] = Field(default_factory=list, description="Explainable evidentiary reasons for score")
    recommendations: list[str] = Field(default_factory=list, description="Actionable security mitigation advice")
    breakdown: ThreatBreakdown
    analyzed_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BatchAnalysisResponse(BaseModel):
    analyzed_count: int
    high_risk_count: int
    results: list[AnalysisResultResponse]
