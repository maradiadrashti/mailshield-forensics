from datetime import datetime
from pydantic import BaseModel, Field
from app.schemas.analysis import ThreatBreakdown


class OCRAnalysisResponse(BaseModel):
    filename: str
    extracted_text: str
    extracted_urls: list[str]
    risk_score: int = Field(..., ge=0, le=100)
    confidence: float = Field(..., ge=0.0, le=1.0)
    threat_type: str
    reasons: list[str]
    recommendations: list[str]
    breakdown: ThreatBreakdown
    scanned_at: datetime
