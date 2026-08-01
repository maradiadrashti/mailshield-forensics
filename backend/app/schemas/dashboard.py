from pydantic import BaseModel, Field
from app.schemas.gmail import EmailMessageResponse
from app.schemas.analysis import AnalysisResultResponse


class ThreatCategoriesBreakdown(BaseModel):
    phishing: int = 0
    scam: int = 0
    suspicious_url: int = 0
    misinformation: int = 0
    social_engineering: int = 0


class WeeklyDataPoint(BaseModel):
    day: str
    total: int
    threats: int


class DashboardStatsResponse(BaseModel):
    inbox_security_score: int = Field(..., ge=0, le=100, description="Overall Inbox Security Rating")
    total_emails: int
    safe_emails: int
    dangerous_emails: int
    threat_detection_rate: float
    threat_categories: ThreatCategoriesBreakdown
    weekly_analytics: list[WeeklyDataPoint]
    recent_threats: list[EmailMessageResponse]
    security_recommendations: list[str]
