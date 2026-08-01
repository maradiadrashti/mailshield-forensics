from sqlalchemy.orm import Session
from app.models.user import User
from app.schemas.analysis import AnalysisResultResponse, BatchAnalysisResponse
from app.services.ai_service import AIService


class AIController:
    @staticmethod
    def analyze_email(db: Session, user: User, email_id: str) -> AnalysisResultResponse:
        result = AIService.analyze_email_by_id(db, user, email_id)
        return AnalysisResultResponse.model_validate(result)

    @staticmethod
    def get_email_analysis(db: Session, user: User, email_id: str) -> AnalysisResultResponse:
        result = AIService.get_analysis_by_email_id(db, user, email_id)
        return AnalysisResultResponse.model_validate(result)

    @staticmethod
    def batch_analyze_inbox(db: Session, user: User) -> BatchAnalysisResponse:
        total_count, high_risk_count, results = AIService.batch_analyze_inbox(db, user)
        return BatchAnalysisResponse(
            analyzed_count=total_count,
            high_risk_count=high_risk_count,
            results=[AnalysisResultResponse.model_validate(r) for r in results]
        )
