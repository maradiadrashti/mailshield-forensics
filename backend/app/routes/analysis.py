from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.auth.dependencies import get_current_user
from app.models.user import User
from app.schemas.analysis import AnalysisResultResponse, BatchAnalysisResponse
from app.controllers.ai_controller import AIController

router = APIRouter(prefix="/analysis", tags=["AI Threat Analysis"])


@router.post(
    "/email/{email_id}",
    response_model=AnalysisResultResponse,
    status_code=status.HTTP_200_OK,
    summary="Run AI threat analysis on a specific email"
)
async def analyze_email(
    email_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return AIController.analyze_email(db, current_user, email_id)


@router.get(
    "/email/{email_id}",
    response_model=AnalysisResultResponse,
    status_code=status.HTTP_200_OK,
    summary="Get cached AI threat analysis result for an email"
)
async def get_analysis(
    email_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return AIController.get_email_analysis(db, current_user, email_id)


@router.post(
    "/batch",
    response_model=BatchAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Run batch AI threat analysis on all user inbox emails"
)
async def batch_analyze_inbox(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return AIController.batch_analyze_inbox(db, current_user)
