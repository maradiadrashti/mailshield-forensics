from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.auth.dependencies import get_current_user
from app.models.user import User
from app.schemas.dashboard import DashboardStatsResponse
from app.controllers.dashboard_controller import DashboardController

router = APIRouter(prefix="/dashboard", tags=["Dashboard Intelligence"])


@router.get(
    "/stats",
    response_model=DashboardStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get real-time executive dashboard security metrics and analytics"
)
async def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return DashboardController.get_stats(db, current_user)
