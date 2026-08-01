from sqlalchemy.orm import Session
from app.models.user import User
from app.schemas.dashboard import DashboardStatsResponse
from app.services.dashboard_service import DashboardService


class DashboardController:
    @staticmethod
    def get_stats(db: Session, user: User) -> DashboardStatsResponse:
        return DashboardService.get_stats(db, user)
