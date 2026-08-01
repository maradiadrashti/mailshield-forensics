from datetime import datetime, timezone
from app.schemas.health import HealthCheckResponse
from app.core.config import settings


class HealthController:
    @staticmethod
    def get_health_status() -> HealthCheckResponse:
        """
        Retrieves health diagnostics status for system components.
        """
        return HealthCheckResponse(
            status="healthy",
            app_name=settings.PROJECT_NAME,
            environment=settings.ENVIRONMENT,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
