from app.schemas.health import HealthCheckResponse
from app.controllers.health_controller import HealthController


class HealthService:
    @staticmethod
    def get_status() -> HealthCheckResponse:
        return HealthController.get_health_status()
