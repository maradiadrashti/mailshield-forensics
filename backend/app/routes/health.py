from fastapi import APIRouter, status
from app.schemas.health import HealthCheckResponse
from app.controllers.health_controller import HealthController

router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Application Health Diagnostics",
    description="Check application health status and operational parameters."
)
async def check_health() -> HealthCheckResponse:
    return HealthController.get_health_status()
