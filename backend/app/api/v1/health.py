from datetime import datetime, timezone
from fastapi import APIRouter, status
from pydantic import BaseModel
from app.core.config import settings


class HealthCheckResponse(BaseModel):
    status: str
    app_name: str
    environment: str
    timestamp: str


router = APIRouter(tags=["Health"])


@router.get(
    "/health",
    response_model=HealthCheckResponse,
    status_code=status.HTTP_200_OK,
    summary="Application Health Check",
    description="Returns current operational status, application name, environment, and server timestamp."
)
async def health_check() -> HealthCheckResponse:
    return HealthCheckResponse(
        status="healthy",
        app_name=settings.PROJECT_NAME,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc).isoformat()
    )
