from pydantic import BaseModel, Field


class HealthCheckResponse(BaseModel):
    status: str = Field(..., example="healthy")
    app_name: str = Field(..., example="MailShield AI")
    environment: str = Field(..., example="development")
    timestamp: str = Field(..., example="2026-07-29T19:00:00Z")
