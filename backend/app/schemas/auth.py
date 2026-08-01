from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    name: str
    avatar_url: str | None = None
    google_id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class GoogleAuthUrlResponse(BaseModel):
    url: str


class GoogleAuthCodeRequest(BaseModel):
    code: str = Field(..., description="Google OAuth authorization code received from callback")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int  # Seconds
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LogoutResponse(BaseModel):
    message: str = "Logged out successfully"
