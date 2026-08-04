from sqlalchemy.orm import Session
from app.schemas.auth import (
    GoogleAuthUrlResponse,
    TokenResponse,
    UserResponse,
    LogoutResponse,
)
from app.services.auth_service import AuthService
from app.models.user import User


class AuthController:
    @staticmethod
    def get_google_auth_url(force_consent: bool = False) -> GoogleAuthUrlResponse:
        url = AuthService.get_google_auth_url(force_consent=force_consent)
        return GoogleAuthUrlResponse(url=url)

    @staticmethod
    def handle_google_callback(db: Session, code: str) -> TokenResponse:
        return AuthService.process_google_callback(db, code)

    @staticmethod
    def refresh_token(db: Session, refresh_token: str) -> TokenResponse:
        return AuthService.refresh_access_token(db, refresh_token)

    @staticmethod
    def get_user_profile(user: User) -> UserResponse:
        return UserResponse.model_validate(user)

    @staticmethod
    def logout() -> LogoutResponse:
        return LogoutResponse()
