from fastapi import APIRouter, Depends, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.core.config import settings
from app.database.session import get_db
from app.schemas.auth import (
    GoogleAuthUrlResponse,
    GoogleAuthCodeRequest,
    TokenResponse,
    RefreshTokenRequest,
    UserResponse,
    LogoutResponse,
)
from app.controllers.auth_controller import AuthController
from app.auth.dependencies import get_current_user
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["Authentication"])



@router.get(
    "/google/login",
    response_model=GoogleAuthUrlResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Google OAuth authorization URL"
)
async def google_login():
    return AuthController.get_google_auth_url()


@router.get(
    "/google/callback",
    summary="Google OAuth GET browser redirect handler"
)
async def google_callback_get(code: str = None, error: str = None):
    """
    Handles browser HTTP GET redirect from Google OAuth consent screen
    and forwards the authorization code to the React frontend callback page.
    """
    if error:
        return RedirectResponse(url=f"{settings.FRONTEND_URL}/auth/callback?error={error}")
    if code:
        return RedirectResponse(url=f"{settings.FRONTEND_URL}/auth/callback?code={code}")
    return RedirectResponse(url=f"{settings.FRONTEND_URL}/login")



@router.post(
    "/google/callback",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Exchange Google OAuth code for access and refresh tokens"
)
async def google_callback_post(
    payload: GoogleAuthCodeRequest,
    db: Session = Depends(get_db)
):
    return AuthController.handle_google_callback(db, payload.code)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh MailShield JWT access token"
)
async def refresh_token(
    payload: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    return AuthController.refresh_token(db, payload.refresh_token)


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get authenticated user profile"
)
async def get_me(current_user: User = Depends(get_current_user)):
    return AuthController.get_user_profile(current_user)


@router.post(
    "/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="User logout endpoint"
)
async def logout(current_user: User = Depends(get_current_user)):
    return AuthController.logout()
