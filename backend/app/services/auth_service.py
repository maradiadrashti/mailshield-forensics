from datetime import datetime, timedelta, timezone
import requests
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.user import User
from app.models.oauth_token import OAuthToken
from app.schemas.auth import TokenResponse, UserResponse
from app.auth.jwt import create_access_token, create_refresh_token, decode_token

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


class AuthService:
    @staticmethod
    def get_google_auth_url(force_consent: bool = False) -> str:
        """
        Generates production Google OAuth 2.0 Consent URL with required scopes.
        """
        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
            if settings.ENABLE_DEV_DEMO:
                return f"{settings.BACKEND_URL}{settings.API_V1_STR}/auth/google/demo/page"
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google OAuth not configured: set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your backend environment."
            )
        scopes = [
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/gmail.readonly"
        ]
        scope_str = "%20".join(scopes)
        
        prompt_val = "consent" if force_consent else "select_account"
        url = (
            f"https://accounts.google.com/o/oauth2/v2/auth?"
            f"client_id={settings.GOOGLE_CLIENT_ID}&"
            f"redirect_uri={settings.GOOGLE_REDIRECT_URI}&"
            f"response_type=code&"
            f"scope={scope_str}&"
            f"access_type=offline&"
            f"prompt={prompt_val}"
        )
        return url

    @classmethod
    def process_google_callback(cls, db: Session, code: str) -> TokenResponse:
        """
        Exchanges Google OAuth authorization code for Google access/refresh tokens,
        fetches authenticated Google user profile, creates/updates User in database,
        stores OAuth token credentials, and issues MailShield JWT session tokens.
        """
        # Isolate Demo Login strictly behind ENABLE_DEV_DEMO flag
        if settings.ENABLE_DEV_DEMO and code.startswith("demo_google_auth_code"):
            if "maradiadrashti" in code:
                google_user = {
                    "id": "google_user_3280443330746947833",
                    "email": "maradiadrashti@gmail.com",
                    "name": "Maradiadrashti (Analyst)",
                    "picture": "https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/user-check.svg"
                }
                google_tokens = {
                    "access_token": "demo_google_access_token_maradiadrashti",
                    "refresh_token": "demo_google_refresh_token_maradiadrashti",
                    "expires_in": 3600,
                    "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly",
                    "token_type": "Bearer"
                }
            elif "drashti" in code:
                google_user = {
                    "id": "101655607069190686749",
                    "email": "24ug1bycs898@bmsit.in",
                    "name": "Drashti Maradia CSE-1",
                    "picture": "https://lh3.googleusercontent.com/a/ACg8ocKY6CQb1BPhTBpu3NPTpvBYp4piIEujHBKdwvxHGAad91VdUw=s96-c"
                }
                google_tokens = {
                    "access_token": "demo_google_access_token_drashti",
                    "refresh_token": "demo_google_refresh_token_drashti",
                    "expires_in": 3600,
                    "scope": "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid https://www.googleapis.com/auth/gmail.readonly",
                    "token_type": "Bearer"
                }
            else:
                google_user = {
                    "id": "google_demo_1092837465",
                    "email": "demo.user@mailshield.ai",
                    "name": "Security Analyst (Demo User)",
                    "picture": "https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/user-check.svg"
                }
                google_tokens = {
                    "access_token": "demo_google_access_token_xyz123",
                    "refresh_token": "demo_google_refresh_token_abc789",
                    "expires_in": 3600,
                    "scope": "openid email profile https://www.googleapis.com/auth/gmail.readonly",
                    "token_type": "Bearer"
                }
            access_token = google_tokens.get("access_token")
        else:
            # Production Real Google OAuth 2.0 Exchange
            token_payload = {
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code"
            }
            
            try:
                token_res = requests.post(GOOGLE_TOKEN_URL, data=token_payload, timeout=12)
            except Exception as net_err:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Network error connecting to Google OAuth servers: {str(net_err)}"
                )

            if token_res.status_code != 200:
                err_detail = token_res.json().get("error_description") or token_res.text
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Google OAuth authorization code exchange failed: {err_detail}"
                )

            google_tokens = token_res.json()
            access_token = google_tokens.get("access_token")
            if not access_token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No access token returned from Google OAuth exchange."
                )

        if not google_user:
            # Fetch authenticated User Profile from Google API
            userinfo_res = requests.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10
            )

            if userinfo_res.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to retrieve user profile from Google UserInfo API."
                )

            google_user = userinfo_res.json()

        if not google_user or "email" not in google_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Google profile data returned."
            )

        # Database Upsert for User
        user = db.query(User).filter(User.google_id == google_user["id"]).first()
        if not user:
            user = db.query(User).filter(User.email == google_user["email"]).first()

        if user:
            user.name = google_user.get("name", user.name)
            user.avatar_url = google_user.get("picture", user.avatar_url)
            user.google_id = google_user.get("id", user.google_id)
        else:
            user = User(
                email=google_user["email"],
                name=google_user.get("name", "MailShield User"),
                avatar_url=google_user.get("picture"),
                google_id=google_user["id"]
            )
            db.add(user)
        
        db.commit()
        db.refresh(user)

        # Database Upsert for OAuth Tokens
        expires_in = google_tokens.get("expires_in", 3600)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        token_record = db.query(OAuthToken).filter(OAuthToken.user_id == user.id).first()
        
        has_refresh = "yes" if google_tokens.get("refresh_token") else "no"
        import logging
        logger = logging.getLogger("mailshield.services")
        logger.info(f"Processing Google OAuth callback. Storing tokens for user ID: {user.id}. Refresh token in response: {has_refresh}")

        if token_record:
            logger.info(f"Updating existing OAuthToken record in database for user ID: {user.id}")
            token_record.access_token = google_tokens.get("access_token", token_record.access_token)
            if google_tokens.get("refresh_token"):
                token_record.refresh_token = google_tokens.get("refresh_token")
            token_record.expires_at = expires_at
            token_record.scope = google_tokens.get("scope", token_record.scope)
        else:
            logger.info(f"Creating new OAuthToken record in database for user ID: {user.id}")
            token_record = OAuthToken(
                user_id=user.id,
                access_token=google_tokens.get("access_token", ""),
                refresh_token=google_tokens.get("refresh_token"),
                scope=google_tokens.get("scope"),
                expires_at=expires_at
            )
            db.add(token_record)
            
        db.commit()
        logger.info(f"OAuthToken record saved successfully for user ID: {user.id}. Access token expires at: {expires_at}")

        # Issue MailShield JWT Tokens
        jwt_payload = {"sub": user.id, "email": user.email, "name": user.name}
        jwt_access_token = create_access_token(jwt_payload)
        jwt_refresh_token = create_refresh_token(jwt_payload)

        return TokenResponse(
            access_token=jwt_access_token,
            refresh_token=jwt_refresh_token,
            token_type="Bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserResponse.model_validate(user)
        )

    @classmethod
    def get_valid_google_access_token(cls, db: Session, user_id: str, force_refresh: bool = False) -> str:
        """
        Retrieves the user's stored Google Access Token. If expired or force_refresh is True,
        automatically refreshes it using the Google Refresh Token and updates the database.
        """
        import logging
        logger = logging.getLogger("mailshield.services")

        token_record = db.query(OAuthToken).filter(OAuthToken.user_id == user_id).first()
        if not token_record or not token_record.access_token:
            logger.error(f"Google OAuth credentials not found in database for user ID: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google OAuth credentials not found for user. Please sign in again."
            )

        # Check token expiration buffer (5 minutes margin)
        now_utc = datetime.now(timezone.utc)
        token_exp = token_record.expires_at
        if token_exp and token_exp.tzinfo is None:
            token_exp = token_exp.replace(tzinfo=timezone.utc)

        is_expired = token_exp and (token_exp - timedelta(minutes=5)) <= now_utc

        if force_refresh or is_expired:
            reason = "forced manual refresh" if force_refresh else f"token expired/nearing expiration (expires_at={token_exp}, now={now_utc})"
            logger.info(f"Initiating Google token refresh for user ID {user_id} due to {reason}.")
            
            # Attempt automatic refresh if refresh_token is present
            refresh_token = token_record.refresh_token
            if refresh_token and refresh_token.startswith("demo_") and settings.MOCK_GOOGLE_REFRESH_TOKEN:
                refresh_token = settings.MOCK_GOOGLE_REFRESH_TOKEN
                logger.info("Using MOCK_GOOGLE_REFRESH_TOKEN from environment for fallback live sync refresh.")

            if not refresh_token:
                logger.error(f"Google refresh token not found for user ID {user_id}. Deleting invalid token record.")
                db.delete(token_record)
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Google refresh token not found. Please sign in with Google again."
                )
            
            try:
                client_id = settings.GOOGLE_CLIENT_ID
                client_secret = settings.GOOGLE_CLIENT_SECRET
                
                # If using public OAuth Playground credentials, leverage Google's Playground refresh proxy
                if (not client_id or not client_secret) and refresh_token.startswith("1//"):
                    proxy_url = "https://developers.google.com/oauthplayground/refreshAccessToken"
                    logger.info("Using Google OAuth Playground refresh proxy endpoint.")
                    res = requests.post(
                        proxy_url, 
                        json={"refresh_token": refresh_token}, 
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                        timeout=10
                    )
                    logger.info(f"Google OAuth Playground proxy response status: {res.status_code}")
                    if res.status_code == 200:
                        data = res.json()
                        if data.get("success") and data.get("access_token"):
                            new_access_token = data.get("access_token")
                            token_record.access_token = new_access_token
                            new_expires_in = data.get("expires_in", 3600)
                            token_record.expires_at = now_utc + timedelta(seconds=new_expires_in)
                            db.commit()
                            logger.info("Successfully refreshed Google access token using OAuth Playground proxy.")
                            return new_access_token
                
                refresh_payload = {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token"
                }
                logger.info(f"Sending POST request to Google token refresh URL: {GOOGLE_TOKEN_URL}")
                res = requests.post(GOOGLE_TOKEN_URL, data=refresh_payload, timeout=10)
                logger.info(f"Google Token URL response status: {res.status_code}")
                
                if res.status_code == 200:
                    new_data = res.json()
                    new_access_token = new_data.get("access_token")
                    if not new_access_token:
                        logger.error("Token refresh response did not contain 'access_token'.")
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="OAuth refresh failed: Google response did not include a new access token."
                        )
                    token_record.access_token = new_access_token
                    if refresh_token == settings.MOCK_GOOGLE_REFRESH_TOKEN:
                        token_record.refresh_token = refresh_token
                    new_expires_in = new_data.get("expires_in", 3600)
                    token_record.expires_at = now_utc + timedelta(seconds=new_expires_in)
                    db.commit()
                    logger.info(f"Google Access Token refreshed successfully for user ID {user_id}. New expiry: {token_record.expires_at}")
                else:
                    err_json = {}
                    try:
                        err_json = res.json()
                    except Exception:
                        pass
                    err_msg = err_json.get("error", "")
                    err_desc = err_json.get("error_description", "")
                    logger.error(f"Failed to refresh Google Access Token: Status={res.status_code}, Error={err_msg}, Description={err_desc}")
                    
                    if res.status_code in (400, 401) or err_msg == "invalid_grant":
                        # Clear invalid tokens from database
                        db.delete(token_record)
                        db.commit()
                        logger.warning(f"Deleted invalid OAuth credentials for user ID {user_id} due to invalid grant error.")
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Google account authorization has been revoked or expired. Please sign in with Google again."
                        )
                    else:
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Google token refresh failed: {err_msg} ({err_desc})"
                        )
            except HTTPException:
                raise
            except Exception as e:
                logger.exception(f"Failed to refresh Google Access Token automatically: {e}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Failed to refresh Google access token: {str(e)}"
                )

        return token_record.access_token

    @classmethod
    def refresh_access_token(cls, db: Session, refresh_token: str) -> TokenResponse:
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type for refresh operation"
            )

        user_id = payload.get("sub")
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User associated with refresh token not found"
            )

        jwt_payload = {"sub": user.id, "email": user.email, "name": user.name}
        new_access_token = create_access_token(jwt_payload)
        new_refresh_token = create_refresh_token(jwt_payload)

        return TokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="Bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserResponse.model_validate(user)
        )

