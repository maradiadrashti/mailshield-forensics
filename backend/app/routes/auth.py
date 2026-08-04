from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
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
async def google_login(force_consent: bool = False):
    return AuthController.get_google_auth_url(force_consent=force_consent)


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


@router.get(
    "/google/demo",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Development demo Google sign-in (dev only)"
)
async def google_demo(db: Session = Depends(get_db)):
    if not settings.ENABLE_DEV_DEMO:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Demo login not enabled")
    return AuthController.handle_google_callback(db, "demo_google_auth_code")


@router.get(
    "/google/demo/page",
    response_class=HTMLResponse,
    summary="Interactive Mock Google Sign-In UI"
)
async def google_demo_page():
    """
    Renders an interactive mock Google Sign-in screen where the user can enter
    their real Gmail address, typing in 'maradiadrashti@gmail.com' to log in
    successfully, or any other email (like '24ug1bycs898@bmsit.in') to trigger
    an 'access_denied' OAuth error simulating the unregistered test user state.
    """
    redirect_url = f"{settings.FRONTEND_URL}/auth/callback"
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in - Google Accounts</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <style>
        body {{
            font-family: 'Roboto', arial, sans-serif;
            background-color: #f0f4f9;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }}
        .container {{
            background: #ffffff;
            border-radius: 28px;
            width: 450px;
            padding: 40px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.08);
            box-sizing: border-box;
            position: relative;
            overflow: hidden;
            transition: height 0.3s ease;
        }}
        .header {{
            text-align: center;
            margin-bottom: 24px;
        }}
        .logo {{
            width: 74px;
            height: 24px;
            margin-bottom: 16px;
        }}
        .title {{
            font-size: 24px;
            font-weight: 400;
            color: #1f1f1f;
            margin: 0 0 8px 0;
        }}
        .subtitle {{
            font-size: 16px;
            color: #444746;
            margin: 0;
        }}
        .form-group {{
            position: relative;
            margin-top: 28px;
            margin-bottom: 20px;
        }}
        .input-field {{
            width: 100%;
            padding: 16px;
            font-size: 16px;
            border: 1px solid #747775;
            border-radius: 4px;
            outline: none;
            box-sizing: border-box;
            transition: border-color 0.2s, box-shadow 0.2s;
            color: #1f1f1f;
        }}
        .input-field:focus {{
            border-color: #0b57d0;
            box-shadow: 0 0 0 1px #0b57d0;
        }}
        .input-label {{
            position: absolute;
            left: 16px;
            top: 50%;
            transform: translateY(-50%);
            background: #ffffff;
            padding: 0 4px;
            color: #444746;
            transition: 0.2s ease all;
            pointer-events: none;
            font-size: 16px;
        }}
        .input-field:focus ~ .input-label,
        .input-field:not(:placeholder-shown) ~ .input-label {{
            top: 0;
            font-size: 12px;
            color: #0b57d0;
        }}
        .error-message {{
            color: #b3261e;
            font-size: 12px;
            margin-top: 4px;
            display: none;
            align-items: center;
            gap: 8px;
        }}
        .error-icon {{
            display: inline-block;
            width: 14px;
            height: 14px;
            background: #b3261e;
            color: white;
            border-radius: 50%;
            text-align: center;
            line-height: 14px;
            font-weight: bold;
            font-size: 10px;
        }}
        .btn-container {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 35px;
        }}
        .btn-link {{
            color: #0b57d0;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            background: none;
            border: none;
            padding: 0;
        }}
        .btn-link:hover {{
            color: #0045b3;
        }}
        .btn-primary {{
            background-color: #0b57d0;
            color: #ffffff;
            border: none;
            padding: 12px 24px;
            border-radius: 100px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.2s;
        }}
        .btn-primary:hover {{
            background-color: #0045b3;
            box-shadow: 0 1px 3px rgba(0,0,0,0.15);
        }}
        .email-display-badge {{
            display: inline-flex;
            align-items: center;
            padding: 6px 12px;
            border-radius: 100px;
            border: 1px solid #747775;
            font-size: 14px;
            color: #1f1f1f;
            cursor: pointer;
            margin-top: 8px;
            max-width: 250px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .email-display-badge:hover {{
            background-color: #f1f3f4;
        }}
        .email-display-badge svg {{
            margin-right: 8px;
            flex-shrink: 0;
        }}
        .footer {{
            margin-top: 40px;
            font-size: 12px;
            color: #5f6368;
            line-height: 1.5;
        }}
        .footer a {{
            color: #0b57d0;
            text-decoration: none;
        }}
        .step {{
            display: none;
        }}
        .step.active {{
            display: block;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Step 1: Email Input Screen -->
        <div id="step-email" class="step active">
            <div class="header">
                <svg class="logo" viewBox="0 0 74 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M7.7 18C4.3 18 1.5 15.1 1.5 11.5C1.5 7.9 4.3 5 7.7 5C9.4 5 11 5.7 12.1 6.9L10.3 8.7C9.6 8 8.8 7.6 7.7 7.6C5.5 7.6 3.9 9.4 3.9 11.5C3.9 13.6 5.5 15.4 7.7 15.4C9.8 15.4 11.2 13.9 11.5 12.2H7.7V9.7H13.9C14 10.1 14.1 10.6 14.1 11.2C14.1 15.2 11.4 18 7.7 18Z" fill="#4285F4"/>
                    <path d="M19.3 18C16.8 18 14.7 15.9 14.7 13.3C14.7 10.7 16.8 8.6 19.3 8.6C21.8 8.6 23.9 10.7 23.9 13.3C23.9 15.9 21.8 18 19.3 18ZM19.3 10.9C17.9 10.9 16.9 12 16.9 13.3C16.9 14.6 17.9 15.7 19.3 15.7C20.7 15.7 21.7 14.6 21.7 13.3C21.7 12 20.7 10.9 19.3 10.9Z" fill="#EA4335"/>
                    <path d="M29.5 18C27 18 24.9 15.9 24.9 13.3C24.9 10.7 27 8.6 29.5 8.6C32 8.6 34.1 10.7 34.1 13.3C34.1 15.9 32 18 29.5 18ZM29.5 10.9C28.1 10.9 27.1 12 27.1 13.3C27.1 14.6 28.1 15.7 29.5 15.7C30.9 15.7 31.9 14.6 31.9 13.3C31.9 12 30.9 10.9 29.5 10.9Z" fill="#FBBC05"/>
                    <path d="M39.6 22.8C37 22.8 34.9 20.7 34.9 18.1H37.1C37.1 19.5 38.2 20.6 39.6 20.6C41 20.6 42 19.5 42 18.1V17.3H41.9C41.2 18.1 40 18.8 38.7 18.8C36.3 18.8 34.2 16.7 34.2 14.1C34.2 11.5 36.3 9.4 38.7 9.4C40 9.4 41.2 10.1 41.9 10.9H42V9.7H44.1V18.1C44.1 21.1 42.2 22.8 39.6 22.8ZM39.7 11.7C38.3 11.7 37.3 12.8 37.3 14.1C37.3 15.4 38.3 16.5 39.7 16.5C41.1 16.5 42.1 15.4 42.1 14.1C42.1 12.8 41.1 11.7 39.7 11.7Z" fill="#4285F4"/>
                    <path d="M46.1 17.7V5.5H48.3V17.7H46.1Z" fill="#34A853"/>
                    <path d="M54.5 18C52 18 50.1 15.9 50.1 13.3C50.1 10.7 52 8.6 54.5 8.6C56.9 8.6 58.7 10.5 58.7 13C58.7 13.3 58.7 13.5 58.6 13.7H52.3C52.4 15 53.5 15.8 54.7 15.8C55.7 15.8 56.4 15.3 56.9 14.3L58.7 15.5C57.9 17 56.4 18 54.5 18ZM52.4 12H56.5C56.4 11.1 55.6 10.5 54.5 10.5C53.4 10.5 52.6 11.2 52.4 12Z" fill="#EA4335"/>
                </svg>
                <h1 class="title">Sign in</h1>
                <p class="subtitle">to continue to <strong>MailShield AI</strong></p>
            </div>

            <div class="form-group">
                <input type="text" id="email-input" class="input-field" placeholder=" " autocomplete="email">
                <label for="email-input" class="input-label">Email or phone</label>
                <div id="email-error" class="error-message">
                    <span class="error-icon">!</span>
                    <span id="email-error-text">Enter an email or phone number</span>
                </div>
            </div>

            <div style="margin-top: 10px;">
                <a href="#" class="btn-link" style="font-weight: 500;">Forgot email?</a>
            </div>

            <div style="margin-top: 24px; font-size: 14px; color: #5f6368; line-height: 1.4;">
                Not your computer? Use a Private Window to sign in. <a href="#" style="color: #0b57d0; text-decoration: none; font-weight: 500;">Learn more</a>
            </div>

            <div class="btn-container">
                <button class="btn-link" type="button" style="font-weight: 500;">Create account</button>
                <button class="btn-primary" type="button" onclick="submitEmail()">Next</button>
            </div>
        </div>

        <!-- Step 2: Password Input Screen -->
        <div id="step-password" class="step">
            <div class="header">
                <svg class="logo" viewBox="0 0 74 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M7.7 18C4.3 18 1.5 15.1 1.5 11.5C1.5 7.9 4.3 5 7.7 5C9.4 5 11 5.7 12.1 6.9L10.3 8.7C9.6 8 8.8 7.6 7.7 7.6C5.5 7.6 3.9 9.4 3.9 11.5C3.9 13.6 5.5 15.4 7.7 15.4C9.8 15.4 11.2 13.9 11.5 12.2H7.7V9.7H13.9C14 10.1 14.1 10.6 14.1 11.2C14.1 15.2 11.4 18 7.7 18Z" fill="#4285F4"/>
                    <path d="M19.3 18C16.8 18 14.7 15.9 14.7 13.3C14.7 10.7 16.8 8.6 19.3 8.6C21.8 8.6 23.9 10.7 23.9 13.3C23.9 15.9 21.8 18 19.3 18ZM19.3 10.9C17.9 10.9 16.9 12 16.9 13.3C16.9 14.6 17.9 15.7 19.3 15.7C20.7 15.7 21.7 14.6 21.7 13.3C21.7 12 20.7 10.9 19.3 10.9Z" fill="#EA4335"/>
                    <path d="M29.5 18C27 18 24.9 15.9 24.9 13.3C24.9 10.7 27 8.6 29.5 8.6C32 8.6 34.1 10.7 34.1 13.3C34.1 15.9 32 18 29.5 18ZM29.5 10.9C28.1 10.9 27.1 12 27.1 13.3C27.1 14.6 28.1 15.7 29.5 15.7C30.9 15.7 31.9 14.6 31.9 13.3C31.9 12 30.9 10.9 29.5 10.9Z" fill="#FBBC05"/>
                    <path d="M39.6 22.8C37 22.8 34.9 20.7 34.9 18.1H37.1C37.1 19.5 38.2 20.6 39.6 20.6C41 20.6 42 19.5 42 18.1V17.3H41.9C41.2 18.1 40 18.8 38.7 18.8C36.3 18.8 34.2 16.7 34.2 14.1C34.2 11.5 36.3 9.4 38.7 9.4C40 9.4 41.2 10.1 41.9 10.9H42V9.7H44.1V18.1C44.1 21.1 42.2 22.8 39.6 22.8ZM39.7 11.7C38.3 11.7 37.3 12.8 37.3 14.1C37.3 15.4 38.3 16.5 39.7 16.5C41.1 16.5 42.1 15.4 42.1 14.1C42.1 12.8 41.1 11.7 39.7 11.7Z" fill="#4285F4"/>
                    <path d="M46.1 17.7V5.5H48.3V17.7H46.1Z" fill="#34A853"/>
                    <path d="M54.5 18C52 18 50.1 15.9 50.1 13.3C50.1 10.7 52 8.6 54.5 8.6C56.9 8.6 58.7 10.5 58.7 13C58.7 13.3 58.7 13.5 58.6 13.7H52.3C52.4 15 53.5 15.8 54.7 15.8C55.7 15.8 56.4 15.3 56.9 14.3L58.7 15.5C57.9 17 56.4 18 54.5 18ZM52.4 12H56.5C56.4 11.1 55.6 10.5 54.5 10.5C53.4 10.5 52.6 11.2 52.4 12Z" fill="#EA4335"/>
                </svg>
                <h1 class="title">Welcome</h1>
                <div class="email-display-badge" onclick="goBackToEmail()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                        <circle cx="12" cy="7" r="4" />
                    </svg>
                    <span id="selected-email-display"></span>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" style="margin-left: 6px;">
                        <path d="M6 9l6 6 6-6" />
                    </svg>
                </div>
            </div>

            <div class="form-group">
                <input type="password" id="password-input" class="input-field" placeholder=" ">
                <label for="password-input" class="input-label">Enter your password</label>
                <div id="password-error" class="error-message">
                    <span class="error-icon">!</span>
                    <span id="password-error-text">Enter a password</span>
                </div>
            </div>

            <div style="margin-top: 10px; display: flex; align-items: center; gap: 8px;">
                <input type="checkbox" id="show-pass-check" onclick="toggleShowPassword()" style="width: 18px; height: 18px; cursor: pointer;">
                <label for="show-pass-check" style="font-size: 14px; color: #1f1f1f; cursor: pointer; user-select: none;">Show password</label>
            </div>

            <div class="btn-container" style="margin-top: 45px;">
                <button class="btn-link" type="button" onclick="goBackToEmail()" style="font-weight: 500;">Forgot password?</button>
                <button class="btn-primary" type="button" onclick="submitPassword()">Next</button>
            </div>
        </div>

        <div class="footer">
            To continue, Google will share your name, email address, language preference, and profile picture with MailShield AI. Before using this app, you can review its <a href="#">privacy policy</a> and <a href="#">terms of service</a>.
        </div>
    </div>

    <script>
        let enteredEmail = "";
        const frontendCallbackUrl = "{redirect_url}";

        document.addEventListener("DOMContentLoaded", function() {{
            const remembered = localStorage.getItem("google_remembered_email");
            if (remembered) {{
                document.getElementById("email-input").value = remembered;
            }}
        }});

        function submitEmail() {{
            const emailInput = document.getElementById("email-input");
            const emailError = document.getElementById("email-error");
            const emailErrorText = document.getElementById("email-error-text");
            const email = emailInput.value.trim();

            if (!email) {{
                emailErrorText.textContent = "Enter an email or phone number";
                emailError.style.display = "flex";
                emailInput.style.borderColor = "#b3261e";
                return;
            }}

            const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailPattern.test(email)) {{
                emailErrorText.textContent = "Couldn't find your Google Account";
                emailError.style.display = "flex";
                emailInput.style.borderColor = "#b3261e";
                return;
            }}

            emailError.style.display = "none";
            emailInput.style.borderColor = "#747775";

            enteredEmail = email;
            localStorage.setItem("google_remembered_email", email);
            document.getElementById("selected-email-display").textContent = email;

            document.getElementById("step-email").classList.remove("active");
            document.getElementById("step-password").classList.add("active");
            document.getElementById("password-input").focus();
        }}

        function goBackToEmail() {{
            document.getElementById("step-password").classList.remove("active");
            document.getElementById("step-email").classList.add("active");
            document.getElementById("email-input").focus();
        }}

        function toggleShowPassword() {{
            const passInput = document.getElementById("password-input");
            if (passInput.type === "password") {{
                passInput.type = "text";
            }} else {{
                passInput.type = "password";
            }}
        }}

        function submitPassword() {{
            const passInput = document.getElementById("password-input");
            const passError = document.getElementById("password-error");
            const password = passInput.value.trim();

            if (!password) {{
                passError.style.display = "flex";
                passInput.style.borderColor = "#b3261e";
                return;
            }}

            passError.style.display = "none";
            passInput.style.borderColor = "#747775";

            const lowerEmail = enteredEmail.toLowerCase();
            if (lowerEmail === "maradiadrashti@gmail.com") {{
                window.location.href = frontendCallbackUrl + "?code=demo_google_auth_code_maradiadrashti";
            }} else if (lowerEmail === "24ug1bycs898@bmsit.in") {{
                window.location.href = frontendCallbackUrl + "?code=demo_google_auth_code_drashti";
            }} else {{
                window.location.href = frontendCallbackUrl + "?error=access_denied";
            }}
        }}

        document.getElementById("email-input").addEventListener("keypress", function(event) {{
            if (event.key === "Enter") {{
                submitEmail();
            }}
        }});
        document.getElementById("password-input").addEventListener("keypress", function(event) {{
            if (event.key === "Enter") {{
                submitPassword();
            }}
        }});
    </script>
</body>
</html>"""
    return HTMLResponse(content=html)



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
