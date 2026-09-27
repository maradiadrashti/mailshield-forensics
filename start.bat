@echo off
setlocal enabledelayedexpansion
title MailShield Forensics - Startup Launcher (SIH26106)

echo ====================================================================
echo   MailShield Forensics - AI Threat Detection & Forensics Platform
echo   Smart India Hackathon (SIH26106) | Cybersecurity & Forensics
echo ====================================================================
echo.

cd /d "%~dp0"

:: Check if Python is installed
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in PATH!
    echo Please install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

:: Run unified supervisor
python start.py %*

if %errorlevel% neq 0 (
    echo.
    echo [NOTICE] MailShield Forensics terminated.
    pause
)
