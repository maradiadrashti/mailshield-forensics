@echo off
setlocal enabledelayedexpansion
title MailShield AI - Startup Launcher

echo ====================================================================
echo   MailShield AI - Enterprise Cybersecurity & Forensics Platform
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
    echo [NOTICE] MailShield terminated.
    pause
)
