<#
.SYNOPSIS
    Starts MailShield AI (FastAPI backend + Vite React frontend) with pre-flight checks and monitoring.

.DESCRIPTION
    Launches MailShield AI development environment with automated dependency verification,
    port collision checks, health-check polling, and graceful process management.

.PARAMETER NoBrowser
    Do not automatically open the browser once services are up.

.PARAMETER BackendOnly
    Start only the FastAPI backend service.

.PARAMETER FrontendOnly
    Start only the React Vite frontend service.

.PARAMETER KillStale
    Automatically kill processes blocking ports 8000 or 3000.

.PARAMETER Install
    Force reinstall backend & frontend dependencies before launching.

.EXAMPLE
    .\start.ps1
    .\start.ps1 -NoBrowser
    .\start.ps1 -KillStale
#>

[CmdletBinding()]
param(
    [switch]$NoBrowser,
    [switch]$BackendOnly,
    [switch]$FrontendOnly,
    [switch]$KillStale,
    [switch]$Install
)

Set-Location $PSScriptRoot

# Verify Python is available
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[ERROR] Python was not found in PATH! Please install Python 3.10+." -ForegroundColor Red
    exit 1
}

# Construct arguments for start.py
$pyArgs = @("start.py")
if ($NoBrowser)    { $pyArgs += "--no-browser" }
if ($BackendOnly)  { $pyArgs += "--backend-only" }
if ($FrontendOnly) { $pyArgs += "--frontend-only" }
if ($KillStale)    { $pyArgs += "--kill-stale" }
if ($Install)      { $pyArgs += "--install" }

& python @pyArgs
