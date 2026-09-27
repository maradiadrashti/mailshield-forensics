<#
.SYNOPSIS
    Starts MailShield Forensics (SIH26106 FastAPI backend + Vite React frontend).

.DESCRIPTION
    Launches MailShield Forensics development environment with automated dependency verification,
    port collision checks, health-check polling, and quiet background log management.

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

.PARAMETER VerboseLog
    Stream live continuous HTTP request logs to console (default: logs saved to logs/ directory).

.EXAMPLE
    .\start.ps1
    .\start.ps1 -NoBrowser
    .\start.ps1 -KillStale
    .\start.ps1 -VerboseLog
#>

[CmdletBinding()]
param(
    [switch]$NoBrowser,
    [switch]$BackendOnly,
    [switch]$FrontendOnly,
    [switch]$KillStale,
    [switch]$Install,
    [switch]$VerboseLog
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
if ($VerboseLog)   { $pyArgs += "--verbose" }

& python @pyArgs

