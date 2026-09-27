#!/usr/bin/env bash
# MailShield AI - Unix/WSL/Git Bash Startup Script

set -e
cd "$(dirname "$0")"

# Find python3 or python
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "Error: Python 3 is not installed or not in PATH."
    exit 1
fi

exec "$PYTHON_CMD" start.py "$@"
