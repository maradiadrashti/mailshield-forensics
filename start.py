#!/usr/bin/env python3
"""
MailShield Forensics — Unified Clean Startup & Development Orchestrator
Smart India Hackathon (SIH26106) Email Threat Detection & Forensic Platform
Cross-platform supervisor for launching Backend (FastAPI) and Frontend (Vite)
with health checks, port cleanup, quiet log management, and graceful shutdown.
"""

import os
import sys

# Ensure UTF-8 output encoding across Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

import time
import socket
import signal
import shutil
import secrets
import argparse
import threading
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

# Enable VT100 colors on Windows terminals
if os.name == 'nt':
    os.system('')

# ANSI Colors
CYAN = "\033[96m"
MAGENTA = "\033[95m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
FRONTEND_DIR = ROOT_DIR / "frontend"
LOGS_DIR = ROOT_DIR / "logs"

def log_info(msg: str):
    print(f"{GREEN}{BOLD}[STARTUP]{RESET} {msg}", flush=True)

def log_warn(msg: str):
    print(f"{YELLOW}{BOLD}[WARNING]{RESET} {msg}", flush=True)

def log_error(msg: str):
    print(f"{RED}{BOLD}[ERROR]{RESET} {msg}", flush=True)

def print_banner():
    banner = f"""{CYAN}{BOLD}
 ====================================================================
   __  __       _ _  _____ _     _      _     _            _____ 
  |  \\/  |     (_) |/ ____| |   (_)    | |   | |     /\\   |_   _|
  | \\  / | __ _ _| | (___ | |__  _  ___| | __| |    /  \\    | |  
  | |\\/| |/ _` | | |\\___ \\| '_ \\| |/ _ \\ |/ _` |   / /\\ \\   | |  
  | |  | | (_| | | |____) | | | | |  __/ | (_| |  / ____ \\ _| |_ 
  |_|  |_|\\__,_|_|_|_____/|_| |_|_|\\___|_|\\__,_| /_/    \\_\\_____|
 ====================================================================
  MailShield Forensics - AI Threat Detection & Forensic Platform
  Smart India Hackathon (SIH26106) | Cybersecurity & Forensics
 ===================================================================={RESET}"""
    print(banner, flush=True)

def get_venv_python() -> Path:
    if os.name == 'nt':
        return BACKEND_DIR / ".venv" / "Scripts" / "python.exe"
    return BACKEND_DIR / ".venv" / "bin" / "python"

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(('127.0.0.1', port)) == 0

def find_pid_using_port(port: int):
    if os.name == 'nt':
        try:
            output = subprocess.check_output(f"netstat -ano | findstr :{port}", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in output.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and f":{port}" in parts[1] and parts[3] == "LISTENING":
                    return int(parts[4])
        except Exception:
            return None
    else:
        try:
            output = subprocess.check_output(f"lsof -t -i:{port}", shell=True, text=True, stderr=subprocess.DEVNULL)
            pids = output.strip().split()
            if pids:
                return int(pids[0])
        except Exception:
            return None
    return None

def kill_process_tree(pid: int):
    try:
        if os.name == 'nt':
            subprocess.run(f"taskkill /F /T /PID {pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    except Exception as e:
        log_warn(f"Failed to kill PID {pid}: {e}")

def check_and_clear_port(port: int, service_name: str, auto_kill: bool = False):
    if is_port_in_use(port):
        pid = find_pid_using_port(port)
        pid_info = f" (PID: {pid})" if pid else ""
        log_warn(f"Port {port} ({service_name}) is currently occupied{pid_info}.")
        if auto_kill and pid:
            log_info(f"Terminating PID {pid} to free port {port}...")
            kill_process_tree(pid)
            time.sleep(1)
            if not is_port_in_use(port):
                log_info(f"Port {port} is now free.")
            else:
                log_warn(f"Port {port} is still occupied. You may need to kill it manually.")
        elif pid:
            log_warn(f"Pass --kill-stale to auto-terminate orphaned processes holding port {port}.")

def check_environment(auto_install: bool = False, kill_stale: bool = False):
    log_info("Running pre-flight system diagnostics...")

    # 1. Ensure logs directory exists
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # 2. Python Check
    py_ver = sys.version_info
    if py_ver < (3, 10):
        log_error(f"Python 3.10+ required. Current version is {py_ver.major}.{py_ver.minor}")
        sys.exit(1)
    log_info(f"Python runtime  : v{py_ver.major}.{py_ver.minor}.{py_ver.micro}")

    # 3. Node.js & npm Check
    node_bin = shutil.which("node")
    npm_bin = shutil.which("npm")
    if not node_bin or not npm_bin:
        log_error("Node.js and npm are required to run the frontend! Please install Node.js (v18+).")
        sys.exit(1)
    
    try:
        node_version = subprocess.check_output([node_bin, "-v"], text=True).strip()
        log_info(f"Node.js runtime : {node_version}")
    except Exception:
        log_warn("Could not retrieve Node.js version, proceeding anyway.")

    # 4. Virtual Environment Check
    venv_py = get_venv_python()
    if not venv_py.exists():
        log_warn(f"Backend virtual environment not found at {venv_py.parent.parent}")
        log_info("Creating new virtual environment in backend/.venv...")
        subprocess.run([sys.executable, "-m", "venv", str(BACKEND_DIR / ".venv")], check=True)
        auto_install = True

    # 5. Backend Dependencies
    if auto_install:
        log_info("Installing backend dependencies from requirements.txt...")
        subprocess.run([str(venv_py), "-m", "pip", "install", "-r", str(BACKEND_DIR / "requirements.txt")], check=True)

    # 6. Backend .env check
    backend_env = BACKEND_DIR / ".env"
    if not backend_env.exists():
        log_warn("backend/.env not found! Generating fresh configuration from .env.example...")
        example_env = BACKEND_DIR / ".env.example"
        env_content = ""
        if example_env.exists():
            env_content = example_env.read_text(encoding="utf-8")
        else:
            env_content = (
                "ENVIRONMENT=development\n"
                "DEBUG=True\n"
                "PROJECT_NAME=MailShield Forensics\n"
                "SECRET_KEY=change-me\n"
                "JWT_SECRET=change-me\n"
                "DATABASE_URL=sqlite:///./mailshield.db\n"
                "FRONTEND_URL=http://localhost:3000\n"
                "BACKEND_URL=http://localhost:8000\n"
                "ENABLE_DEV_DEMO=True\n"
            )
        secret_key = secrets.token_urlsafe(32)
        jwt_secret = secrets.token_urlsafe(32)
        env_content = env_content.replace("change-me-secret-key", secret_key)
        env_content = env_content.replace("change-me-jwt-secret", jwt_secret)
        backend_env.write_text(env_content, encoding="utf-8")
        log_info(f"Created {backend_env} with generated security keys.")

    # 7. Frontend node_modules check
    if not (FRONTEND_DIR / "node_modules").exists() or auto_install:
        log_info("Frontend node_modules missing. Running npm install...")
        subprocess.run(["npm", "install"], cwd=str(FRONTEND_DIR), shell=True, check=True)

    # 8. Check and clear ports automatically
    check_and_clear_port(8000, "FastAPI Backend", auto_kill=True)
    check_and_clear_port(3000, "Vite Frontend", auto_kill=True)

    log_info("Pre-flight checks completed successfully!\n")

def stream_and_write_logs(pipe, prefix: str, color: str, log_file_path: Path, verbose: bool = False):
    """Write all process output cleanly to a log file; only stream to terminal if verbose or an error occurs."""
    try:
        with open(log_file_path, "a", encoding="utf-8", errors="replace") as f_out:
            for line in iter(pipe.readline, ''):
                if line:
                    line_str = line.rstrip()
                    f_out.write(line_str + "\n")
                    f_out.flush()
                    if verbose:
                        print(f"{color}{BOLD}[{prefix}]{RESET} {line_str}", flush=True)
                    elif "ERROR" in line_str.upper() or "CRITICAL" in line_str.upper() or "EXCEPTION" in line_str.upper():
                        # Only show critical errors in terminal when in quiet/normal mode
                        print(f"{RED}{BOLD}[{prefix} ERROR]{RESET} {line_str}", flush=True)
    except (ValueError, OSError):
        pass
    finally:
        pipe.close()

def wait_for_health(timeout: int = 30) -> bool:
    log_info("Awaiting services readiness (health check)...")
    urls = [
        "http://127.0.0.1:8000/api/v1/health",
        "http://localhost:8000/api/v1/health",
        "http://127.0.0.1:8000/",
    ]
    start_time = time.time()
    while time.time() - start_time < timeout:
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "MailShield-Startup-Check"})
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                pass
        time.sleep(0.6)
    return False

def wait_for_frontend(timeout: int = 20) -> bool:
    start_time = time.time()
    while time.time() - start_time < timeout:
        if is_port_in_use(3000):
            return True
        time.sleep(0.5)
    return False

def open_browser(url: str):
    time.sleep(1.5)
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser(description="MailShield Forensics Clean Startup Orchestrator (SIH26106)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    parser.add_argument("--backend-only", action="store_true", help="Run only the FastAPI backend")
    parser.add_argument("--frontend-only", action="store_true", help="Run only the Vite frontend")
    parser.add_argument("--kill-stale", action="store_true", help="Auto-kill any processes occupying port 8000 or 3000")
    parser.add_argument("--install", action="store_true", help="Force install backend and frontend dependencies")
    parser.add_argument("--verbose", action="store_true", help="Stream all continuous HTTP/backend logs to the terminal")
    args = parser.parse_args()

    print_banner()
    check_environment(auto_install=args.install, kill_stale=True)

    processes = []
    venv_py = get_venv_python()

    # Handlers for graceful exit
    is_shutting_down = False
    def shutdown_all(signum=None, frame=None):
        nonlocal is_shutting_down
        if is_shutting_down:
            return
        is_shutting_down = True
        print(f"\n{YELLOW}{BOLD}[SHUTDOWN]{RESET} Gracefully terminating all MailShield services...", flush=True)
        for proc in processes:
            if proc.poll() is None:
                kill_process_tree(proc.pid)
        print(f"{GREEN}{BOLD}[SHUTDOWN]{RESET} All processes stopped cleanly. Goodbye!\n", flush=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_all)
    signal.signal(signal.SIGTERM, shutdown_all)

    backend_log_file = LOGS_DIR / "backend.log"
    frontend_log_file = LOGS_DIR / "frontend.log"

    # Reset log files for current session
    try:
        backend_log_file.write_text(f"--- MailShield Backend Log Started at {time.ctime()} ---\n", encoding="utf-8")
        frontend_log_file.write_text(f"--- MailShield Frontend Log Started at {time.ctime()} ---\n", encoding="utf-8")
    except Exception:
        pass

    # 1. Start Backend
    if not args.frontend_only:
        log_info(f"Starting FastAPI Backend Server on {BOLD}http://localhost:8000{RESET} (background)...")
        backend_cmd = [
            str(venv_py),
            "-m", "uvicorn",
            "app.main:app",
            "--host", "0.0.0.0",
            "--port", "8000",
            "--reload",
            "--reload-dir", "app",
            "--log-level", "info"
        ]
        
        backend_proc = subprocess.Popen(
            backend_cmd,
            cwd=str(BACKEND_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env={**os.environ, "PYTHONUNBUFFERED": "1"}
        )
        processes.append(backend_proc)

        threading.Thread(
            target=stream_and_write_logs,
            args=(backend_proc.stdout, "BACKEND", CYAN, backend_log_file, args.verbose),
            daemon=True
        ).start()

    # 2. Start Frontend
    if not args.backend_only:
        log_info(f"Starting Vite React Frontend on {BOLD}http://localhost:3000{RESET} (background)...")
        npm_cmd = "npm run dev"
        frontend_proc = subprocess.Popen(
            npm_cmd,
            cwd=str(FRONTEND_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            shell=True
        )
        processes.append(frontend_proc)

        threading.Thread(
            target=stream_and_write_logs,
            args=(frontend_proc.stdout, "FRONTEND", MAGENTA, frontend_log_file, args.verbose),
            daemon=True
        ).start()

    # 3. Health & Readiness checks
    backend_ok = True
    if not args.frontend_only:
        backend_ok = wait_for_health(timeout=25)
        if backend_ok:
            log_info(f"{GREEN}FastAPI Backend is healthy and operational!{RESET}")
        else:
            log_warn("Backend health check timed out, but process is running.")

    if not args.backend_only:
        frontend_ok = wait_for_frontend(timeout=15)
        if frontend_ok:
            log_info(f"{GREEN}Vite Frontend dev server is live and listening!{RESET}")

    # Print clean summary box
    summary = f"""
{GREEN}{BOLD}+--------------------------------------------------------------------+
|  MailShield Forensics (SIH26106) Platform is Live & Operational!   |
+--------------------------------------------------------------------+{RESET}
|  {BOLD}Frontend UI App{RESET}    : {CYAN}{BOLD}http://localhost:3000{RESET}                        |
|  {BOLD}Backend API Root{RESET}   : {CYAN}http://localhost:8000/api/v1{RESET}                   |
|  {BOLD}Interactive Docs{RESET}   : {CYAN}http://localhost:8000/docs{RESET}                     |
|  {BOLD}Health Check API{RESET}   : {CYAN}http://localhost:8000/api/v1/health{RESET}             |
|  {BOLD}Backend Logs{RESET}       : {DIM}logs/backend.log{RESET}                               |
|  {BOLD}Frontend Logs{RESET}      : {DIM}logs/frontend.log{RESET}                              |
{GREEN}{BOLD}+--------------------------------------------------------------------+
|  * Terminal output is kept clean. Logs saved to logs/ directory.   |
|  * Use --verbose flag if you want to stream all HTTP requests.     |
|  * Press [Ctrl + C] anytime to cleanly terminate all services.     |
+--------------------------------------------------------------------+{RESET}
"""
    print(summary, flush=True)

    if not args.no_browser and not args.backend_only:
        threading.Thread(target=open_browser, args=("http://localhost:3000",), daemon=True).start()

    # Keep supervisor alive while child processes run
    try:
        while True:
            for p in processes:
                code = p.poll()
                if code is not None:
                    log_warn(f"A service process exited unexpectedly with code {code}.")
                    shutdown_all()
            time.sleep(0.5)
    except KeyboardInterrupt:
        shutdown_all()

if __name__ == "__main__":
    main()

