# MailShield AI — Enterprise AI Cybersecurity Platform

**MailShield AI** is an AI-powered cybersecurity platform that securely connects to a user's Gmail account via Google OAuth 2.0 and analyzes incoming emails for Phishing, Scams, Suspicious URLs, Misinformation, Social Engineering, and Screenshot threats.

---

## 🌟 Key Features

- **Google OAuth 2.0 & JWT Security**: Secure OAuth 2.0 authentication flow with JWT access/refresh token rotation.
- **Gmail API Synchronization**: Automatic email header, MIME body, attachment, and URL parsing via `gmail.readonly`.
- **HuggingFace Zero-Shot Threat Classification**: AI text classification powered by HuggingFace Transformer models (`facebook/bart-large-mnli`).
- **6-Vector URL Threat Scanner**:
  1. 🔒 **HTTPS Security Check**
  2. 🎯 **Typosquatting & Brand Spoofing**
  3. ✂️ **Shortened URLs** (`bit.ly`, `tinyurl.com`, etc.)
  4. 📏 **Domain Length Analysis** (>35 chars)
  5. ⚠️ **Special Characters & Obfuscation** (`@` tricks, excessive hyphens)
  6. 🌐 **IP Address Hostnames** (`192.168.1.1`)
- **AI Misinformation & Fake News Detector**: Truth Credibility Score (0-100%) and **inline suspicious sentence highlighting**.
- **OCR Screenshot Threat Scanner**: Drag-and-drop screenshot uploads (.png, .jpg, .webp) with text extraction and threat analysis.
- **Executive Cybersecurity Dashboard**: Inbox Security Health Gauge, Threat Spectrum Charts, Weekly Trend Analytics, and Actionable Recommendations.

---

## 🛠️ Technology Stack

- **Frontend**: React 18, TypeScript, Vite, TailwindCSS, Lucide Icons, Axios.
- **Backend**: Python 3.11+, FastAPI, SQLAlchemy ORM, SQLite (embedded), Alembic, SlowAPI Rate Limiting, Pillow (PIL), EasyOCR.
- **Authentication**: Google OAuth 2.0, PyJWT.

---

## 🚀 Quick Start (One-Command Clean Startup)

No manual database setup or separate terminals required. Everything (virtualenv, dependency checks, port validation, database initialization, and process management) runs cleanly in a single command.

### 1. Prerequisites
- **Python 3.10+** (with SQLite built-in)
- **Node.js 18+** & **npm**

### 2. Launch MailShield AI

Choose any method based on your preferred workflow:

#### Option A: Unified Python Launcher (Cross-Platform)
```bash
python start.py
```

#### Option B: Windows PowerShell
```powershell
.\start.ps1
```

#### Option C: Windows Batch File (Double-Clickable)
Double-click `start.bat` or run:
```cmd
start.bat
```

#### Option D: NPM
```bash
npm start
# or
npm run dev
```

#### Option E: macOS / Linux / WSL / Git Bash
```bash
chmod +x start.sh
./start.sh
```

---

### ⚙️ Startup Options & Flags

| Flag | Description |
| :--- | :--- |
| `--no-browser` | Prevent automatic opening of the web browser |
| `--backend-only` | Run only the FastAPI backend service |
| `--frontend-only` | Run only the Vite React frontend service |
| `--kill-stale` | Automatically terminate any lingering processes holding port `8000` or `3000` |
| `--install` | Force reinstall/update backend and frontend dependencies |

---

### 🌐 Access Endpoints

Once started, the following services are live:
- **Frontend Cybersecurity Dashboard**: `http://localhost:3000`
- **Backend API Root**: `http://localhost:8000/api/v1`
- **Interactive OpenAPI/Swagger Docs**: `http://localhost:8000/docs`
- **Application Health Diagnostics**: `http://localhost:8000/api/v1/health`

Press `Ctrl + C` in the terminal anytime to cleanly and gracefully shut down both services without orphaned background processes.

---

## 🔒 Verification

1. **Automatic SQLite Initialization**: Upon backend launch, FastAPI's lifespan context calls `init_db()`, generating `backend/mailshield.db` automatically if it does not exist.
2. **Verify Database File**:
   - Check that `backend/mailshield.db` file exists.
   - Run `sqlite3 backend/mailshield.db ".tables"` to view `users`, `oauth_tokens`, `email_messages`, and `analysis_results` tables.
