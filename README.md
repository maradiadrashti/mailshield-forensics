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

## 🚀 Quick Start (Local Setup)

No database installation (like PostgreSQL) or Docker is required. SQLite is built into Python and initializes automatically.

### 1. Prerequisites
- Python 3.11+
- Node.js 18+
- SQLite (built into Python)

### 2. Environment Setup
Create `.env` file in the `backend/` directory (or copy `.env.example`):
```bash
cp backend/.env.example backend/.env
```

### 3. Backend Setup & Launch
```bash
cd backend
pip install -r requirements.txt

# Run Alembic migrations (optional, init_db automatically creates tables)
alembic upgrade head

# Start FastAPI dev server using any of the following commands:
python app/main.py
# OR
python -m app.main
# OR
uvicorn app.main:app --reload
```
FastAPI server starts at `http://localhost:8000`. OpenAPI docs available at `http://localhost:8000/docs`.

### 4. Frontend Setup & Launch
In a new terminal:
```bash
cd frontend
npm install
npm run dev
```
React application starts at `http://localhost:5173` (or `http://localhost:3000`).

---

## 🔒 Verification

1. **Automatic SQLite Initialization**: Upon backend launch, FastAPI's lifespan context calls `init_db()`, generating `backend/mailshield.db` automatically if it does not exist.
2. **Verify Database File**:
   - Check that `backend/mailshield.db` file exists.
   - Run `sqlite3 backend/mailshield.db ".tables"` to view `users`, `oauth_tokens`, `email_messages`, and `analysis_results` tables.
