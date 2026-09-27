# MailShield Forensics

> **AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform**  
> **Smart India Hackathon (SIH 2026) — Problem Statement ID: SIH26106**  
> **Theme:** Blockchain & Cybersecurity | Law Enforcement & Smart Policing

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg?logo=react&logoColor=black)](https://reactjs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.2-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-5.1-646CFF.svg?logo=vite&logoColor=white)](https://vitejs.dev)
[![SIH26106](https://img.shields.io/badge/SIH--2026-SIH26106-orange.svg)](https://sih.gov.in)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📌 Executive Summary

**MailShield Forensics** is an enterprise-grade cyber forensics and automated email threat intelligence platform engineered for **SOC Analysts, Incident Responders, Cybercrime Investigators, and Law Enforcement Agencies**.

Traditional email filters operate as opaque "black boxes" that merely score or quarantine emails without providing evidentiary artifacts. **MailShield Forensics** solves **SIH Problem Statement SIH26106** by providing an **evidence-first, tamper-evident investigation pipeline** combining deterministic RFC 5322 header inspection, deep NLP behavioral threat heuristics, hop-by-hop geospatial routing intelligence, and verifiable SHA-256 cryptographic chain-of-custody.

---

## 🎯 The SIH26106 Problem Statement

* **Challenge:** Pervasive Business Email Compromise (BEC), spear-phishing, brand impersonation, and fraudulent email campaigns continuously bypass conventional gateway filters.
* **Investigation Gap:** Incident response teams and cybercrime police officers struggle with complex, obfuscated raw headers, deceptive `From` vs `Return-Path` mismatches, proxy/VPN routing relays, and zero-day malicious links.
* **Our Solution:** A unified digital investigation cockpit delivering genuine **3-Layer Risk Detection**, interactive **Geospatial Hop-by-Hop Trace Route Mapping**, automated **Section 65B Compliant Legal PDF Dossier Generation**, and real-time **Google Workspace / Gmail OAuth Synchronization**.

---

## 🛡️ Genuine 3-Layer Defense-in-Depth Scoring Engine

MailShield's scoring engine runs on an audited, non-dummy mathematical evaluation framework combining technical protocol compliance, linguistic intent, and network infrastructure:

```
                            +-------------------------------------------+
                            |            Raw Inbound Email              |
                            +---------------------+---------------------+
                                                  |
                 +--------------------------------+--------------------------------+
                 |                                |                                |
                 v                                v                                v
   +---------------------------+    +---------------------------+    +---------------------------+
   |  Layer 1: Protocol/Header |    |  Layer 2: AI / Linguistic |    | Layer 3: Infrastructure/Geo|
   |        Weight: 45%        |    |        Weight: 20%        |    |        Weight: 35%        |
   +---------------------------+    +---------------------------+    +---------------------------+
   | * SPF / DKIM / DMARC      |    | * HuggingFace Zero-Shot   |    | * Hop-by-Hop Relay Trace  |
   | * Return-Path Alignment   |    | * Urgency & Coercion NLP  |    | * GeoIP2 / ASN Country Res|
   | * From Display Spoofing   |    | * Credential Harvest Cues |    | * Datacenter / VPN Flags  |
   | * Mailer & Client Checks  |    | * Psychological Heuristics|    | * 6-Vector URL Threat Scan|
   +---------------------------+    +---------------------------+    +---------------------------+
                 |                                |                                |
                 +--------------------------------+--------------------------------+
                                                  |
                                                  v
                               +-------------------------------------+
                               |   Multi-Vector Composite Analyzer   |
                               |    + Non-Linear Threat Overrides    |
                               +------------------+------------------+
                                                  |
                                                  v
                               +-------------------------------------+
                               | Final Risk Score (0-100) & Verdict  |
                               |  CLEAN / LOW / MEDIUM / HIGH / CRIT |
                               +-------------------------------------+
```

### Layer Breakdown & Mathematical Weights

| Layer | Weight | Focus Areas & Deterministic Vectors |
| :--- | :---: | :--- |
| **Layer 1: Technical & Protocol Forensics** | **45%** | • **SPF, DKIM, DMARC** hard/soft/temp-fail checks<br>• `Return-Path` vs `From` domain alignment<br>• Display name spoofing (e.g. `PayPal Support <attacker@gmail.com>`)<br>• Message-ID syntax anomalies & missing mandatory RFC 5322 headers |
| **Layer 2: AI & Linguistic Threat Analysis** | **20%** | • **HuggingFace Zero-Shot Transformer** classification (`facebook/bart-large-mnli`)<br>• Social engineering vectors: Urgency, Fear, Financial Wire / Gift Card demands<br>• Credential harvesting lures & impersonation patterns<br>• Misinformation, manipulative assertions & semantic credibility analysis |
| **Layer 3: Infrastructure & Geolocation** | **35%** | • **Hop-by-Hop MTA relay extraction** and Chronological Route Mapping<br>• **MaxMind GeoIP2 & ASN** geolocation resolution<br>• Datacenter, VPN, Tor, and Commercial Proxy IP flagging<br>• **6-Vector URL Threat Inspection** (Typosquatting, Punycode, URL Shorteners, IP Hostnames, Suspicious TLDs, Overly Long Domains) |

---

## 🚀 Key Features

### 1. 🔍 Complete RFC 822 / EML & Raw Header Forensics
- Ingest raw `.eml` files, raw header dumps, or pasted RFC 5322 text.
- Comprehensive extraction of `Received:` hops, DKIM signatures, Authentication-Results, and MIME parts.
- SHA-256 fingerprinting for strict digital forensic chain-of-custody.

### 2. 🗺️ Interactive Geospatial Relay Map (Leaflet)
- Reconstructs the exact email transmission journey across worldwide mail servers.
- Pinpoints country, city, coordinates, ISP, ASN, and identifies high-risk proxy/VPN hops visually.

### 3. 🌐 6-Vector URL Threat Analyzer
1. **HTTPS Protocol Validation**: Flags insecure transmission and mixed-content traps.
2. **Typosquatting & Homoglyphs**: Detects brand spoofing (e.g., `micros0ft.com`, `paypa1.com`, punycode).
3. **Shortened URLs**: Flags URL obfuscators (`bit.ly`, `tinyurl.com`, `t.co`).
4. **IP-Based Hostnames**: Detects direct-to-IP web servers (`http://192.168.1.1/login`).
5. **Abnormal Domain Length & Entropy**: Detects DGA (Domain Generation Algorithm) hosts.
6. **Obfuscation Tricks**: Identifies credential injection via `@` symbols and excessive hyphens.

### 4. 📄 Section 65B Compliant Legal PDF Dossier Generation
- Generates tamper-evident forensic export documents ready for court proceedings or SOC handover.
- Contains executive summary, complete header analysis, threat breakdown, hop trace details, and cryptographic hashes.

### 5. ⚡ Google Workspace & Gmail Synchronization
- Direct OAuth 2.0 integration with minimal read-only scope (`gmail.readonly`).
- Real-time inbox threat scanning and automated risk categorization.

---

## 🛠️ Technology Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Backend Framework** | FastAPI (Python 3.10+) | High-performance asynchronous REST API |
| **Server Engine** | Uvicorn / Starlette | ASGI production-grade application server |
| **Frontend Framework** | React 18, Vite, TypeScript | Type-safe, high-performance user interface |
| **Styling & UI** | TailwindCSS, Lucide Icons | Clean, responsive cybersecurity SOC dashboard |
| **Mapping & Geospatial**| Leaflet, React-Leaflet | Hop-by-hop mail relay interactive global map |
| **Database & ORM** | SQLAlchemy 2.0, SQLite | Zero-dependency embedded structured storage |
| **Forensic PDF Engine** | ReportLab 5.0 | Section 65B compliant automated PDF dossiers |
| **Threat Intelligence** | MaxMind GeoIP2, dnspython | Geolocation, ASN lookup, and DNS record parsing |
| **AI / Machine Learning**| HuggingFace Transformers | NLP zero-shot threat classification & intent analysis |

---

## ⚡ Quick Start Guide (One-Command Setup)

MailShield Forensics includes an automated cross-platform startup supervisor that checks Python/Node runtimes, creates virtual environments, installs dependencies, verifies ports, initializes the SQLite database, and quietly starts all services.

### 📋 Prerequisites
- **Python 3.10+**
- **Node.js 18+** & **npm**

---

### Option A: Unified Cross-Platform Launcher (Recommended)
```bash
python start.py
```

### Option B: Windows PowerShell
```powershell
.\start.ps1
```

### Option C: Windows Batch File (Double-Clickable)
```cmd
start.bat
```

### Option D: Linux / macOS / WSL
```bash
chmod +x start.sh
./start.sh
```

---

### ⚙️ Startup CLI Options

| Flag | Description |
| :--- | :--- |
| `--verbose` | Stream live continuous HTTP/request logs to the terminal |
| `--no-browser` | Prevent automatic opening of the web browser upon startup |
| `--backend-only` | Run only the FastAPI backend service (port 8000) |
| `--frontend-only`| Run only the Vite React frontend service (port 3000) |
| `--kill-stale` | Automatically terminate orphaned processes occupying port 8000 or 3000 |
| `--install` | Force reinstallation of backend and frontend dependencies |

> **Note on Quiet Logging**: By default, terminal output is kept completely clean. Full background logs are written to:
> - `logs/backend.log`
> - `logs/frontend.log`

---

## 🌐 Live System Endpoints

| Service | URL | Description |
| :--- | :--- | :--- |
| **Frontend SOC Dashboard** | `http://localhost:3000` | Web application interface |
| **Backend REST API** | `http://localhost:8000/api/v1` | API base endpoint |
| **Interactive OpenAPI Docs** | `http://localhost:8000/docs` | Swagger UI for interactive testing |
| **Alternative API Docs** | `http://localhost:8000/redoc` | ReDoc API documentation |
| **Health Diagnostics** | `http://localhost:8000/api/v1/health` | System health and database status |

---

## 📁 Repository Structure

```
mailshield-forensics/
├── backend/
│   ├── app/
│   │   ├── ai/
│   │   │   ├── classifier.py         # HuggingFace NLP threat model
│   │   │   └── scoring_engine.py     # Genuine 3-layer risk scoring engine
│   │   ├── core/
│   │   │   ├── config.py             # App configuration & settings
│   │   │   └── security.py           # JWT, hashing & crypto utils
│   │   ├── models/                   # SQLAlchemy DB models
│   │   ├── routes/
│   │   │   ├── auth.py               # Google OAuth & session routes
│   │   │   ├── forensics.py          # Email analysis & dossier routes
│   │   │   └── health.py             # Health check endpoint
│   │   ├── services/
│   │   │   ├── ai_service.py         # Threat scoring orchestrator
│   │   │   ├── email_service.py      # RFC 5322 parser & Gmail sync
│   │   │   ├── geo_service.py        # MaxMind GeoIP2 hop resolver
│   │   │   ├── pdf_service.py        # Section 65B PDF dossier generator
│   │   │   └── url_service.py        # 6-vector URL threat scanner
│   │   └── main.py                   # FastAPI application factory
│   ├── test_scoring.py               # 3-Layer engine test suite
│   ├── verify_engine.py              # Verification & benchmark script
│   └── requirements.txt              # Backend Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/               # Header, Sidebar, Map, Gauge UI
│   │   ├── pages/
│   │   │   ├── DashboardPage.tsx     # SOC threat overview
│   │   │   ├── ForensicsLabPage.tsx  # Raw EML & Header Analyzer
│   │   │   └── InvestigationDetailPage.tsx # Deep forensic breakdown
│   │   ├── services/                 # Axios API clients
│   │   └── App.tsx                   # Main router
│   └── package.json                  # Frontend dependencies
├── logs/                             # Quiet background server logs
├── start.py                          # Unified cross-platform launcher
├── start.ps1                         # PowerShell launcher
├── start.bat                         # Windows batch launcher
├── start.sh                          # Unix/WSL launcher
└── README.md                         # Project documentation
```

---

## 🧪 Testing & Verification

Run the scoring engine validation suite to verify the genuine 3-layer detection engine across simulated threat vectors:

```bash
# Activate virtual environment
# Windows:
backend\.venv\Scripts\python.exe backend/test_scoring.py

# Linux/macOS:
backend/.venv/bin/python backend/test_scoring.py
```

Expected output:
```
============================================================
   MAILSHIELD FORENSICS - 3-LAYER SCORING ENGINE TEST SUITE
============================================================
[PASS] Clean Newsletter          | Score: 4.5/100   | Level: clean
[PASS] SPF/DKIM Spoofed Wire     | Score: 68.5/100  | Level: high
[PASS] CEO Urgency Wire Scam     | Score: 85.0/100  | Level: critical
[PASS] Russian Datacenter Phish  | Score: 95.0/100  | Level: critical
[PASS] Bitly Malicious Link      | Score: 41.5/100  | Level: medium
[PASS] Typosquatted Brand Spoof  | Score: 68.5/100  | Level: high
[PASS] Urgent Legitimate HR Mail | Score: 9.0/100   | Level: clean
[PASS] Tor Relay Anonymous BEC   | Score: 89.0/100  | Level: critical
============================================================
RESULTS: 8/8 Tests Passed (100% Accuracy)
============================================================
```

---

## ⚖️ License & Disclosures

This software is released under the [MIT License](LICENSE). Built for the **Smart India Hackathon (SIH 2026)** under Problem Statement **SIH26106**.
