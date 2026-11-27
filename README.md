# Sentinel AI — Autonomous Cybersecurity Monitoring & Threat Detection Platform

**Sentinel AI** is an AI-powered mini Security Operations Center (SOC) designed to monitor network & system activity, detect suspicious behavior through rule-based and AI correlation, investigate cyber threats, manage incidents, and generate executive security reports.

---

## 🛠️ Architecture & Technology Stack

* **Frontend**: React 18, Vite, Tailwind CSS, Recharts, Lucide Icons
* **Backend**: Python 3.13, FastAPI, SQLAlchemy 2.0, Pydantic V2
* **Database**: PostgreSQL (Supabase compatible) / SQLite local fallback
* **Detection Engine**: Correlated rule-based analysis (Brute Force, Password Spraying, Port Scan, Privilege Escalation, C2 Beacons)
* **API Foundation & Observability**:
  * Unified structured error handling (`code`, `message`, `details`, `request_id`, `timestamp`)
  * `SecurityTelemetryMiddleware`: Injects `X-Request-ID` and high-precision `X-Process-Time` (latency in ms)
  * Deep Health Check: Live DB ping latency, telemetry counts, and detection rules registry
* **AI Analysis**: Gemini API (structured incident reasoning & defensive recommendations)
* **Reports**: Automated PDF generator (ReportLab)

---

## 🚀 Quick Start Guide

### 1. Backend Setup (FastAPI)
```bash
# Navigate to backend directory
cd backend

# Create & activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
uvicorn backend.app.main:app --reload --port 8000
```
* Interactive API Documentation (Swagger): `http://localhost:8000/docs`
* ReDoc Documentation: `http://localhost:8000/redoc`
* Basic Health Check: `http://localhost:8000/health`
* Deep SOC Diagnostics: `http://localhost:8000/api/v1/health/detailed`

### 2. Frontend Setup (React + Vite)
```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start Vite development server
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## 📊 Modules & Roadmap

- [x] **Backend Foundation & Telemetry Core**
  - Modular FastAPI architecture with structured routing
  - Global standardized error responses (`HTTPException`, `RequestValidationError`, `SentinelException`)
  - Request correlation ID (`X-Request-ID`) & latency timing (`X-Process-Time`)
  - Deep diagnostics endpoint checking live DB ping and detection rule status
- [x] **Module 1: Security Dashboard**
  - Real-time SOC event telemetry & metrics
  - Severity breakdown (Critical, High, Medium, Low)
  - Recharts event timeline & failed login trend tracking
  - Active alert queue with rule correlation
  - Searchable live security event stream
- [x] **Module 2: Log Analyzer & Threat Detection Engine**
  - Multi-format ingestion: CSV, JSON array, NDJSON, and raw text paste
  - Automated schema normalization across timestamps, IPs, users, and actions
  - Rule-based correlation engine:
    - `RULE_AUTH_BRUTE_FORCE`: Repeated failed logins from single IP
    - `RULE_AUTH_PASSWORD_SPRAYING`: Single IP spraying multiple user accounts
    - `RULE_HOST_SUDO_VIOLATION`: Unauthorized privilege escalation attempts
    - `RULE_PERIMETER_PORT_SCAN`: Multi-port TCP SYN sweep detection
    - `RULE_NETWORK_C2_BEACON`: Suspicious DNS tunneling & outbound beaconing
  - Automated Alert generation with structured evidence
  - Interactive Log Explorer with pagination, type/verdict filters, and JSON inspection
- [ ] **Module 3: Threat Intelligence** (IP/Domain reputation scoring & indicator correlation)
- [ ] **Module 4: AI Security Analyst** (Gemini API incident explanation & triage suggestions)
- [ ] **Module 5: Incident Management** (Severity escalation, containment tracking, case history)
- [ ] **Module 6: Security Reports** (Executive downloadable PDF reporting)

---

## 🛡️ Security & Integrity
* Strict credential protection: `.env` and tokens are ignored by default.
* Pre-commit validation and test automation with `pytest`.
