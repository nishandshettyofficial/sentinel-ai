# Sentinel AI — Autonomous Cybersecurity Monitoring & Threat Detection Platform

**Sentinel AI** is an AI-powered mini Security Operations Center (SOC) designed to monitor network & system activity, detect suspicious behavior through rule-based and AI correlation, investigate cyber threats, manage incidents, and generate executive security reports.

---

## 🛠️ Architecture & Technology Stack

* **Frontend**: React 18, Vite, Tailwind CSS, Recharts, Lucide Icons
* **Backend**: Python 3.13, FastAPI, SQLAlchemy 2.0, Pydantic V2
* **Database**: PostgreSQL (Supabase compatible) / SQLite local fallback
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
API Documentation is available at `http://localhost:8000/docs`.

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

- [x] **Module 1: Security Dashboard**
  - Real-time SOC event telemetry & metrics
  - Severity breakdown (Critical, High, Medium, Low)
  - Recharts event timeline & failed login trend tracking
  - Active alert queue with rule correlation
  - Searchable live security event stream
- [ ] **Module 2: Log Analyzer** (CSV/JSON upload, brute force detection, pattern parser)
- [ ] **Module 3: Threat Intelligence** (IP/Domain reputation scoring & indicator correlation)
- [ ] **Module 4: AI Security Analyst** (Gemini API incident explanation & triage suggestions)
- [ ] **Module 5: Incident Management** (Severity escalation, containment tracking, case history)
- [ ] **Module 6: Security Reports** (Executive downloadable PDF reporting)

---

## 🛡️ Security & Integrity
* Strict credential protection: `.env` and tokens are ignored by default.
* Pre-commit validation and test automation with `pytest`.
