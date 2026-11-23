# 🛡️ PhishGuard AI

> **Autonomous Multi-Vector Phishing Threat Intelligence & Phishing DNA Detection Platform**  
> Built for Hackathon by **Team ENDFRAME**

---

## 🌟 Executive Summary

**PhishGuard AI** is a real-time cybersecurity platform designed to combat sophisticated modern phishing campaigns, brand impersonation, and social engineering attacks across emails, SMS, and URLs. 

Rather than relying purely on static domain blacklists—which fail against novel zero-day campaigns—PhishGuard AI generates a comprehensive **Phishing DNA Report** across four threat dimensions:
1. **🧬 Lexical DNA**: Subdomain depth, Shannon entropy, raw IP hosts, URL shortener cloaking, and high-abuse TLDs.
2. **🎭 Identity DNA**: Punycode/IDN homoglyphs, typosquatting, and deceptive brand impersonation targeting major organizations (PayPal, Microsoft, Apple, Google, Banks, etc.).
3. **🧠 Behavior DNA**: NLP heuristics identifying artificial urgency, authority coercion, fear appeals, financial lures, and direct credential solicitation.
4. **🛡️ External Threat Intelligence**: VirusTotal API v3 integration with resilient graceful degradation when unconfigured or rate-limited.

---

## 🏗️ Repository Architecture

```text
phishguard ai/
├── .gitignore
├── README.md
├── scripts/
│   └── setup.ps1                 # Automated Windows environment replication script
├── backend/
│   ├── .env.example              # Template environment configuration
│   ├── requirements.txt          # Python 3.11+ dependencies
│   ├── app/
│   │   ├── main.py               # FastAPI application entrypoint & lifespan
│   │   ├── api/routes/
│   │   │   └── analysis.py       # REST endpoints (/api/health, /api/analyze/*, /api/history)
│   │   ├── core/
│   │   │   ├── config.py         # Pydantic/dotenv settings manager
│   │   │   └── database.py       # SQLAlchemy engine, session factory & schema auto-creation
│   │   ├── models/
│   │   │   └── analysis.py       # AnalysisRecord ORM model (Privacy guaranteed)
│   │   ├── schemas/
│   │   │   └── analysis.py       # Pydantic request/response schemas
│   │   └── services/
│   │       ├── threat_intelligence.py # VirusTotal API v3 async adapter
│   │       ├── url_analyzer.py   # Lexical & structural URL heuristics
│   │       ├── message_analyzer.py # Behavioral & social engineering text analysis
│   │       ├── risk_engine.py    # Multi-factor risk scoring (0-100) & recommendations
│   │       └── phishing_dna.py   # Pipeline orchestrator & persistence coordinator
│   └── tests/                    # Pytest test suite (16 tests covering all endpoints & fallbacks)
└── frontend/
    ├── package.json
    ├── vite.config.js            # React 19 + Vite 8 + Tailwind CSS v4 setup
    └── src/
        ├── index.css             # Tailwind v4 configuration
        ├── App.jsx               # App wrapper
        ├── components/
        │   └── Navbar.jsx        # Navigation bar
        ├── pages/
        │   └── Dashboard.jsx     # Dual-mode scanner & Phishing DNA visualizer
        └── services/
            └── api.js            # Client-side API integration layer
```

---

## 🔒 Security & Privacy Guarantees (FR-04)

- **Zero-Storage of Sensitive Content**: The persistence layer (`analysis_records` table) strictly stores analysis metadata, risk scores, indicators, recommendations, and sanitized summaries. **Raw message content, passwords, tokens, or personal identifiers are NEVER stored in the database.**
- **Excluded Secrets**: `.gitignore` strictly excludes all `.env` files, virtual environments (`.venv/`), and database files.

---

## 🚀 Quick Start for Teammates (Windows)

### Option 1: Automated Setup (Recommended)

Run the included automated setup script in PowerShell:

```powershell
.\scripts\setup.ps1
```

This script will automatically:
1. Verify global prerequisites (Git, Python 3.11+, Node.js LTS, npm, MySQL 8.x).
2. Reset any misconfigured `COMSPEC` environment variables.
3. Create `backend/.env` from `backend/.env.example`.
4. Create the Python virtual environment (`backend/.venv`) and install dependencies.
5. Install and build frontend npm packages.
6. Run the `pytest` test suite to verify system integrity.

---

### Option 2: Manual Setup

#### 1. Backend Setup (FastAPI + Python 3.11+)

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Run unit tests
pytest

# Launch FastAPI development server
uvicorn app.main:app --reload --port 8000
```

- **Interactive API Documentation (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check**: [http://localhost:8000/api/health](http://localhost:8000/api/health)

#### 2. Frontend Setup (React + Vite + Tailwind CSS)

```powershell
cd frontend
npm install
npm run dev
```

- **Web Application**: [http://localhost:5173](http://localhost:5173)

---

## 📡 REST API Contract

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health, MySQL connectivity, and VirusTotal status |
| `POST` | `/api/analyze/url` | URL threat analysis, Phishing DNA extraction & VirusTotal lookup |
| `POST` | `/api/analyze/message` | Email / SMS social engineering & embedded link analysis |
| `GET` | `/api/history` | Paginated history of previous scans (sanitized metadata) |

---

## 🛡️ VirusTotal API v3 Integration Notes

- If `VIRUSTOTAL_API_KEY` is not provided or set to `your_vt_api_key_here`, PhishGuard AI automatically operates in **graceful stateless mode**, relying on its local heuristic engines and documenting the limitation in the report.
- Zero detections on VirusTotal are explicitly noted as non-definitive, ensuring users remain vigilant against novel zero-day phishing attacks.

---

## 👥 Team ENDFRAME
Built with passion for the Hackathon.
