# Specula — HORUS Security Scanner

A locally-trained security platform combining **network intrusion detection**, **source-code vulnerability detection**, and **dynamic application security testing** under one confidence-based triage system.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    React Dashboard (3001)                        │
│  ┌──────────────┐  ┌──────────────────┐  ┌───────────────────┐  │
│  │ Threat Feed  │  │  Unified Scanner │  │  Live Stats       │  │
│  │ (WebSocket)  │  │  (SAST/DAST/Repo)│  │  (Events/Severity)│  │
│  └──────────────┘  └──────────────────┘  └───────────────────┘  │
└──────────────────────────────┬──────────────────────────────────┘
                               │ WebSocket + HTTP
┌──────────────────────────────▼──────────────────────────────────┐
│              Node.js/Express Gateway (3000)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────────────────┐  │
│  │  Router      │  │  WS Server  │  │  Triage Engine         │  │
│  └─────────────┘  └─────────────┘  └────────────────────────┘  │
└───────┬────────────────────┬──────────────────┬────────────────┘
        │ HTTP               │ HTTP             │ HTTP
┌───────▼─────────┐ ┌───────▼──────────┐ ┌─────▼───────────────┐
│ Network Service │ │  Code Service    │ │  DAST Service       │
│ (Flask) (5001)  │ │  (Flask) (5002)  │ │  (Flask) (5003)     │
│ ┌─────────────┐ │ │  ┌─────────────┐ │ │  ┌────────────────┐ │
│ │ XGBoost     │ │ │  │ CodeBERT    │ │ │  │ Passive Checks │ │
│ │ Isolation   │ │ │  │ Classifier  │ │ │  │ (8 checks)     │ │
│ │ Forest      │ │ │  ├─────────────┤ │ │  ├────────────────┤ │
│ └─────────────┘ │ │  │ CodeT5      │ │ │  │ Active Probes  │ │
│                 │ │  │ Fix Gen     │ │ │  │ (SQLi/XSS/IDOR)│ │
│                 │ │  ├─────────────┤ │ │  └────────────────┘ │
│                 │ │  │ CWE KB      │ │ │                     │
│                 │ │  └─────────────┘ │ │                     │
│                 │ │  ┌─────────────┐ │ │                     │
│                 │ │  │ Repo Scanner│ │ │                     │
│                 │ │  └─────────────┘ │ │                     │
└───────┬─────────┘ └───────┬──────────┘ └─────┬───────────────┘
        │                   │                   │
        └──────────┬────────┴───────────────────┘
            ┌──────▼──────────────────────────────────────────────┐
            │              MongoDB (27017)                        │
            │  events (network | code | dast | scan_repo)        │
            └────────────────────────────────────────────────────┘
```

## Hard Constraint

**No external inference APIs** in the runtime path. Every model is trained/fine-tuned on local hardware. Pretrained weight downloads at setup are fine; runtime API calls to hosted models are not.

## Quick Start

```bash
# 1. Start MongoDB
mongod --dbpath ./data/db

# 2. Install dependencies
cd backend/gateway && npm install
cd ../services/network && pip install -r requirements.txt
cd ../services/code && pip install -r requirements.txt
cd ../services/dast && pip install -r requirements.txt
cd ../../frontend/dashboard && npm install

# 3. Start all services
./scripts/start-all.sh
```

## Modules

### Module 1 — Network Anomaly Detection (NIDS)
- **Model A (Supervised):** XGBoost classifier on NSL-KDD (23 attack classes)
- **Model B (Unsupervised):** Isolation Forest for novel attack patterns
- **Ensemble:** IF anomaly score overrides XGBoost when confidence is low
- **Output:** Predicted class + anomaly score + confidence + CWE explanation

### Module 2 — Code Vulnerability Detection (SAST)
- **Classifier:** Fine-tuned CodeBERT (6 CWE classes + "not vulnerable")
- **Fix Generator:** Fine-tuned CodeT5 (seq2seq)
- **Rule Engine:** Pattern-based classifier (87% accuracy, 0% FP on parameterized queries)
- **Repo Scanner:** Clone any GitHub repo, scan every source file, stream findings

### Module 3 — Dynamic Application Security Testing (DAST)
- **Passive Checks (8):** CSP, HSTS, X-Frame-Options, cookies, CORS, TLS, error disclosure, server banner
- **Active Probes (5):** SQL injection, XSS reflection, IDOR, auth bypass, endpoint discovery
- **Authorization Gate:** External targets auto-authorized on first scan; localhost always allowed

### Triage Engine
- **Confirmed findings** (passive DAST): No confidence % — severity drives triage directly
- **Inferred findings** (active probes, ML): Confidence % with strength labels

| Confidence | Action |
|------------|--------|
| ≥ 0.90 | Auto-flag (high priority) |
| 0.50 – 0.90 | Human review |
| < 0.50 | Ignore |

## API Endpoints

### Gateway (port 3000)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/network/analyze` | Analyze network flow |
| POST | `/api/code/scan` | Scan code snippet |
| POST | `/api/code/scan-repo` | Start repo scan |
| GET | `/api/code/scan-repo` | List repo scan jobs |
| GET | `/api/code/scan-repo/:jobId` | Poll repo scan status |
| POST | `/api/dast/scan` | Run DAST scan |
| GET | `/api/dast/authorized-targets` | List authorized targets |
| POST | `/api/dast/authorized-targets` | Add authorized target |
| DELETE | `/api/dast/authorized-targets/:target` | Remove target |
| GET | `/api/events` | Get all events |
| GET | `/api/events/stats/summary` | Event statistics |
| WS | `/ws` | Real-time event stream |

### Network Service (port 5001)
- `POST /predict` — Predict network traffic class
- `GET /health` — Health check

### Code Service (port 5002)
- `POST /scan` — Scan code for vulnerabilities
- `POST /fix` — Generate suggested fix
- `POST /repo-scan` — Start background repo scan
- `GET /repo-scan` — List all repo scans
- `GET /repo-scan/:jobId` — Get scan status
- `GET /health` — Health check

### DAST Service (port 5003)
- `POST /scan` — Run passive + active DAST scan
- `GET /health` — Health check

## Project Structure

```
Specula/
├── frontend/
│   └── dashboard/            # React UI (3001)
│       ├── src/components/   # ThreatFeed, UnifiedScanner, StatsBar
│       ├── src/services/     # API client, WebSocket
│       └── build/            # Production build
├── backend/
│   ├── gateway/              # Node.js/Express API gateway (3000)
│   │   ├── routes/           # code, dast, network, events, repoScan
│   │   └── __tests__/        # 33 passing tests
│   ├── services/
│   │   ├── network/          # Flask — NIDS (5001)
│   │   │   └── models/       # XGBoost, Isolation Forest
│   │   ├── code/             # Flask — SAST (5002)
│   │   │   ├── models/       # CodeBERT, CodeT5, Rule Classifier
│   │   │   └── repo_scanner.py
│   │   └── dast/             # Flask — DAST (5003)
│   │       └── active_scanner.py
│   └── shared/               # middleware, schemas, triage engine
├── scripts/                  # Training, evaluation, ablation
├── docs/                     # Paper sections, evaluation reports
├── data/                     # NSL-KDD, CVE datasets
├── Dockerfile.*              # Per-service Docker builds
└── docker-compose.yml        # Full stack orchestration
```

## Model Training

```bash
# Train all models
python scripts/train_all.py

# Train individual models
python scripts/train_xgboost.py        # Network classifier
python scripts/train_isolation_forest.py # Anomaly detector
python scripts/train_codebert.py        # Code vulnerability classifier
python scripts/train_codet5.py          # Fix generator
```

## Evaluation

```bash
python scripts/evaluate_xgboost.py      # NIDS metrics
python scripts/evaluate_code_classifier.py # SAST metrics
python scripts/ablation_sast.py         # SAST ablation study
python scripts/ablation_nids.py         # NIDS ablation study
```

## Docker

```bash
docker-compose up --build
```

## License

MIT
