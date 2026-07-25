# Specula

A locally-trained security platform combining **network intrusion detection** and **source-code vulnerability detection** under one confidence-based triage system.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    React Dashboard                          │
│  ┌──────────────────┐  ┌──────────────────────────────────┐ │
│  │  Threat Feed     │  │  Code Scanner                    │ │
│  │  (WebSocket)     │  │  (Paste → Type/Severity/Fix)     │ │
│  └──────────────────┘  └──────────────────────────────────┘ │
└──────────────────────────┬──────────────────────────────────┘
                           │ WebSocket + HTTP
┌──────────────────────────▼──────────────────────────────────┐
│              Node.js/Express Gateway                        │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────────────┐   │
│  │  Router     │  │  WS Server  │  │  Triage Engine    │   │
│  └─────────────┘  └─────────────┘  └───────────────────┘   │
└───────┬──────────────────────┬──────────────────────────────┘
        │ HTTP                 │ HTTP
┌───────▼──────────┐  ┌───────▼──────────────────────────────┐
│  Network Service │  │  Code Service                        │
│  (Flask)         │  │  (Flask)                             │
│  ┌─────────────┐ │  │  ┌─────────────┐  ┌──────────────┐  │
│  │ XGBoost     │ │  │  │ CodeBERT    │  │ CodeT5       │  │
│  │ Isolation   │ │  │  │ Classifier  │  │ Fix Gen      │  │
│  │ Forest      │ │  │  └─────────────┘  └──────────────┘  │
│  └─────────────┘ │  │  ┌─────────────┐                    │
└───────┬──────────┘  │  │ CWE KB      │                    │
        │             │  └─────────────┘                    │
        └──────┬──────┴──────────────┬──────────────────────┘
               │                     │
        ┌──────▼─────────────────────▼──────────────────────┐
        │              MongoDB                              │
        │  events collection (network | code)               │
        └──────────────────────────────────────────────────┘
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
cd ../../frontend/dashboard && npm install

# 3. Start all services
./scripts/start-all.sh
```

## Modules

### Module 1 — Network Anomaly Detection
- **Model A (Supervised):** XGBoost classifier on NSL-KDD
- **Model B (Unsupervised):** Isolation Forest for novel attack patterns
- **Output:** Predicted class + anomaly score + confidence

### Module 2 — Code Vulnerability Detection
- **Classifier:** Fine-tuned CodeBERT (6 CWE classes + "not vulnerable")
- **Fix Generator:** Fine-tuned CodeT5 (seq2seq)
- **Explanation:** Local JSON knowledge base (MITRE CWE + OWASP)

## Triage Engine

| Confidence | Action |
|------------|--------|
| ≥ 0.90 | Auto-flag (high priority) |
| 0.50 – 0.90 | Human review |
| < 0.50 | Ignore |

## API Endpoints

### Gateway (port 3000)
- `POST /api/network/analyze` — Analyze network flow
- `POST /api/code/scan` — Scan code snippet
- `GET /api/events` — Get all events
- `GET /api/events/:id` — Get event by ID
- `WS /ws` — Real-time event stream

### Network Service (port 5001)
- `POST /predict` — Predict network traffic class
- `GET /health` — Health check

### Code Service (port 5002)
- `POST /scan` — Scan code for vulnerabilities
- `POST /fix` — Generate suggested fix
- `GET /health` — Health check

## Project Structure

```
Specula/
├── backend/
│   ├── gateway/              # Node.js/Express API gateway
│   ├── services/
│   │   ├── network/          # Flask - Network anomaly detection
│   │   └── code/             # Flask - Code vulnerability detection
│   └── shared/
│       ├── schema/           # MongoDB schemas
│       └── triage/           # Confidence-based triage engine
├── frontend/
│   └── dashboard/            # React frontend
├── scripts/                  # Startup/utility scripts
├── docs/                     # Evaluation documentation
└── data/                     # Datasets and model weights
```

## Evaluation Metrics

### Network Module
- Per-class precision/recall/F1
- False positive rate on normal traffic (headline metric)
- Supervised vs. unsupervised recall on novel attacks

### Code Module
- Macro-F1 across 6 classes
- Top-2 CWE accuracy
- BLEU + exact-match rate for fix generation

## License

MIT
