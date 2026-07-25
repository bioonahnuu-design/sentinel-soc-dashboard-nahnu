# Sentinel SOC Dashboard
A portfolio-ready mini SIEM that ingests authentication logs, detects suspicious behavior, stores alerts, and gives analysts a live dashboard for triage.
## Features
- REST log ingestion with FastAPI
- PostgreSQL event and alert storage
- Brute-force detection: 5 failed logins from one IP within 10 minutes
- Suspicious-location login rule
- Live overview metrics, 24-hour timeline, and top attacking IPs
- Alert filtering and acknowledgement workflow
- Interactive API documentation at `/docs`
- Docker-based local setup and demo data generator
## Architecture

mermaid
flowchart LR
    A[Authentication logs] --> B[FastAPI ingest API]
    B --> C[(PostgreSQL)]
    B --> D[Detection engine]
    D --> E[Alerts]
    C --> F[SOC Dashboard]
    E --> F


## Run locally

Requirements: Docker Desktop and Docker Compose.

bash
docker compose up --build -d


Open <http://localhost:8000>, then add realistic demo traffic:

bash
docker compose exec web python scripts/generate_demo_logs.py

Stop the project with `docker compose down`. Add `-v` only if you also want to delete the PostgreSQL volume.

## API examples

Send a security event:

bash
curl -X POST http://localhost:8000/api/logs \
  -H "Content-Type: application/json" \
  -d '{"timestamp":"2026-07-17T10:00:00Z","source_ip":"203.0.113.10","username":"admin","event_type":"login","status":"failed","country":"Indonesia"}'


Useful endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/logs` | Ingest one event and run detection rules |
| GET | `/api/logs` | Fetch recent raw events |
| GET | `/api/alerts` | List/filter detections |
| PATCH | `/api/alerts/{id}/acknowledge` | Mark an alert reviewed |
| GET | `/api/stats/overview` | Dashboard KPI data |
| GET | `/api/stats/timeline` | 24-hour event series |
| GET | `/api/stats/top-ips` | Top failed-login sources |

## Test

bash
python -m pytest


## Next security upgrades

- JWT login and analyst/admin roles
- GeoIP enrichment and IP reputation lookup
- WebSocket real-time alert delivery
- Sigma-compatible detection rules
- CSV/JSON bulk upload and webhook collectors
- Alembic database migrations

