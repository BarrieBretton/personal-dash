# Atmosphere — cloud-first air dashboard starter

A responsive Petite Vue dashboard with FastAPI and SQLite-backed historical PM2.5 readings. Includes explicit preview mode and a protected ingestion interface for future cloud or local bridges.

## Important integration status

**Xiaomi AC-M18-SC and Philips AC2221 are not yet connected.** This is a tested application scaffold, not a finished vendor OAuth integration. Neither manufacturer is assumed to offer an unrestricted third-party API. Xiaomi's Home Assistant integration code is licensed for noncommercial Home Assistant use and must not be copied into an unrelated dashboard. Philips Air+ cloud access is not guaranteed. The `/api/ingest` endpoint supports authorized external collectors once validated. Do not enter Xiaomi or Philips account passwords into this app.

## Local start

Python 3.11+:

```bash
cd backend
python -m venv .venv
# Activate the environment for your OS
pip install -r requirements.txt
export DASHBOARD_API_KEY='replace-with-long-random-secret'
export INGEST_API_KEY='replace-with-a-different-long-random-secret'
uvicorn main:app --reload --port 8000
```

In another terminal, from `frontend`:

```bash
python -m http.server 8080
```

Open http://localhost:8080. Use Settings to enter the backend URL and dashboard API key. These values are kept in memory and disappear on reload.

## Ingestion example

```bash
curl -X POST http://localhost:8000/api/ingest \
  -H 'Authorization: Bearer YOUR_INGEST_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"device":"xiaomi","pm25":24.5}'
```

The other device id is `philips`. Values are PM2.5 in µg/m³, not official AQI. The backend marks readings stale after 3 minutes.

## Deployment guidance

- Deploy the `frontend/` directory to Cloudflare Pages (static site; no build step).
- Deploy FastAPI to a Python host with a **persistent volume** for SQLite, or replace SQLite with a managed database. Ephemeral filesystems lose history on restart.
- Use HTTPS and Cloudflare Access for access control. A browser-held bearer key is suitable only for local testing; for production replace it with a server-side session / Access JWT validation and a same-origin API proxy. Never expose the ingest key to frontend JavaScript.
- Configure `CORS_ORIGINS` with the exact frontend origin. CORS is not authentication.
- Build vendor adapters as separate workers; connect only after confirming the legal and technical availability of their cloud interfaces. If unsupported, use a home-network bridge that securely POSTs to `/api/ingest` without opening inbound home-network ports.

## Next milestones

1. Validate Xiaomi account region, cloud API permissions and device identifiers; implement a legally permitted connector if available.
2. Verify Philips AC2221 model variant and cloud support; otherwise use a local CoAP bridge.
3. Replace development bearer authentication with Cloudflare Access verification and secure server-side connector secret storage.
4. Add hourly aggregates, data retention, resilient polling, and device onboarding flows.
