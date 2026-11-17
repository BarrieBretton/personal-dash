
import os
import time
import hmac
from contextlib import asynccontextmanager

import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from xiaomi_collector import init_schema, save_profile, collect


DATABASE_URL = os.environ["DATABASE_URL"]
API_KEY = os.getenv("DASHBOARD_API_KEY", "")
INGEST_KEY = os.getenv("INGEST_API_KEY", "")
CORS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS", "http://localhost:8080"
    ).split(",")
    if origin.strip()
]

DEVICES = {
    "xiaomi": {
        "name": "Xiaomi 4 Compact",
        "model": "AC-M18-SC",
    },
    "philips": {
        "name": "Philips AC2221",
        "model": "AC2221",
    },
}


def conn():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=10,
    )


@asynccontextmanager
async def lifespan(app):
    with conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS readings (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                device TEXT NOT NULL,
                pm25 DOUBLE PRECISION NOT NULL,
                ts BIGINT NOT NULL
            )
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS readings_device_ts
            ON readings(device, ts DESC)
        """)
        init_schema(c)
    yield


app = FastAPI(
    title="Atmosphere API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def authorize(value, expected):
    if not expected or not value:
        raise HTTPException(
            401, "Unauthorized or server key not configured"
        )

    if not hmac.compare_digest(
        value, f"Bearer {expected}"
    ):
        raise HTTPException(401, "Unauthorized")


class Reading(BaseModel):
    device: str
    pm25: float = Field(ge=0, le=1000, allow_inf_nan=False)
    timestamp: int | None = None


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/api/devices")
def devices(authorization: str | None = Header(None)):
    authorize(authorization, API_KEY)

    with conn() as c:
        rows = c.execute("""
            SELECT DISTINCT ON (device)
                device, pm25, ts
            FROM readings
            ORDER BY device, ts DESC, id DESC
        """).fetchall()

    latest = {r["device"]: r for r in rows}
    now = int(time.time())

    result = []

    for device_id, metadata in DEVICES.items():
        reading = latest.get(device_id)
        timestamp = reading["ts"] if reading else None

        status = "unconfigured"

        if timestamp is not None:
            status = (
                "live"
                if 0 <= now - timestamp < 180
                else "stale"
            )

        result.append({
            "id": device_id,
            **metadata,
            "pm25": reading["pm25"] if reading else None,
            "timestamp": timestamp,
            "status": status,
            "integration": "external bridge required",
        })

    return result


@app.get("/api/history")
def history(
    device: str,
    hours: int = 24,
    authorization: str | None = Header(None),
):
    authorize(authorization, API_KEY)

    if device not in DEVICES:
        raise HTTPException(404, "Unknown device")

    hours = max(1, min(hours, 168))
    since = int(time.time()) - hours * 3600

    with conn() as c:
        rows = c.execute("""
            SELECT pm25, ts
            FROM readings
            WHERE device = %s AND ts >= %s
            ORDER BY ts DESC, id DESC
            LIMIT 5000
        """, (device, since)).fetchall()

    return list(reversed(rows))


@app.post("/api/ingest")
def ingest(
    reading: Reading,
    authorization: str | None = Header(None),
):
    authorize(authorization, INGEST_KEY)

    if reading.device not in DEVICES:
        raise HTTPException(404, "Unknown device")

    now = int(time.time())
    ts = (
        reading.timestamp
        if reading.timestamp is not None
        else now
    )

    if abs(ts - now) > 300:
        raise HTTPException(
            400,
            "Timestamp must be within 5 minutes of server time",
        )

    with conn() as c:
        c.execute("""
            INSERT INTO readings (device, pm25, ts)
            VALUES (%s, %s, %s)
        """, (reading.device, reading.pm25, ts))

    return {"ok": True}


@app.post('/internal/xiaomi/onboard', include_in_schema=False)
def xiaomi_onboard(bundle: dict, authorization: str | None = Header(None)):
    authorize(authorization, os.getenv('XIAOMI_ONBOARDING_KEY', ''))
    try:
        with conn() as c:
            save_profile(c, bundle)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {'ok': True, 'provider': 'xiaomi'}


@app.post('/internal/xiaomi/collect', include_in_schema=False)
def xiaomi_collect(authorization: str | None = Header(None)):
    authorize(authorization, os.getenv('COLLECTOR_API_KEY', ''))
    try:
        with conn() as c:
            return collect(c)
    except Exception:
        import logging
        logging.getLogger('atmosphere').exception('Xiaomi collection failed')
        raise HTTPException(502, 'Xiaomi collection failed; inspect server logs')
