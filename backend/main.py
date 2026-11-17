
import os
import time
import hmac
import asyncio
import logging

from contextlib import asynccontextmanager

import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from xiaomi_collector import init_schema, save_profile, collect, set_xiaomi_power
from philips_cloud import save_credentials, run_forever, request_power


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


POLL_INTERVAL_SECONDS = 5
logger = logging.getLogger("atmosphere.poller")


def collect_xiaomi_once():
    with conn() as connection:
        return collect(connection)


async def xiaomi_polling_loop():
    logger.info(
        "Xiaomi polling started; interval=%s seconds",
        POLL_INTERVAL_SECONDS,
    )

    while True:
        try:
            result = await asyncio.to_thread(collect_xiaomi_once)

            if result.get("status") == "collected":
                logger.info(
                    "Xiaomi PM2.5=%s",
                    result.get("pm25"),
                )
            else:
                logger.info(
                    "Xiaomi collection: %s",
                    result.get("status"),
                )

        except asyncio.CancelledError:
            raise

        except Exception:
            logger.exception("Xiaomi polling failed")

        await asyncio.sleep(POLL_INTERVAL_SECONDS)


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

    poller = asyncio.create_task(xiaomi_polling_loop())
    philips_task = asyncio.create_task(run_forever(conn))

    try:
        yield
    finally:
        philips_task.cancel()
        poller.cancel()

        try:
            await asyncio.wait_for(poller, timeout=10)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass
        try:
            await asyncio.wait_for(philips_task, timeout=10)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass


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
            SELECT DISTINCT ON (device) device, pm25, ts
            FROM readings
            ORDER BY device, ts DESC, id DESC
        """).fetchall()
        states = c.execute("""
            SELECT device, power_on, reachable, updated_at
            FROM device_state
        """).fetchall()

    latest = {r["device"]: r for r in rows}
    state_by_device = {r["device"]: r for r in states}
    now = int(time.time())
    result = []

    for device_id, metadata in DEVICES.items():
        reading = latest.get(device_id)
        state = state_by_device.get(device_id)
        timestamp = reading["ts"] if reading else None
        state_age = now - state["updated_at"] if state else None
        # XIAOMI_POWER_STATE_PATCH_V1: never equate a missing reading with power off.
        # Freshness of cloud telemetry determines reachability.
        if state and 0 <= state_age < 30 and state["reachable"]:
            status = "live"
            power_on = state["power_on"]
            reachable = True
        elif state:
            status = "unavailable"
            power_on = None
            reachable = False
        elif timestamp is not None:
            status = "stale"
            power_on = None
            reachable = None
        else:
            status = "unconfigured"
            power_on = None
            reachable = None

        result.append({
            "id": device_id,
            **metadata,
            "pm25": reading["pm25"] if reading else None,
            "timestamp": timestamp,
            "status": status,
            "power_on": power_on,
            "reachable": reachable,
            "state_timestamp": state["updated_at"] if state else None,
            "integration": "xiaomi cloud" if device_id == "xiaomi" else "philips air+ cloud",
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


class PowerCommand(BaseModel):
    power_on: bool


@app.post('/internal/xiaomi/power', include_in_schema=False)
def xiaomi_power(command: PowerCommand, authorization: str | None = Header(None)):
    authorize(authorization, os.getenv('CONTROL_API_KEY', ''))
    try:
        with conn() as c:
            result = set_xiaomi_power(c, command.power_on)
        if result['status'] == 'busy':
            raise HTTPException(409, 'Xiaomi collector busy; retry')
        return result
    except HTTPException:
        raise
    except Exception:
        logging.getLogger('atmosphere').exception('Xiaomi power control failed')
        raise HTTPException(502, 'Xiaomi power control failed')


@app.post('/internal/philips/onboard', include_in_schema=False)
def philips_onboard(bundle: dict, authorization: str | None = Header(None)):
    authorize(authorization, os.getenv('PHILIPS_ONBOARDING_KEY', ''))
    try:
        with conn() as c:
            save_credentials(c, bundle)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {'ok': True, 'provider': 'philips'}


@app.post('/internal/philips/power', include_in_schema=False)
def philips_power(command: PowerCommand, authorization: str | None = Header(None)):
    authorize(authorization, os.getenv('CONTROL_API_KEY', ''))
    try:
        return request_power(command.power_on)
    except TimeoutError:
        raise HTTPException(504, 'Philips power confirmation timed out')
    except RuntimeError as exc:
        logging.getLogger('atmosphere').warning('Philips control unavailable: %s', type(exc).__name__)
        raise HTTPException(503, 'Philips control unavailable')
