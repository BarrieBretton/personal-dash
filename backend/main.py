import os, sqlite3, json, asyncio, time
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

DB = os.getenv('DATABASE_PATH','./atmosphere.db')
API_KEY = os.getenv('DASHBOARD_API_KEY','')
INGEST_KEY = os.getenv('INGEST_API_KEY','')
CORS = os.getenv('CORS_ORIGINS','http://localhost:8080').split(',')

def conn():
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    return c

@asynccontextmanager
async def lifespan(app):
    with conn() as c:
        c.execute('CREATE TABLE IF NOT EXISTS readings (id INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT NOT NULL, pm25 REAL NOT NULL, ts INTEGER NOT NULL)')
        c.execute('CREATE INDEX IF NOT EXISTS readings_device_ts ON readings(device,ts)')
    yield

app=FastAPI(title='Atmosphere API',lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=CORS,allow_methods=['GET','POST'],allow_headers=['*'])
DEVICES={'xiaomi':{'name':'Xiaomi 4 Compact','model':'AC-M18-SC'},'philips':{'name':'Philips AC2221','model':'AC2221'}}

def authorize(value, expected):
    if not expected or value != f'Bearer {expected}':
        raise HTTPException(401,'Unauthorized or server key not configured')

class Reading(BaseModel):
    device: str
    pm25: float=Field(ge=0,le=1000)
    timestamp: int | None=None

@app.get('/health')
def health():return {'ok':True}

@app.get('/api/devices')
def devices(authorization: str | None=Header(None)):
    authorize(authorization,API_KEY)
    with conn() as c:
        latest={r['device']:dict(r) for r in c.execute('SELECT device,pm25,ts FROM readings WHERE id IN (SELECT MAX(id) FROM readings GROUP BY device)')}
    now=int(time.time())
    return [{'id':key,**v,'pm25':latest.get(key,{}).get('pm25'),'timestamp':latest.get(key,{}).get('ts'),'status':('live' if now-latest[key]['ts']<180 else 'stale') if key in latest else 'unconfigured','integration':'external bridge required'} for key,v in DEVICES.items()]

@app.get('/api/history')
def history(device:str,hours:int=24,authorization:str|None=Header(None)):
    authorize(authorization,API_KEY)
    if device not in DEVICES:raise HTTPException(404,'Unknown device')
    hours=max(1,min(hours,168))
    with conn() as c:
        return [dict(r) for r in c.execute('SELECT pm25,ts FROM readings WHERE device=? AND ts>=? ORDER BY ts LIMIT 5000',(device,int(time.time())-hours*3600))]

@app.post('/api/ingest')
def ingest(reading:Reading,authorization:str|None=Header(None)):
    authorize(authorization,INGEST_KEY)
    if reading.device not in DEVICES:raise HTTPException(404,'Unknown device')
    now=int(time.time()); ts=reading.timestamp or now
    if abs(ts-now)>300:raise HTTPException(400,'Timestamp must be within 5 minutes of server time')
    with conn() as c:c.execute('INSERT INTO readings(device,pm25,ts) VALUES(?,?,?)',(reading.device,reading.pm25,ts))
    return {'ok':True}
