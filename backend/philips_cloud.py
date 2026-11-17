"""Philips Air+ Cobra read-only cloud adapter. Unofficial protocol, best-effort."""
import asyncio
import hashlib
import hmac
import json
import logging
import os
import random
import re
import secrets
import ssl
import threading
import time
from urllib.parse import quote_plus

import aiohttp
import paho.mqtt.client as mqtt
from xiaomi_collector import cipher

LOG = logging.getLogger('atmosphere.philips')
AIR = 'https://www.api.air.philips.com/'
APP_ID = '9fd505fa9c7111e9a1e3061302926720'
MODEL = 'AC2221/13'


def save_credentials(connection, payload):
    if not isinstance(payload, dict) or set(payload) != {'uid', 'signing_key'}:
        raise ValueError('Expected uid and signing_key')
    if not isinstance(payload['uid'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', payload['uid']):
        raise ValueError('Invalid account identifier')
    if not isinstance(payload['signing_key'], str) or not re.fullmatch(r'a_[A-Za-z0-9]{32}', payload['signing_key']):
        raise ValueError('Invalid signing key')
    encrypted = cipher().encrypt(json.dumps(payload).encode())
    connection.execute('''INSERT INTO connector_credentials(provider,encrypted_payload,updated_at)
        VALUES('philips',%s,%s) ON CONFLICT(provider) DO UPDATE SET
        encrypted_payload=EXCLUDED.encrypted_payload,updated_at=EXCLUDED.updated_at''',
        (encrypted, int(time.time())))


def load_credentials(connection):
    row = connection.execute("SELECT encrypted_payload FROM connector_credentials WHERE provider='philips'").fetchone()
    if row is None:
        return None
    return json.loads(cipher().decrypt(bytes(row['encrypted_payload'])))


def sign(ts, username, key):
    encoded = quote_plus(username, safe='-._*').replace('~', '%7E')
    canonical = f'app_id={APP_ID}&timestamp={ts}&username={encoded}'
    inner = hmac.new(key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return hmac.new(username.encode(), inner.encode(), hashlib.sha256).hexdigest()


async def request(session, path, *, body=None, headers=None):
    opts = {'headers': {'Accept': 'application/json', **(headers or {})},
            'timeout': aiohttp.ClientTimeout(total=18), 'allow_redirects': False}
    if body is not None:
        opts['json'] = body
    async with session.request('POST' if body is not None else 'GET', AIR + path, **opts) as res:
        if res.status != 200:
            raise RuntimeError(f'Philips API HTTP {res.status}')
        data = await res.json(content_type=None)
    if not isinstance(data, dict) or not isinstance(data.get('meta'), dict) or data['meta'].get('code') != 0:
        raise RuntimeError('Philips API returned an error')
    return data.get('data')


async def connect_details(session, credentials):
    server = await request(session, 'device/serverTime/')
    if isinstance(server, str):
        server = json.loads(server)
    ts = str(server['timestamp2'])
    if not re.fullmatch(r'\d{1,20}', ts):
        raise RuntimeError('Invalid Philips cloud time')
    user = 'PHILIPS:' + credentials['uid']
    result = await request(session, 'enduser/v2/getToken/', body={
        'app_id': APP_ID, 'username': user, 'timestamp': ts
    }, headers={'Signature': sign(ts, user, credentials['signing_key'])})
    token = result['token']
    headers = {'Authorization': 'jwt ' + token}
    devices = await request(session, 'enduser/deviceList/', headers=headers)
    matches = [d for d in devices if isinstance(d, dict) and isinstance(d.get('device_info'), dict)
               and d['device_info'].get('type') == 'Cobra'
               and d['device_info'].get('modelid') == MODEL]
    if len(matches) != 1:
        raise RuntimeError(f'Expected one Philips {MODEL}, found {len(matches)}')
    record = matches[0]
    if record['device_info'].get('is_online') is not True:
        raise RuntimeError('Philips device reported offline')
    did = record['device_id']
    details = await request(session, 'enduser/v2/mqttInfo/', body={'device_id': [did]}, headers=headers)
    matching = [m for m in details.get('mqttinfos', []) if m.get('device_id') == did]
    if len(matching) != 1:
        raise RuntimeError('Philips MQTT metadata missing')
    data = matching[0]
    host, path, client_id = data['endpoint'], data['path'], data['client_id']
    if not re.fullmatch(r'[a-z0-9-]+-ats\.iot\.[a-z0-9-]+\.amazonaws\.com', host):
        raise RuntimeError('Unexpected Philips MQTT host')
    if not isinstance(path, str) or not path.startswith('/mqtt?') or len(path) > 8192 or '\n' in path or '\r' in path:
        raise RuntimeError('Invalid MQTT signed path')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', client_id):
        raise RuntimeError('Invalid MQTT client ID')
    return host, path, client_id, did


class ShadowReader:
    def __init__(self, host, path, client_id, did):
        self.lock = threading.Lock()
        self.last_state = None
        self.last_update = 0.0
        self.ready = threading.Event()
        self.disconnected = threading.Event()
        self.prefix = f'$aws/things/{did}/shadow'
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id,
                                  transport='websockets', reconnect_on_failure=False)
        self.client.tls_set_context(ssl.create_default_context())
        self.client.ws_set_options(path=path)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect
        self.host = host

    def _on_connect(self, client, userdata, flags, reason, props):
        if reason.is_failure:
            self.disconnected.set()
            return
        client.subscribe([(self.prefix + '/get/accepted', 1),
                          (self.prefix + '/update/documents', 1),
                          (self.prefix + '/update/accepted', 1)], qos=1)
        client.publish(self.prefix + '/get', json.dumps({'clientToken': secrets.token_hex(12)}), qos=1)

    def _on_message(self, client, userdata, message):
        if len(message.payload) > 262144:
            return
        try:
            payload = json.loads(message.payload)
            doc = payload.get('current', payload) if message.topic.endswith('/documents') else payload
            state = doc.get('state', {}).get('reported')
            if not isinstance(state, dict):
                return
            with self.lock:
                self.last_state = {**(self.last_state or {}), **state}
                self.last_update = time.monotonic()
            self.ready.set()
        except (ValueError, TypeError, AttributeError):
            return

    def _on_disconnect(self, client, userdata, flags, reason, props):
        self.disconnected.set()

    def start(self):
        self.client.connect(self.host, 443, 60)
        self.client.loop_start()
        if not self.ready.wait(25):
            raise RuntimeError('Philips MQTT initial state timeout')

    def read(self):
        self.client.publish(self.prefix + '/get', json.dumps({'clientToken': secrets.token_hex(12)}), qos=1)

    def snapshot(self):
        with self.lock:
            return dict(self.last_state or {}), self.last_update

    def close(self):
        self.client.disconnect()
        self.client.loop_stop()


async def run_forever(connect_db):
    """Read-only, reconnecting task. One Uvicorn worker only."""
    delay = 2
    while True:
        reader = None
        try:
            with connect_db() as db:
                credentials = load_credentials(db)
            if credentials is None:
                await asyncio.sleep(30)
                continue
            async with aiohttp.ClientSession() as session:
                host, path, client_id, did = await connect_details(session, credentials)
            reader = ShadowReader(host, path, client_id, did)
            await asyncio.to_thread(reader.start)
            delay = 2
            last_persisted = None
            last_requested = 0.0
            while not reader.disconnected.is_set():
                state, updated = reader.snapshot()
                now = time.monotonic()
                if now - last_requested >= 30:
                    reader.read()
                    last_requested = now
                if updated and now - updated > 150:
                    raise RuntimeError('Philips shadow telemetry stale')
                power = state.get('D03102')
                pm = state.get('D03221')
                if type(power) in (int, bool) and int(power) in (0, 1) and type(pm) in (int, float) and 0 <= pm <= 600:
                    snapshot = (int(power), float(pm), updated)
                    if snapshot != last_persisted:
                        with connect_db() as db:
                            db.execute('''INSERT INTO device_state(device,power_on,reachable,updated_at)
                                VALUES('philips',%s,TRUE,%s) ON CONFLICT(device) DO UPDATE SET
                                power_on=EXCLUDED.power_on,reachable=TRUE,updated_at=EXCLUDED.updated_at''',
                                (bool(power), int(time.time())))
                            db.execute("INSERT INTO readings(device,pm25,ts) VALUES('philips',%s,%s)",
                                       (float(pm), int(time.time())))
                        last_persisted = snapshot
                await asyncio.sleep(5)
            raise RuntimeError('Philips MQTT disconnected')
        except asyncio.CancelledError:
            raise
        except Exception as error:
            LOG.warning('Philips cloud unavailable: %s', type(error).__name__)
            await asyncio.sleep(delay + random.uniform(0, 1))
            delay = min(60, delay * 2)
        finally:
            if reader is not None:
                await asyncio.to_thread(reader.close)
