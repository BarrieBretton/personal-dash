"""Xiaomi Home cloud collector for Atmosphere; mi-home-cli 0.1.3."""
import json
import os
import tempfile
import time
from pathlib import Path

from cryptography.fernet import Fernet
from mi_home_cli.store import Profile
from mi_home_cli.core.session import Session
from mi_home_cli.core.cloud import CloudApi

MODEL = 'xiaomi.airp.cpa4m'
REGION = 'i2'


def cipher():
    return Fernet(os.environ['CREDENTIAL_ENCRYPTION_KEY'].encode())


def init_schema(connection):
    connection.execute('''CREATE TABLE IF NOT EXISTS connector_credentials (
        provider TEXT PRIMARY KEY,
        encrypted_payload BYTEA NOT NULL,
        updated_at BIGINT NOT NULL
    )''')


def save_profile(connection, bundle):
    # Only the two required credential/identity files are accepted.
    if not isinstance(bundle, dict) or set(bundle) != {'auth', 'identity'}:
        raise ValueError('Expected auth and identity objects')
    auth, identity = bundle['auth'], bundle['identity']
    if not isinstance(auth, dict) or not isinstance(identity, dict):
        raise ValueError('Invalid credential bundle')
    required = ('access_token', 'refresh_token', 'device_id', 'obtained_at', 'expires_in')
    if any(not auth.get(k) for k in required) or auth.get('region') != REGION:
        raise ValueError('Missing credentials or incorrect region')
    if not identity.get('install_id') or not identity.get('webhook_id'):
        raise ValueError('Missing OAuth identity')
    encrypted = cipher().encrypt(json.dumps(bundle).encode())
    connection.execute('''INSERT INTO connector_credentials(provider, encrypted_payload, updated_at)
        VALUES ('xiaomi', %s, %s)
        ON CONFLICT(provider) DO UPDATE SET encrypted_payload=EXCLUDED.encrypted_payload,
        updated_at=EXCLUDED.updated_at''', (encrypted, int(time.time())))


def load_profile(connection):
    row = connection.execute('SELECT encrypted_payload FROM connector_credentials WHERE provider=%s', ('xiaomi',)).fetchone()
    if not row:
        raise RuntimeError('Xiaomi credentials not onboarded')
    return json.loads(cipher().decrypt(bytes(row['encrypted_payload'])))


def collect(connection):
    # Transaction-scoped lock prevents concurrent collectors from overwriting refreshed tokens.
    locked = connection.execute('SELECT pg_try_advisory_xact_lock(%s) AS locked', (761902441,)).fetchone()['locked']
    if not locked:
        return {'status': 'already_running'}
    bundle = load_profile(connection)
    with tempfile.TemporaryDirectory(prefix='atmosphere-xiaomi-') as directory:
        profile = Profile('default', root=Path(directory))
        profile.path.mkdir(parents=True, exist_ok=True)
        profile.auth_path.write_text(json.dumps(bundle['auth']), encoding='utf-8')
        profile.identity_path.write_text(json.dumps(bundle['identity']), encoding='utf-8')
        os.chmod(profile.auth_path, 0o600)
        os.chmod(profile.identity_path, 0o600)
        try:
            with Session(profile, region=REGION) as session:
                api = CloudApi(session)
                devices = [d for d in api.fetch_all()['devices'].values() if d.get('model') == MODEL]
                if len(devices) != 1:
                    raise RuntimeError(f'Expected one Xiaomi {MODEL} device, found {len(devices)}')
                device = devices[0]
                if not device.get('online'):
                    raise RuntimeError('Xiaomi purifier is offline')
                props = api.get_props([{'did': device['did'], 'siid': 3, 'piid': 4}])
                if len(props) != 1 or props[0].get('code') != 0:
                    raise RuntimeError('Xiaomi PM2.5 property read failed')
                pm25 = props[0].get('value')
                if isinstance(pm25, bool) or not isinstance(pm25, (int, float)) or not 0 <= pm25 <= 600:
                    raise RuntimeError('Invalid PM2.5 reading')
        finally:
            # Persist token rotation even when a subsequent cloud call fails.
            refreshed = json.loads(profile.auth_path.read_text(encoding='utf-8'))
            if refreshed != bundle['auth']:
                save_profile(connection, {'auth': refreshed, 'identity': bundle['identity']})
        now = int(time.time())
        connection.execute('INSERT INTO readings(device,pm25,ts) VALUES (%s,%s,%s)', ('xiaomi', float(pm25), now))
        return {'status': 'collected', 'device': 'xiaomi', 'pm25': float(pm25), 'timestamp': now}
