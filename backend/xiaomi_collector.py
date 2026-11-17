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
    # XIAOMI_POWER_STATE_PATCH_V1: last confirmed power and reachability.
    connection.execute('''CREATE TABLE IF NOT EXISTS device_state (
        device TEXT PRIMARY KEY,
        power_on BOOLEAN,
        reachable BOOLEAN NOT NULL DEFAULT FALSE,
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
                props = api.get_props([
                    {'did': device['did'], 'siid': 3, 'piid': 4},
                    {'did': device['did'], 'siid': 2, 'piid': 1},
                ])
                values = {
                    (item.get('siid'), item.get('piid')): item.get('value')
                    for item in props if item.get('code') == 0
                }
                if (3, 4) not in values:
                    raise RuntimeError('Xiaomi PM2.5 property read failed')
                pm25 = values[(3, 4)]
                raw_power = values.get((2, 1))
                power_on = raw_power if isinstance(raw_power, bool) else None
                if isinstance(pm25, bool) or not isinstance(pm25, (int, float)) or not 0 <= pm25 <= 600:
                    raise RuntimeError('Invalid PM2.5 reading')
        finally:
            # Persist token rotation even when a subsequent cloud call fails.
            refreshed = json.loads(profile.auth_path.read_text(encoding='utf-8'))
            if refreshed != bundle['auth']:
                save_profile(connection, {'auth': refreshed, 'identity': bundle['identity']})
        now = int(time.time())
        connection.execute('''INSERT INTO device_state(device,power_on,reachable,updated_at)
            VALUES (%s,%s,TRUE,%s)
            ON CONFLICT(device) DO UPDATE SET
                power_on=EXCLUDED.power_on,
                reachable=EXCLUDED.reachable,
                updated_at=EXCLUDED.updated_at''', ('xiaomi', power_on, now))
        connection.execute('INSERT INTO readings(device,pm25,ts) VALUES (%s,%s,%s)', ('xiaomi', float(pm25), now))
        return {'status': 'collected', 'device': 'xiaomi', 'pm25': float(pm25), 'power_on': power_on, 'timestamp': now}


def set_xiaomi_power(connection, desired: bool):
    """Change the power property, then verify it from Xiaomi Cloud."""
    if not isinstance(desired, bool):
        raise ValueError('Power value must be boolean')
    lock = connection.execute(
        'SELECT pg_advisory_xact_lock(%s) AS locked', (761902441,)
    ).fetchone()['locked']
    if not lock:
        return {'status': 'busy'}
    bundle = load_profile(connection)
    with tempfile.TemporaryDirectory(prefix='atmosphere-xiaomi-control-') as directory:
        profile = Profile('default', root=Path(directory))
        profile.path.mkdir(parents=True, exist_ok=True)
        profile.auth_path.write_text(json.dumps(bundle['auth']), encoding='utf-8')
        profile.identity_path.write_text(json.dumps(bundle['identity']), encoding='utf-8')
        os.chmod(profile.auth_path, 0o600)
        os.chmod(profile.identity_path, 0o600)
        try:
            with Session(profile, region=REGION) as session:
                api = CloudApi(session)
                devices = [d for d in api.fetch_all()['devices'].values()
                           if d.get('model') == MODEL]
                if len(devices) != 1 or not devices[0].get('online'):
                    raise RuntimeError('Xiaomi purifier unavailable or ambiguous')
                did = devices[0]['did']
                response = api.set_props([{'did': did, 'siid': 2, 'piid': 1, 'value': desired}])
                if len(response) != 1 or response[0].get('code') not in (0, 1):
                    raise RuntimeError('Xiaomi rejected power command')
                # Cloud acceptance is not proof that the physical device has changed.
                result = api.get_props([{'did': did, 'siid': 2, 'piid': 1}])
                actual = result[0].get('value') if len(result) == 1 and result[0].get('code') == 0 else None
        finally:
            refreshed = json.loads(profile.auth_path.read_text(encoding='utf-8'))
            if refreshed != bundle['auth']:
                save_profile(connection, {'auth': refreshed, 'identity': bundle['identity']})
    if isinstance(actual, bool) and actual == desired:
        connection.execute("""INSERT INTO device_state(device,power_on,reachable,updated_at)
            VALUES (%s,%s,TRUE,%s)
            ON CONFLICT(device) DO UPDATE SET power_on=EXCLUDED.power_on,
            reachable=EXCLUDED.reachable, updated_at=EXCLUDED.updated_at""",
            ('xiaomi', actual, int(time.time())))
    return {'status': 'confirmed' if actual == desired else 'pending',
            'requested_power_on': desired, 'power_on': actual}
