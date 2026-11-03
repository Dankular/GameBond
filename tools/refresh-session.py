"""Generate matching fresh session IDs; copy server config then restart BOTH peers."""
import json
from pathlib import Path
import secrets

root = Path(__file__).resolve().parents[1]
session = secrets.token_hex(16)
for role in ('client', 'server'):
    path = root / 'configs' / f'local-{role}.json'
    config = json.loads(path.read_text())
    config['session'] = session
    path.write_text(json.dumps(config, indent=2) + '\n')
print(json.dumps({'session': session, 'next': 'Update server config and restart only GameBond; start client with matching config'}))
