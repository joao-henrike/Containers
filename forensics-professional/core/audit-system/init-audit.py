#!/usr/bin/env python3
"""Initialize audit system"""

import os
import json
from pathlib import Path
from datetime import datetime, timezone

# Initialize audit log
log_file = Path('/var/log/forensics/audit.log')
log_file.parent.mkdir(parents=True, exist_ok=True)

# Create genesis entry if log doesn't exist
if not log_file.exists() or log_file.stat().st_size == 0:
    genesis = {
        'seq': 0,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event_type': 'system_init',
        'user': 'system',
        'details': {'message': 'Audit system initialized'},
        'metadata': {'version': '2.0.0'},
        'prev_hash': '0' * 64,
        'hash': '0' * 64,
        'signatures': {'ed25519': 'genesis', 'gpg': 'genesis'}
    }
    
    with open(log_file, 'w') as f:
        f.write(json.dumps(genesis) + '\n')
    
    print("✅ Audit system initialized")
else:
    print("ℹ️  Audit system already initialized")
