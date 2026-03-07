#!/usr/bin/env python3
"""
FORENSICS AUDIT LOGGER
Cryptographic audit logging with Ed25519 + GPG hybrid signatures
Implements blockchain-like integrity with immutable, verifiable logs
"""

import json
import hashlib
import time
import sys
import os
from datetime import datetime, timezone
from pathlib import Path
import argparse

try:
    from nacl.signing import SigningKey
    from nacl.encoding import Base64Encoder
    import gnupg
except ImportError:
    print("ERROR: Required packages not installed", file=sys.stderr)
    print("Run: pip3 install PyNaCl python-gnupg", file=sys.stderr)
    sys.exit(1)

class ForensicsAuditLogger:
    """
    Cryptographic audit logger with hybrid signatures
    - Ed25519 for speed and modern crypto
    - GPG for compatibility and legal standards
    """
    
    def __init__(self, log_file="/var/log/forensics/audit.log", 
                 keys_dir="/keys"):
        self.log_file = Path(log_file)
        self.keys_dir = Path(keys_dir)
        self.ed25519_key_path = self.keys_dir / "audit_ed25519.key"
        self.gpg_home = self.keys_dir / "gnupg"
        
        # Ensure directories exist
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize crypto
        self._init_ed25519()
        self._init_gpg()
        
    def _init_ed25519(self):
        """Initialize or load Ed25519 signing key"""
        if self.ed25519_key_path.exists():
            # Load existing key
            with open(self.ed25519_key_path, 'rb') as f:
                self.signing_key = SigningKey(f.read())
        else:
            # Generate new key
            self.signing_key = SigningKey.generate()
            # Save private key (protected by filesystem permissions)
            with open(self.ed25519_key_path, 'wb') as f:
                f.write(bytes(self.signing_key))
            os.chmod(self.ed25519_key_path, 0o600)
            
            # Save public key
            verify_key = self.signing_key.verify_key
            pub_key_path = self.keys_dir / "audit_ed25519.pub"
            with open(pub_key_path, 'wb') as f:
                f.write(bytes(verify_key))
            os.chmod(pub_key_path, 0o644)
                
    def _init_gpg(self):
        """Initialize GPG for additional signatures"""
        self.gpg_home.mkdir(parents=True, exist_ok=True)
        os.chmod(self.gpg_home, 0o700)
        
        self.gpg = gnupg.GPG(gnupghome=str(self.gpg_home))
        
        # Check if key exists, if not create one
        keys = self.gpg.list_keys()
        if not keys:
            # Generate GPG key for audit signing
            input_data = self.gpg.gen_key_input(
                name_email='forensics-audit@localhost',
                name_real='Forensics Audit System',
                key_type='RSA',
                key_length=4096,
                passphrase=''  # No passphrase for automated signing
            )
            key = self.gpg.gen_key(input_data)
            self.gpg_fingerprint = str(key)
        else:
            self.gpg_fingerprint = keys[0]['fingerprint']
    
    def _get_last_hash(self):
        """Get hash of the last log entry (blockchain-like linking)"""
        if not self.log_file.exists() or self.log_file.stat().st_size == 0:
            # Genesis block
            return "0" * 64
        
        try:
            with open(self.log_file, 'r') as f:
                # Read last line
                lines = f.readlines()
                if lines:
                    last_entry = json.loads(lines[-1])
                    return last_entry.get('hash', "0" * 64)
        except:
            pass
        
        return "0" * 64
    
    def _compute_hash(self, data):
        """Compute SHA-256 hash of data"""
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    
    def _sign_ed25519(self, data):
        """Sign data with Ed25519"""
        message = json.dumps(data, sort_keys=True).encode()
        signed = self.signing_key.sign(message, encoder=Base64Encoder)
        return signed.signature.decode('utf-8')
    
    def _sign_gpg(self, data):
        """Sign data with GPG"""
        message = json.dumps(data, sort_keys=True)
        signed = self.gpg.sign(message, keyid=self.gpg_fingerprint, detach=True)
        return str(signed)
    
    def log_event(self, event_type, user, details=None, metadata=None):
        """
        Log an auditable event with cryptographic signatures
        
        Args:
            event_type: Type of event (e.g., 'module_install', 'evidence_added')
            user: User performing the action
            details: Details about the event
            metadata: Additional metadata
        """
        # Get sequence number
        seq = self._get_sequence_number()
        
        # Get previous hash (blockchain-like)
        prev_hash = self._get_last_hash()
        
        # Build event data
        event_data = {
            'seq': seq,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'user': user,
            'details': details or {},
            'metadata': metadata or {},
            'container_id': os.environ.get('HOSTNAME', 'unknown'),
        }
        
        # Add previous hash
        event_data['prev_hash'] = prev_hash
        
        # Compute current hash
        current_hash = self._compute_hash(event_data)
        event_data['hash'] = current_hash
        
        # Generate signatures
        signatures = {
            'ed25519': self._sign_ed25519(event_data),
            'gpg': self._sign_gpg(event_data)
        }
        event_data['signatures'] = signatures
        
        # Write to log file (append-only)
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(event_data) + '\n')
        
        return event_data
    
    def _get_sequence_number(self):
        """Get next sequence number"""
        if not self.log_file.exists():
            return 1
        
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_entry = json.loads(lines[-1])
                    return last_entry.get('seq', 0) + 1
        except:
            pass
        
        return 1
    
    def verify_integrity(self):
        """Verify integrity of entire audit log chain"""
        if not self.log_file.exists():
            return True, "No audit log found"
        
        errors = []
        entries = []
        
        with open(self.log_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    entry = json.loads(line.strip())
                    entries.append(entry)
                except json.JSONDecodeError as e:
                    errors.append(f"Line {line_num}: Invalid JSON - {e}")
        
        # Verify chain
        for i, entry in enumerate(entries):
            # Verify hash chain
            if i == 0:
                # Genesis entry
                if entry['prev_hash'] != "0" * 64:
                    errors.append(f"Entry {i+1}: Invalid genesis prev_hash")
            else:
                expected_prev_hash = entries[i-1]['hash']
                if entry['prev_hash'] != expected_prev_hash:
                    errors.append(f"Entry {i+1}: Chain broken - prev_hash mismatch")
            
            # Verify hash
            entry_copy = entry.copy()
            stored_hash = entry_copy.pop('hash')
            entry_copy.pop('signatures')  # Remove signatures for hash verification
            computed_hash = self._compute_hash(entry_copy)
            
            if stored_hash != computed_hash:
                errors.append(f"Entry {i+1}: Hash mismatch - entry may be tampered")
        
        if errors:
            return False, errors
        
        return True, f"Verified {len(entries)} entries successfully"


def main():
    parser = argparse.ArgumentParser(description='Forensics Audit Logger')
    parser.add_argument('--event', required=True, help='Event type')
    parser.add_argument('--user', default='sherlock', help='User performing action')
    parser.add_argument('--details', default='{}', help='Event details (JSON)')
    parser.add_argument('--metadata', default='{}', help='Additional metadata (JSON)')
    parser.add_argument('--log-file', default='/var/log/forensics/audit.log')
    parser.add_argument('--keys-dir', default='/keys')
    
    args = parser.parse_args()
    
    try:
        details = json.loads(args.details) if args.details else {}
        metadata = json.loads(args.metadata) if args.metadata else {}
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in details/metadata: {e}", file=sys.stderr)
        sys.exit(1)
    
    logger = ForensicsAuditLogger(log_file=args.log_file, keys_dir=args.keys_dir)
    
    try:
        event = logger.log_event(
            event_type=args.event,
            user=args.user,
            details=details,
            metadata=metadata
        )
        print(f"Event logged: seq={event['seq']}, hash={event['hash'][:16]}...")
    except Exception as e:
        print(f"ERROR: Failed to log event: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
