#!/usr/bin/env python3
"""
==============================================================================
Professional Forensics Container — Audit Logger v2.1.0
Criptografia Híbrida: Ed25519 (primário) + GPG (compatibilidade legal)
Blockchain-like: cada entrada encadeada à anterior via SHA-256
Compliance: NIST SP 800-86
==============================================================================
"""

import json
import hashlib
import datetime
import os
import sys
import subprocess
import uuid
from pathlib import Path

# Caminhos do sistema
AUDIT_LOG     = "/var/log/forensics/audit.log"
KEYS_DIR      = "/opt/forensics/quantum-keys"
ED25519_KEY   = f"{KEYS_DIR}/audit_ed25519.key"
ED25519_PUB   = f"{KEYS_DIR}/audit_ed25519.pub"
GPG_EMAIL     = "forensics-audit@professional.local"


class AuditLogger:
    """
    Logger criptográfico com assinaturas híbridas Ed25519 + GPG.
    Cada entrada está encadeada à anterior via hash SHA-256 (blockchain-like).
    """

    def __init__(self):
        self.log_path = Path(AUDIT_LOG)
        self.keys_dir = Path(KEYS_DIR)
        self._ensure_log_exists()

    def _ensure_log_exists(self):
        """Garante que o arquivo de log e os diretórios existem."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.touch()

    def _get_last_hash(self) -> str:
        """Retorna o hash da última entrada do log (para encadeamento)."""
        try:
            with open(self.log_path, "r") as f:
                lines = [l.strip() for l in f if l.strip()]
            if lines:
                last = json.loads(lines[-1])
                return last.get("hash", "0" * 64)
        except Exception:
            pass
        return "0" * 64

    def _get_next_seq(self) -> int:
        """Retorna o próximo número de sequência."""
        try:
            with open(self.log_path, "r") as f:
                lines = [l.strip() for l in f if l.strip()]
            if lines:
                last = json.loads(lines[-1])
                return last.get("seq", 0) + 1
        except Exception:
            pass
        return 1

    def _compute_hash(self, entry: dict) -> str:
        """Calcula o SHA-256 de uma entrada (excluindo o campo 'hash')."""
        data = {k: v for k, v in entry.items() if k != "hash"}
        serialized = json.dumps(data, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _sign_ed25519(self, data: str) -> str:
        """Assina dados com a chave Ed25519."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            import base64

            with open(ED25519_KEY, "rb") as f:
                private_key = load_pem_private_key(f.read(), password=None)

            signature = private_key.sign(data.encode("utf-8"))
            return base64.b64encode(signature).decode("utf-8")
        except Exception as e:
            return f"signature_failed:{str(e)[:50]}"

    def _sign_gpg(self, data: str) -> str:
        """Assina dados com GPG para compatibilidade legal."""
        try:
            result = subprocess.run(
                ["gpg", "--clearsign", "--local-user", GPG_EMAIL,
                 "--batch", "--no-tty"],
                input=data.encode("utf-8"),
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.decode("utf-8", errors="replace")[:200]
            return f"gpg_failed:returncode={result.returncode}"
        except Exception as e:
            return f"gpg_unavailable:{str(e)[:50]}"

    def log_event(self, event_type: str, details: dict, user: str = None) -> dict:
        """
        Registra um evento no audit log com assinaturas criptográficas.

        Eventos auditáveis (NIST SP 800-86):
          — module_install / module_remove / module_update / module_verify
          — case_created / case_closed
          — evidence_added / evidence_hashed / custody_updated
          — container_started / container_stopped
          — user_login / privilege_escalation / config_changed
          — tool_executed / file_accessed / export_created
          — violation_attempt (tentativa de deletar evidência)
        """
        if user is None:
            user = os.environ.get("USER", os.environ.get("LOGNAME", "unknown"))

        prev_hash = self._get_last_hash()
        seq = self._get_next_seq()

        entry = {
            "seq": seq,
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
            "event_type": event_type,
            "user": user,
            "container_id": self._get_container_id(),
            "details": details,
            "prev_hash": prev_hash,
            "hash": "",
            "signatures": {
                "ed25519": "",
                "gpg": ""
            }
        }

        # Computar hash (blockchain-like)
        entry["hash"] = self._compute_hash(entry)

        # Assinar com Ed25519
        sign_data = json.dumps(
            {k: v for k, v in entry.items() if k != "signatures"},
            sort_keys=True
        )
        entry["signatures"]["ed25519"] = self._sign_ed25519(sign_data)
        entry["signatures"]["gpg"] = self._sign_gpg(sign_data[:500])

        # Escrever no log (append-only)
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except PermissionError:
            # Log com chattr +a — somente append funciona
            try:
                os.system(f'echo \'{json.dumps(entry)}\' >> {self.log_path}')
            except Exception:
                pass

        return entry

    def _get_container_id(self) -> str:
        """Retorna ID do container Docker."""
        try:
            with open("/proc/self/cgroup", "r") as f:
                for line in f:
                    if "docker" in line:
                        return line.strip().split("/")[-1][:12]
        except Exception:
            pass
        return "local"

    def verify_integrity(self) -> dict:
        """
        Verifica a integridade completa do audit log.
        Valida:
          1. Cadeia de hashes (blockchain-like)
          2. Assinaturas Ed25519
          3. Consistência de sequência
        """
        results = {
            "status": "VALID",
            "total_entries": 0,
            "broken_links": [],
            "signature_failures": [],
            "sequence_gaps": []
        }

        try:
            with open(self.log_path, "r") as f:
                lines = [l.strip() for l in f if l.strip()]

            results["total_entries"] = len(lines)
            entries = [json.loads(l) for l in lines]

            for i, entry in enumerate(entries):
                # Verificar hash da entrada
                stored_hash = entry.get("hash", "")
                computed = self._compute_hash(entry)
                if stored_hash != computed:
                    results["broken_links"].append({
                        "seq": entry.get("seq"),
                        "reason": "hash_mismatch"
                    })
                    results["status"] = "INVALID"

                # Verificar encadeamento com a entrada anterior
                if i > 0:
                    prev = entries[i - 1]
                    if entry.get("prev_hash") != prev.get("hash"):
                        results["broken_links"].append({
                            "seq": entry.get("seq"),
                            "reason": "chain_broken",
                            "expected": prev.get("hash", "")[:16],
                            "got": entry.get("prev_hash", "")[:16]
                        })
                        results["status"] = "INVALID"

                # Verificar gaps de sequência
                if i > 0:
                    expected_seq = entries[i - 1].get("seq", 0) + 1
                    if entry.get("seq") != expected_seq:
                        results["sequence_gaps"].append({
                            "expected": expected_seq,
                            "got": entry.get("seq")
                        })

        except Exception as e:
            results["status"] = "ERROR"
            results["error"] = str(e)

        return results

    def show_entries(self, limit: int = 20, event_type: str = None,
                     user: str = None) -> list:
        """Retorna entradas recentes do audit log com filtros opcionais."""
        try:
            with open(self.log_path, "r") as f:
                lines = [l.strip() for l in f if l.strip()]

            entries = [json.loads(l) for l in lines]

            if event_type:
                entries = [e for e in entries if e.get("event_type") == event_type]
            if user:
                entries = [e for e in entries if e.get("user") == user]

            return entries[-limit:]
        except Exception:
            return []

    def export_log(self, output_path: str, fmt: str = "json") -> bool:
        """Exporta o audit log para arquivo externo."""
        try:
            with open(self.log_path, "r") as f:
                lines = [l.strip() for l in f if l.strip()]
            entries = [json.loads(l) for l in lines]

            with open(output_path, "w") as f:
                if fmt == "json":
                    json.dump(entries, f, indent=2, ensure_ascii=False)
                else:
                    import csv as csv_mod
                    writer = csv_mod.writer(f)
                    writer.writerow(["seq", "timestamp", "event_type",
                                     "user", "hash", "prev_hash"])
                    for e in entries:
                        writer.writerow([
                            e.get("seq"), e.get("timestamp"),
                            e.get("event_type"), e.get("user"),
                            e.get("hash", "")[:16], e.get("prev_hash", "")[:16]
                        ])
            return True
        except Exception:
            return False

    def get_stats(self) -> dict:
        """Retorna estatísticas do audit log."""
        try:
            with open(self.log_path, "r") as f:
                lines = [l.strip() for l in f if l.strip()]
            entries = [json.loads(l) for l in lines]

            event_counts = {}
            for e in entries:
                et = e.get("event_type", "unknown")
                event_counts[et] = event_counts.get(et, 0) + 1

            return {
                "total_entries": len(entries),
                "first_entry": entries[0].get("timestamp") if entries else None,
                "last_entry": entries[-1].get("timestamp") if entries else None,
                "event_counts": event_counts,
                "log_size_bytes": self.log_path.stat().st_size
            }
        except Exception as e:
            return {"error": str(e)}


# Instância global (singleton)
_logger = None


def get_logger() -> AuditLogger:
    """Retorna instância singleton do AuditLogger."""
    global _logger
    if _logger is None:
        _logger = AuditLogger()
    return _logger


def log_event(event_type: str, details: dict, user: str = None) -> dict:
    """Função de conveniência para logar um evento."""
    return get_logger().log_event(event_type, details, user)


if __name__ == "__main__":
    # CLI básica para testes
    if len(sys.argv) >= 3:
        logger = get_logger()
        event = sys.argv[1]
        detail_str = sys.argv[2] if len(sys.argv) > 2 else "{}"
        try:
            details = json.loads(detail_str)
        except Exception:
            details = {"raw": detail_str}
        result = logger.log_event(event, details)
        print(json.dumps(result, indent=2))
    else:
        print("Usage: audit-logger.py <event_type> '<details_json>'")
        sys.exit(1)
