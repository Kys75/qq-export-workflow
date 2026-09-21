from .errors import SafeError
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import uuid

from .config import NAMES, private_dir


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def parameters(config):
    values = dict(config)
    sidecar = Path(str(config["key_file"]) + ".params.json")
    if sidecar.exists():
        params = json.loads(sidecar.read_text())
        iterations = int(params["kdf_iter"])
        algorithm = params["hmac_algorithm"].upper()
        if iterations < 1 or algorithm not in ("SHA1", "SHA256", "SHA512"):
            raise SafeError("Invalid key parameter sidecar")
        values.update(kdf_iter=iterations, hmac_algorithm=algorithm)
    return values


def refresh(config):
    """Publish one complete generation only after every present database validates."""
    config = parameters(config)
    key = config["key_file"].read_text().rstrip("\r\n")
    if not key or any(ord(c) < 32 for c in key):
        raise SafeError("Key file is empty or contains control characters")
    source = config["source_dir"]
    if not (source / "nt_msg.db").is_file():
        raise SafeError("Main encrypted database is missing; check source_dir")
    def check_wal():
        for database_name in NAMES:
            wal = source / (database_name + ".db-wal")
            if wal.exists() and wal.stat().st_size:
                raise SafeError("Database has a nonempty WAL; fully quit QQ before refreshing")
    check_wal()
    original_stats = {name: ((source / (name + ".db")).stat().st_size,
                             (source / (name + ".db")).stat().st_mtime_ns)
                      for name in NAMES if (source / (name + ".db")).exists()}
    state = private_dir(config["state_dir"])
    generations = private_dir(state / "generations")
    with tempfile.TemporaryDirectory(prefix="refresh-", dir=state) as temporary:
        work = Path(temporary)
        ready = private_dir(work / "ready")
        for name in NAMES:
            origin = source / (name + ".db")
            if not origin.exists():
                continue
            before = origin.stat()
            clean = work / (name + ".encrypted")
            with origin.open("rb") as reader, clean.open("wb") as writer:
                reader.seek(config["header_bytes"])
                shutil.copyfileobj(reader, writer)
            clean.chmod(0o600)
            after = origin.stat()
            check_wal()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise SafeError("Source database changed during copy; fully quit QQ and retry")
            output = ready / (name + ".db")
            sql = (f"PRAGMA key={literal(key)};"
                   f"PRAGMA cipher_page_size={config['page_size']};"
                   f"PRAGMA kdf_iter={config['kdf_iter']};"
                   f"PRAGMA cipher_hmac_algorithm=HMAC_{config['hmac_algorithm']};"
                   f"PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_{config['kdf_algorithm']};"
                   f"ATTACH DATABASE {literal(output)} AS plain KEY '';"
                   "SELECT sqlcipher_export('plain'); DETACH DATABASE plain;")
            result = subprocess.run([config["sqlcipher"], "-bail", str(clean)], input=sql,
                                    text=True, capture_output=True, timeout=600)
            if result.returncode or not output.exists():
                raise SafeError("SQLCipher decryption failed; check key and configured parameters")
            output.chmod(0o600)
            with sqlite3.connect(output.as_uri() + "?mode=ro", uri=True) as connection:
                if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise SafeError("Decrypted database integrity check failed")
                if name == "nt_msg":
                    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if not {"group_msg_table", "c2c_msg_table"}.issubset(tables):
                        raise SafeError("QQ message schema is unsupported")
                    for table in ("group_msg_table", "c2c_msg_table"):
                        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
                        if not {"40030", "40050", "40033", "40093", "40800"}.issubset(columns):
                            raise SafeError("QQ message columns are unsupported")
        check_wal()
        for name, original in original_stats.items():
            present = (source / (name + ".db")).stat()
            if original != (present.st_size, present.st_mtime_ns):
                raise SafeError("Source changed while refreshing; fully quit QQ and retry")
        generation = uuid.uuid4().hex
        os.replace(ready, generations / generation)
        pointer = work / "CURRENT"
        pointer.write_text(generation, encoding="ascii")
        pointer.chmod(0o600)
        os.replace(pointer, state / "CURRENT")
    return "Refresh completed and validated."


def current(config):
    generation = (config["state_dir"] / "CURRENT").read_text().strip()
    if len(generation) != 32 or any(c not in "0123456789abcdef" for c in generation):
        raise SafeError("Invalid database generation pointer")
    return config["state_dir"] / "generations" / generation
