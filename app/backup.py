"""Versioned, authenticated full-SQLite backups. No config, files, or network IO.

AES-256-GCM authenticates the envelope as AAD and encrypts the manifest and DB.
Argon2id derives a disposable key (64 MiB, 3 iterations, 4 lanes).
"""
import json
import os
import sqlite3
import struct
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from . import db, removal_history
from .storage import database_lock, StorageBusy

MAGIC = b"SCRUBBR-BACKUP\x00"
VERSION = 1
MAX_DATABASE = 64 * 1024 * 1024
MAX_FILE = MAX_DATABASE + 8192
KDF = {"name": "argon2id", "memory_cost": 65536, "iterations": 3, "lanes": 4, "length": 32}


class BackupError(Exception):
    """Only non-sensitive, fixed messages may cross the CLI boundary."""


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _key(passphrase, salt):
    if not isinstance(passphrase, str) or not passphrase or len(passphrase) > 1024:
        raise BackupError("Use a non-empty passphrase of at most 1024 characters.")
    try:
        return Argon2id(salt=salt, **{k: v for k, v in KDF.items() if k != "name"}).derive(passphrase.encode())
    except (UnsupportedAlgorithm, MemoryError):
        raise BackupError("Encryption runtime unavailable or insufficient memory. No data was changed.") from None


def _schema(conn):
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    result = {}
    for table in sorted(tables - {"sqlite_sequence"}):
        # Table identifiers come from the schema, never interpolation without quoting.
        quoted = '"' + table.replace('"', '""') + '"'
        columns = [tuple(r)[1:] for r in conn.execute(f"PRAGMA table_info({quoted})")]
        fks = sorted(tuple(r)[2:] for r in conn.execute(f"PRAGMA foreign_key_list({quoted})"))
        unique = []
        for index in conn.execute(f"PRAGMA index_list({quoted})"):
            if index[2]:
                index_name = '"' + index[1].replace('"', '""') + '"'
                unique.append(tuple(r[2] for r in conn.execute(f"PRAGMA index_info({index_name})")))
        result[table] = (columns, fks, sorted(unique))
    return result


def _expected_schema():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    db.init_db(conn)
    try:
        return _schema(conn)
    finally:
        conn.close()


def validate_database(data, migrate=False):
    """Validate only recognized schema shapes; older current-tracker v0 can migrate."""
    if len(data) > MAX_DATABASE or not data.startswith(b"SQLite format 3\x00"):
        raise BackupError("Backup database is invalid or exceeds the 64 MiB limit.")
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    try:
        conn.deserialize(data)
        conn.execute("PRAGMA trusted_schema=OFF")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version not in {0, 1}:
            raise BackupError("Unsupported database schema version.")
        if conn.execute("SELECT count(*) FROM sqlite_master WHERE type IN ('trigger','view')").fetchone()[0]:
            raise BackupError("Unsupported database schema objects.")
        expected = _expected_schema()
        actual = _schema(conn)
        if version == 0:
            legacy = dict(expected)
            legacy.pop("removal_record_history")
            cols, fks, indexes = legacy["removal_records"]
            legacy["removal_records"] = ([c for c in cols if c[0] not in {"broker_id", "check_outcome"}], [], indexes)
            hardening = {k: v for k, v in legacy.items() if k != "removal_records"}
            if actual not in (expected, legacy, hardening):
                raise BackupError("Unsupported older database schema; no data was changed.")
        elif actual != expected:
            raise BackupError("Database schema does not match this Scrubbr version.")
        if conn.execute("PRAGMA integrity_check").fetchall()[0][0] != "ok":
            raise BackupError("Database integrity validation failed.")
        if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise BackupError("Database relationships are invalid.")
        if version == 0 and migrate:
            db.init_db(conn)
        if "removal_records" in _schema(conn):
            for row in conn.execute("SELECT * FROM removal_records"):
                values, errors = removal_history.validate(dict(row) | {
                    "broker_id": str(row["broker_id"] or "") if "broker_id" in row.keys() else ""})
                if errors:
                    raise BackupError("Tracker record validation failed.")
        if "removal_record_history" in _schema(conn):
            for row in conn.execute("SELECT record_id, action, effective_date, snapshot FROM removal_record_history"):
                snapshot = json.loads(row["snapshot"])
                if not isinstance(snapshot, dict) or row["action"] not in {"created", "updated", "imported_baseline"}:
                    raise BackupError("Tracker history validation failed.")
                snapshot["broker_id"] = str(snapshot.get("broker_id") or "")
                if removal_history.validate(snapshot)[1]:
                    raise BackupError("Tracker history validation failed.")
                if row["effective_date"] != snapshot.get("request_date"):
                    raise BackupError("Tracker history dates are inconsistent.")
                if row["record_id"] != snapshot.get("id"):
                    raise BackupError("Tracker history relationships are inconsistent.")
        counts = {table: conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
                  for table in _expected_schema() if table in _schema(conn)}
        return conn.serialize(), counts, version
    except (sqlite3.Error, ValueError, TypeError, KeyError, RecursionError):
        raise BackupError("Backup database validation failed.") from None
    finally:
        conn.close()


def snapshot_database(path):
    """SQLite online backup includes committed WAL state; plaintext stays in memory."""
    path = Path(path).resolve()
    source = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)
    dest = sqlite3.connect(":memory:")
    start = time.monotonic()
    def progress(status, remaining, total):
        if total * page_size > MAX_DATABASE or time.monotonic() - start > 15:
            raise BackupError("Database snapshot exceeded its size or time limit.")
    try:
        page_size = source.execute("PRAGMA page_size").fetchone()[0]
        if source.execute("PRAGMA page_count").fetchone()[0] * page_size > MAX_DATABASE:
            raise BackupError("Database exceeds the 64 MiB backup limit.")
        source.backup(dest, pages=256, progress=progress, sleep=0.01)
        # SQLite rebuilds this private in-memory snapshot into a standalone
        # rollback-journal image. No manual file-header editing or WAL omission.
        dest.execute("PRAGMA journal_mode=OFF")
        dest.execute("VACUUM")
        return dest.serialize()
    finally:
        dest.close()
        source.close()


def encrypt_database(data, passphrase):
    data, counts, schema_version = validate_database(data)
    manifest = {"format": VERSION, "created_at": datetime.now(timezone.utc).isoformat(),
                "schema_version": schema_version, "counts": counts,
                "includes_profiles": bool(counts.get("profiles")),
                "assets": ["database"], "database_bytes": len(data)}
    encoded = _json(manifest)
    salt, nonce = os.urandom(16), os.urandom(12)
    header = _json({"version": VERSION, "kdf": KDF, "salt": salt.hex(), "nonce": nonce.hex()})
    aad = MAGIC + struct.pack(">I", len(header)) + header
    payload = struct.pack(">I", len(encoded)) + encoded + data
    return aad + AESGCM(_key(passphrase, salt)).encrypt(nonce, payload, aad), manifest


def decrypt_backup(path, passphrase):
    try:
        with open(path, "rb") as f:
            encoded = f.read(MAX_FILE + 1)
        if len(encoded) > MAX_FILE or not encoded.startswith(MAGIC):
            raise BackupError("Unsupported or oversized backup file.")
        start = len(MAGIC) + 4
        size = struct.unpack(">I", encoded[len(MAGIC):start])[0]
        if not 1 <= size <= 1024:
            raise BackupError("Invalid backup header.")
        header = json.loads(encoded[start:start + size])
        if set(header) != {"version", "kdf", "salt", "nonce"} or header["version"] != VERSION or header["kdf"] != KDF:
            raise BackupError("Unsupported backup version or encryption parameters.")
        salt, nonce = bytes.fromhex(header["salt"]), bytes.fromhex(header["nonce"])
        if len(salt) != 16 or len(nonce) != 12:
            raise BackupError("Invalid backup encryption parameters.")
        aad = encoded[:start + size]
        payload = AESGCM(_key(passphrase, salt)).decrypt(nonce, encoded[start + size:], aad)
        size = struct.unpack(">I", payload[:4])[0]
        if not 1 <= size <= 4096:
            raise BackupError("Invalid backup manifest.")
        manifest = json.loads(payload[4:4 + size])
        data = payload[4 + size:]
        validated, counts, version = validate_database(data)
        if (set(manifest) != {"format", "created_at", "schema_version", "counts", "includes_profiles", "assets", "database_bytes"}
                or manifest["format"] != VERSION or manifest["counts"] != counts
                or manifest["schema_version"] != version or manifest["database_bytes"] != len(data)
                or manifest["assets"] != ["database"]
                or manifest["includes_profiles"] != bool(counts.get("profiles"))):
            raise BackupError("Backup manifest does not match its database.")
        datetime.fromisoformat(manifest["created_at"])
        return validated, manifest
    except InvalidTag:
        raise BackupError("Incorrect passphrase or damaged backup. No data was changed.") from None
    except (OSError, ValueError, TypeError, KeyError, struct.error, sqlite3.Error, RecursionError):
        raise BackupError("Unable to read or validate backup. No data was changed.") from None


def _publish(path, data, suffix=".backup-stage", replace=False):
    """Restrictive staging, fsync, atomic publish; refuse overwrite by default."""
    path = Path(path)
    fd, stage = tempfile.mkstemp(prefix=".scrubbr-", suffix=suffix, dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if replace:
            os.replace(stage, path)
        else:
            os.link(stage, path)  # atomic fail-if-exists; no overwrite race
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(stage):
            os.unlink(stage)


def create_backup(database, output, passphrase):
    if Path(output).suffix != ".scrubbr-backup":
        raise BackupError("Use a .scrubbr-backup filename so generated backups are excluded from Git.")
    try:
        with database_lock(database):
            encoded, manifest = encrypt_database(snapshot_database(database), passphrase)
        _publish(output, encoded)
        return manifest
    except (OSError, sqlite3.Error, StorageBusy):
        raise BackupError("Unable to create backup; check paths, permissions, and database availability. Existing files were not overwritten.") from None


def restore_backup(backup, destination, passphrase, *, replace=False, confirmation="",
                   recovery=None, recovery_passphrase=None):
    data, manifest = decrypt_backup(backup, passphrase)
    data, _, _ = validate_database(data, migrate=True)
    destination = Path(destination).absolute()
    if destination.suffix not in {".db", ".sqlite", ".sqlite3"}:
        raise BackupError("Use a .db, .sqlite, or .sqlite3 restore destination excluded from Git.")
    try:
        if destination.is_symlink():
            raise BackupError("Restore destination must not be a symbolic link.")
        if destination.resolve() == Path(backup).resolve():
            raise BackupError("Restore destination must differ from the backup.")
        with database_lock(destination, exclusive=True):
            exists = destination.exists()
            if exists and not replace:
                raise BackupError("Destination already exists. Use a fresh isolated destination.")
            sidecars = [Path(str(destination) + s) for s in ("-wal", "-shm", "-journal")]
            if not exists and any(p.exists() for p in sidecars):
                raise BackupError("Destination has SQLite sidecars. Choose a fresh isolated path.")
            if not exists:
                _publish(destination, data, suffix=".restore-stage")
                return manifest
            if confirmation != "REPLACE" or not recovery or not recovery_passphrase:
                raise BackupError("Replacement requires explicit REPLACE confirmation and an encrypted recovery snapshot.")
            if Path(recovery).suffix != ".scrubbr-backup":
                raise BackupError("Recovery snapshots require a .scrubbr-backup filename.")
            if Path(recovery).resolve() in {destination.resolve(), Path(backup).resolve()}:
                raise BackupError("Recovery snapshot must use a distinct fresh path.")
            # Validate old state and publish an encrypted recovery before mutation.
            original = snapshot_database(destination)
            encoded, _ = encrypt_database(original, recovery_passphrase)
            _publish(recovery, encoded)
            decrypt_backup(recovery, recovery_passphrase)  # prove artifact readable first
            conn = sqlite3.connect(destination, timeout=0)
            try:
                if conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] != 0:
                    raise BackupError("Database has active connections; replacement aborted.")
                conn.execute("BEGIN EXCLUSIVE")
                conn.rollback()
            finally:
                conn.close()
            try:
                for sidecar in sidecars:
                    if sidecar.exists():
                        sidecar.unlink()
                _publish(destination, data, suffix=".restore-stage", replace=True)
                validate_database(snapshot_database(destination))
            except BaseException:
                try:
                    _publish(destination, original, suffix=".restore-stage", replace=True)
                except BaseException:
                    raise BackupError("Replacement and rollback failed. Keep the app stopped; restore the encrypted recovery snapshot to a fresh destination.") from None
                raise BackupError("Replacement failed; the original database was restored. Keep the encrypted recovery snapshot.") from None
            return manifest
    except StorageBusy:
        raise BackupError("Database is in use. Stop Scrubbr before restoring.") from None
    except (OSError, sqlite3.Error):
        raise BackupError("Restore failed. Existing data remains intact or recoverable from the encrypted recovery snapshot.") from None
