import json
import os
import secrets
import sqlite3
import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import backup, db
from app.storage import database_lock
from scripts import backup as cli
from scripts.backup_rehearsal import synthetic_database, logical_export

SECRET = secrets.token_urlsafe(32)  # ephemeral test key material; never persisted


@pytest.fixture
def source(tmp_path, monkeypatch):
    import socket
    def blocked(*args, **kwargs):
        pytest.fail("Backup workflow attempted external network access")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    p = tmp_path / "original.db"
    synthetic_database(p)
    return p


@pytest.fixture
def artifact(source):
    output = source.parent / "test.scrubbr-backup"
    backup.create_backup(source, output, SECRET)
    return output


def test_round_trip_full_logical_dataset(source, artifact):
    expected = logical_export(source)
    destination = source.parent / "restored.db"
    manifest = backup.restore_backup(artifact, destination, SECRET)
    assert logical_export(source) == logical_export(destination) == expected
    assert manifest["counts"]["removal_records"] == 5
    assert manifest["counts"]["removal_record_history"] == 10
    assert not manifest["includes_profiles"]
    assert os.stat(destination).st_mode & 0o777 == 0o600
    assert not list(source.parent.glob("*.restore-stage"))


def test_randomized_encrypted_files_no_plaintext_or_credentials(source, artifact):
    second = source.parent / "second.scrubbr-backup"
    (source.parent / "config.toml").write_text('password = "synthetic-config-sentinel"')
    backup.create_backup(source, second, SECRET)
    assert artifact.read_bytes() != second.read_bytes()
    for text in (b"Example Broker Alpha", b"Synthetic corrected note", SECRET.encode(), b"synthetic-config-sentinel"):
        assert text not in artifact.read_bytes()
    assert os.stat(artifact).st_mode & 0o777 == 0o600
    assert backup.decrypt_backup(artifact, SECRET)[1]["assets"] == ["database"]


def test_consistent_snapshot_with_uncheckpointed_wal(source):
    conn = db.connect(source)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("UPDATE removal_records SET notes='Synthetic WAL sentinel' WHERE id=1")
    conn.commit()
    assert source.with_name(source.name + "-wal").stat().st_size > 0
    artifact = source.parent / "wal.scrubbr-backup"
    expected = logical_export(source)
    backup.create_backup(source, artifact, SECRET)
    conn.close()
    dest = source.parent / "wal-restored.db"
    backup.restore_backup(artifact, dest, SECRET)
    assert logical_export(dest) == expected


def test_wrong_password_leaves_existing_destination_untouched(source, artifact):
    expected = logical_export(source)
    with pytest.raises(backup.BackupError, match="Incorrect passphrase") as exc:
        backup.restore_backup(artifact, source, "incorrect synthetic passphrase", replace=True)
    assert SECRET not in str(exc.value) and "Example" not in str(exc.value)
    assert logical_export(source) == expected


@pytest.mark.parametrize("mutation", ["ciphertext", "salt", "nonce", "version", "kdf", "truncated", "magic", "header_size"])
def test_damaged_backup_rejected_without_touching_destination(source, artifact, mutation):
    expected = logical_export(source)
    encoded = bytearray(artifact.read_bytes())
    start = len(backup.MAGIC) + 4
    size = struct.unpack(">I", encoded[len(backup.MAGIC):start])[0]
    if mutation in {"salt", "nonce", "version", "kdf"}:
        header = json.loads(encoded[start:start+size])
        if mutation in {"salt", "nonce"}:
            header[mutation] = "00" + header[mutation][2:]
        elif mutation == "version":
            header["version"] = 999
        else:
            header["kdf"]["memory_cost"] = 2**30
        new = backup._json(header)
        encoded = backup.MAGIC + struct.pack(">I", len(new)) + new + encoded[start+size:]
    elif mutation == "ciphertext":
        encoded[-20] ^= 1
    elif mutation == "truncated":
        encoded = encoded[:start+size+8]
    elif mutation == "magic":
        encoded[0] ^= 1
    else:
        encoded[len(backup.MAGIC):start] = struct.pack(">I", 2**31)
    artifact.write_bytes(encoded)
    with pytest.raises(backup.BackupError):
        backup.restore_backup(artifact, source, SECRET, replace=True, confirmation="REPLACE")
    assert logical_export(source) == expected


def test_refuse_overwrite_existing_backup_and_database(source, artifact):
    original = artifact.read_bytes()
    with pytest.raises(backup.BackupError):
        backup.create_backup(source, artifact, SECRET)
    assert artifact.read_bytes() == original
    expected = logical_export(source)
    with pytest.raises(backup.BackupError, match="already exists"):
        backup.restore_backup(artifact, source, SECRET)
    assert logical_export(source) == expected


def test_failed_atomic_output_has_no_plaintext_or_partial_backup(source, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("Synthetic simulated disk error")
    monkeypatch.setattr(backup.os, "link", fail)
    output = source.parent / "failed.scrubbr-backup"
    with pytest.raises(backup.BackupError):
        backup.create_backup(source, output, SECRET)
    assert not output.exists()
    assert not list(source.parent.glob("*.backup-stage"))


@pytest.mark.parametrize("confirm, recovery_password", [("", SECRET), ("replace", SECRET), ("REPLACE", None)])
def test_replacement_requires_explicit_confirmation_and_snapshot(source, artifact, confirm, recovery_password):
    expected = logical_export(source)
    with pytest.raises(backup.BackupError, match="Replacement requires"):
        backup.restore_backup(artifact, source, SECRET, replace=True, confirmation=confirm,
                              recovery=source.parent / "recovery.scrubbr-backup", recovery_passphrase=recovery_password)
    assert logical_export(source) == expected


def test_recovery_snapshot_failure_aborts_replacement(source, artifact):
    expected = logical_export(source)
    with pytest.raises(backup.BackupError):
        backup.restore_backup(artifact, source, SECRET, replace=True, confirmation="REPLACE",
                              recovery=source.parent / "missing" / "recovery.scrubbr-backup", recovery_passphrase=SECRET)
    assert logical_export(source) == expected


def test_running_scrubbr_lock_prevents_restore(source, artifact):
    expected = logical_export(source)
    with database_lock(source):
        with pytest.raises(backup.BackupError, match="in use"):
            backup.restore_backup(artifact, source, SECRET, replace=True)
    assert logical_export(source) == expected


def test_replace_and_encrypted_recovery_snapshot(source, artifact):
    destination = source.parent / "destination.db"
    synthetic_database(destination)
    conn = db.connect(destination)
    conn.execute("UPDATE removal_records SET notes='Synthetic original destination sentinel'")
    conn.commit()
    conn.close()
    expected = logical_export(destination)
    recovery = source.parent / "recovery.scrubbr-backup"
    backup.restore_backup(artifact, destination, SECRET, replace=True, confirmation="REPLACE",
                          recovery=recovery, recovery_passphrase=SECRET)
    assert logical_export(destination) == logical_export(source)
    recovered = source.parent / "recovered.db"
    backup.restore_backup(recovery, recovered, SECRET)
    assert logical_export(recovered) == expected


@pytest.mark.parametrize("interruption", [OSError, KeyboardInterrupt])
def test_replacement_failure_rolls_back_original(source, artifact, monkeypatch, interruption):
    expected = logical_export(source)
    recovery = source.parent / "recovery.scrubbr-backup"
    real_replace = backup.os.replace
    calls = []
    def fail_first(*args):
        calls.append(args)
        if len(calls) == 1:
            raise interruption("synthetic failure")
        return real_replace(*args)
    monkeypatch.setattr(backup.os, "replace", fail_first)
    with pytest.raises(backup.BackupError, match="original database was restored"):
        backup.restore_backup(artifact, source, SECRET, replace=True, confirmation="REPLACE",
                              recovery=recovery, recovery_passphrase=SECRET)
    assert logical_export(source) == expected
    assert recovery.exists()
    assert not list(source.parent.glob("*.restore-stage"))


def test_double_failure_leaves_encrypted_recovery(source, artifact, monkeypatch):
    def fail(*args):
        raise OSError("Synthetic replacement and rollback failure")
    monkeypatch.setattr(backup.os, "replace", fail)
    recovery = source.parent / "recovery.scrubbr-backup"
    with pytest.raises(backup.BackupError, match="rollback failed"):
        backup.restore_backup(artifact, source, SECRET, replace=True, confirmation="REPLACE",
                              recovery=recovery, recovery_passphrase=SECRET)
    assert backup.decrypt_backup(recovery, SECRET)[1]["counts"]["removal_records"] == 5


@pytest.mark.parametrize("change", ["new_version", "missing_table", "bad_fk", "trigger", "invalid_record", "corrupt"])
def test_schema_and_integrity_validation(source, change):
    c = sqlite3.connect(source)
    if change == "new_version":
        c.execute("PRAGMA user_version=999")
    elif change == "missing_table":
        c.execute("DROP TABLE seen_messages")
    elif change == "bad_fk":
        c.execute("UPDATE removal_records SET broker_id=999 WHERE id=1")
    elif change == "trigger":
        c.execute("CREATE TRIGGER extra AFTER UPDATE ON removal_records BEGIN SELECT 1; END")
    elif change == "invalid_record":
        c.execute("UPDATE removal_records SET recheck_date='not a date'")
    c.commit()
    c.close()
    data = backup.snapshot_database(source)
    if change == "corrupt":
        data = data[:100]
    with pytest.raises(backup.BackupError):
        backup.validate_database(data)


def test_older_tracker_backup_migrates_only_staged_restore(source):
    c = sqlite3.connect(source)
    c.execute("DROP TABLE removal_record_history")
    c.execute("ALTER TABLE removal_records DROP COLUMN broker_id")
    c.execute("ALTER TABLE removal_records DROP COLUMN check_outcome")
    c.execute("PRAGMA user_version=0")
    c.commit()
    c.close()
    before = logical_export(source)
    artifact = source.parent / "old.scrubbr-backup"
    backup.create_backup(source, artifact, SECRET)
    destination = source.parent / "new.db"
    backup.restore_backup(artifact, destination, SECRET)
    assert logical_export(source) == before
    c = db.connect(destination)
    assert c.execute("PRAGMA user_version").fetchone()[0] == 1
    assert len(db.removal_records(c)) == 5
    assert all(db.removal_record_history(c, i)[0]["action"] == "imported_baseline" for i in range(1, 6))
    c.close()


def test_size_bound_and_sidecar_rejection(source, artifact, monkeypatch):
    destination = source.parent / "fresh.db"
    destination.with_name(destination.name+"-wal").write_bytes(b"synthetic sidecar")
    with pytest.raises(backup.BackupError, match="sidecars"):
        backup.restore_backup(artifact, destination, SECRET)
    assert not destination.exists()
    monkeypatch.setattr(backup, "MAX_FILE", 20)
    with pytest.raises(backup.BackupError, match="oversized"):
        backup.decrypt_backup(artifact, SECRET)


def test_cli_passphrase_confirmation_and_safe_failure(source, monkeypatch, capsys):
    values = iter((SECRET, "different"))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: next(values))
    output = source.parent / "cli.scrubbr-backup"
    assert cli.main(["create", "--database", str(source), "--output", str(output)]) == 1
    result = capsys.readouterr().out
    assert SECRET not in result and "do not match" in result
    assert not output.exists()


def test_cli_restore_preview_and_cancel(source, artifact, monkeypatch, capsys):
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: SECRET)
    monkeypatch.setattr("builtins.input", lambda prompt: "CANCEL")
    destination = source.parent / "cancelled.db"
    assert cli.main(["restore", "--input", str(artifact), "--destination", str(destination)]) == 1
    output = capsys.readouterr().out
    assert "record counts" in output and "Includes personal profiles: no" in output
    assert "Synthetic corrected note" not in output and SECRET not in output
    assert not destination.exists()


def test_restored_app_tracker_and_queue_are_manual(source, artifact, monkeypatch):
    from datetime import date
    from bs4 import BeautifulSoup
    from fastapi.testclient import TestClient
    from app import main, removal_history
    destination = source.parent / "workflow.db"
    backup.restore_backup(artifact, destination, SECRET)
    def get_conn():
        c = db.connect(destination)
        db.init_db(c)
        return c
    monkeypatch.setattr(main, "get_conn", get_conn)
    monkeypatch.setattr(main, "DEFAULT_DB_PATH", destination)
    monkeypatch.setattr(main, "load_config", lambda: {})
    def blocked(*args, **kwargs):
        pytest.fail("Restored tracker called an external service")
    monkeypatch.setattr(main.inbox, "poll", blocked)
    monkeypatch.setattr(main.scan_service, "scan_and_persist", blocked)
    monkeypatch.setattr(main.send_service, "send_and_persist", blocked)
    with TestClient(main.app, base_url="http://127.0.0.1:3001") as client:
        with pytest.raises(backup.BackupError, match="in use"):
            backup.restore_backup(artifact, destination, SECRET, replace=True)
        response = client.get("/history")
        assert response.status_code == 200
        assert "Due this week" in response.text and "Example Broker Alpha" in response.text
        page = client.get("/history/1/edit")
        assert "Manual history" in page.text and "Synthetic corrected note" in page.text
        token = BeautifulSoup(page.text, "html.parser").select_one('input[name="csrf_token"]')["value"]
        c = get_conn()
        old = db.get_removal_record(c, 1)
        c.close()
        values = {k: old[k] for k in removal_history.FIELDS} | {"csrf_token": token, "recheck_date": ""}
        assert client.post("/history/1", data=values, headers={"Origin": "http://127.0.0.1:3001"}).status_code == 200
        soup = BeautifulSoup(client.get("/history").text, "html.parser")
        assert not soup.select('.weekly-queue a[href="/history/1/edit"]')
    c = get_conn()
    assert db.all_profiles(c) == []
    assert c.execute("SELECT count(*) FROM requests").fetchone()[0] == 0
    c.close()


def test_profile_presence_disclosed_without_field_contents(source):
    c = db.connect(source)
    c.execute("INSERT INTO profiles(name) VALUES ('Synthetic profile sentinel')")
    c.commit()
    c.close()
    output = source.parent / "profile.scrubbr-backup"
    manifest = backup.create_backup(source, output, SECRET)
    assert manifest["includes_profiles"] and manifest["counts"]["profiles"] == 1
    assert b"Synthetic profile sentinel" not in output.read_bytes()
    dest = source.parent / "profile-restored.db"
    backup.restore_backup(output, dest, SECRET)
    assert logical_export(dest) == logical_export(source)


def test_post_replacement_failure_restores_previous_logical_data(source, artifact, monkeypatch):
    destination = source.parent / "old-state.db"
    synthetic_database(destination)
    c = db.connect(destination)
    c.execute("UPDATE removal_records SET notes='Synthetic previous-state sentinel'")
    c.commit()
    c.close()
    expected = logical_export(destination)
    original_snapshot = backup.snapshot_database
    calls = 0
    def fail_after_replacement(path):
        nonlocal calls
        if str(path) == str(destination):
            calls += 1
            if calls == 2:
                raise backup.BackupError("Synthetic post-replacement validation failure")
        return original_snapshot(path)
    monkeypatch.setattr(backup, "snapshot_database", fail_after_replacement)
    with pytest.raises(backup.BackupError, match="original database was restored"):
        backup.restore_backup(artifact, destination, SECRET, replace=True, confirmation="REPLACE",
                              recovery=source.parent / "recovery.scrubbr-backup", recovery_passphrase=SECRET)
    assert calls == 2
    assert logical_export(destination) == expected


def test_hidden_input_fallback_is_refused(source, monkeypatch, capsys):
    import warnings
    def no_terminal(prompt):
        warnings.warn("Synthetic unavailable terminal", cli.getpass.GetPassWarning)
        pytest.fail("Must not read echoed input")
    monkeypatch.setattr(cli.getpass, "getpass", no_terminal)
    output = source.parent / "no-terminal.scrubbr-backup"
    assert cli.main(["create", "--database", str(source), "--output", str(output)]) == 1
    assert "hidden input is required" in capsys.readouterr().out
    assert not output.exists()


def test_git_ignored_filename_requirements(source, artifact):
    with pytest.raises(backup.BackupError, match="filename"):
        backup.create_backup(source, source.parent / "unsafe-output.json", SECRET)
    with pytest.raises(backup.BackupError, match="destination"):
        backup.restore_backup(artifact, source.parent / "unsafe-output.json", SECRET)


def test_external_sqlite_writer_prevents_replacement(source, artifact):
    expected = logical_export(source)
    external = sqlite3.connect(source)
    external.execute("PRAGMA journal_mode=WAL")
    external.execute("BEGIN IMMEDIATE")
    external.execute("UPDATE removal_records SET notes='Uncommitted synthetic note'")
    try:
        with pytest.raises(backup.BackupError, match="active connections"):
            backup.restore_backup(artifact, source, SECRET, replace=True, confirmation="REPLACE",
                                  recovery=source.parent / "recovery.scrubbr-backup", recovery_passphrase=SECRET)
        assert logical_export(source) == expected
    finally:
        external.rollback()
        external.close()


@pytest.mark.parametrize("invalid", ["schema", "manifest"])
def test_authenticated_but_invalid_payload_does_not_replace(source, artifact, invalid):
    data, manifest = backup.decrypt_backup(artifact, SECRET)
    if invalid == "schema":
        conn = sqlite3.connect(":memory:")
        conn.deserialize(data)
        conn.execute("PRAGMA user_version=999")
        data = conn.serialize()
        conn.close()
    else:
        manifest["counts"]["removal_records"] = 999
    salt, nonce = os.urandom(16), os.urandom(12)
    header = backup._json({"version": 1, "kdf": backup.KDF, "salt": salt.hex(), "nonce": nonce.hex()})
    aad = backup.MAGIC + struct.pack(">I", len(header)) + header
    encoded_manifest = backup._json(manifest)
    payload = struct.pack(">I", len(encoded_manifest)) + encoded_manifest + data
    artifact.write_bytes(aad + AESGCM(backup._key(SECRET, salt)).encrypt(nonce, payload, aad))
    expected = logical_export(source)
    with pytest.raises(backup.BackupError):
        backup.restore_backup(artifact, source, SECRET, replace=True, confirmation="REPLACE")
    assert logical_export(source) == expected
