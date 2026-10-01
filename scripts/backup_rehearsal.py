"""Synthetic rehearsal only: never opens DEFAULT_DB_PATH or loads config."""
import argparse
import secrets
from datetime import date, timedelta
from pathlib import Path

from app import backup, db, removal_history


def synthetic_database(path):
    if Path(path).exists():
        raise ValueError("Synthetic destination already exists")
    conn = db.connect(path)
    try:
        db.init_db(conn)
        db.upsert_broker(conn, {"name": "Example Broker Alpha", "category": "people_search",
                               "website": "https://alpha.example"})
        conn.commit()
        broker = db.all_brokers(conn)[0]
        today = date.today()
        for i, status in enumerate(("requested", "confirmed", "verified", "needs_verification", "reappeared")):
            values, errors = removal_history.validate({
                "site_name": broker.name if i == 0 else f"Example Custom Site {i}",
                "broker_id": str(broker.id) if i == 0 else "", "status": status,
                "listing_url": f"https://site{i}.example/listing", "request_date": "" if i == 1 else "2026-09-01",
                "recheck_date": (today + timedelta(days=i-1)).isoformat(),
                "notes": "Fictional synthetic record; no personal identifiers."})
            assert not errors
            record = db.save_removal_record(conn, values)
            db.save_removal_record(conn, values | {"notes": "Synthetic corrected note."}, record)
    finally:
        conn.close()


def logical_export(path):
    import sqlite3
    conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        tables = sorted(r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"))
        return {t: sorted(conn.execute(f'SELECT * FROM "{t}"').fetchall(), key=repr) for t in tables}
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Create and verify an isolated synthetic backup rehearsal")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--directory", type=Path)
    mode.add_argument("--compare", type=Path, nargs=2, metavar=("ORIGINAL", "RESTORED"))
    args = parser.parse_args()
    if args.compare:
        if logical_export(args.compare[0]) != logical_export(args.compare[1]):
            raise SystemExit("Datasets differ.")
        print("Every logical table and relationship matches.")
        return
    args.directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    original, restored = args.directory / "original.db", args.directory / "restored.db"
    synthetic_database(original)
    expected = logical_export(original)
    secret = secrets.token_urlsafe(32)  # synthetic only, not printed or persisted
    encrypted = args.directory / "rehearsal.scrubbr-backup"
    backup.create_backup(original, encrypted, secret)
    backup.restore_backup(encrypted, restored, secret)
    assert logical_export(original) == logical_export(restored) == expected
    print("Synthetic round-trip verified: every table, ID, date, status, history row, and relationship matches.")
    print("Original:", original.resolve())
    print("Restored:", restored.resolve())
    print("Rehearsal passphrase was temporary and discarded. Create your own test backup to try interactive prompts.")


if __name__ == "__main__":
    main()
