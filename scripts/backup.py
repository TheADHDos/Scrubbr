"""Run with python -m scripts.backup; passphrases only through getpass."""
import argparse
import getpass
import warnings
from pathlib import Path

from app.backup import BackupError, create_backup, decrypt_backup, restore_backup
from app.config import DEFAULT_DB_PATH


def passphrase(confirm=False):
    def read(prompt):
        # getpass normally falls back to echoed stdin when no terminal exists.
        # Refuse that fallback before it can read or display a secret.
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                return getpass.getpass(prompt)
        except getpass.GetPassWarning:
            raise BackupError("A terminal with hidden input is required; run this command in Terminal.") from None
    value = read("Passphrase (hidden): ")
    if confirm and read("Confirm passphrase (hidden): ") != value:
        raise BackupError("Passphrases do not match.")
    return value


def preview(manifest, destination=None):
    print(f"Backup version: {manifest['format']}; created: {manifest['created_at']}")
    print(f"Schema: {manifest['schema_version']}; record counts: {manifest['counts']}")
    print("Includes personal profiles:", "yes" if manifest["includes_profiles"] else "no")
    if destination:
        print("Destination:", destination.absolute())
        print("Would replace existing data:", destination.exists())


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local encrypted SQLite backup/restore. No config or credentials included.")
    commands = parser.add_subparsers(dest="command", required=True)
    backup = commands.add_parser("create")
    backup.add_argument("--database", type=Path, default=DEFAULT_DB_PATH)
    backup.add_argument("--output", type=Path, required=True)
    restore = commands.add_parser("restore")
    restore.add_argument("--input", type=Path, required=True)
    restore.add_argument("--destination", type=Path, required=True, help="Use a fresh isolated .db path by default")
    restore.add_argument("--replace-existing", action="store_true")
    restore.add_argument("--recovery-backup", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            print("The entire database is included, including any profiles/email metadata. Configuration and external assets are excluded.")
            print("Losing the passphrase prevents recovery. The active database remains unencrypted.")
            preview(create_backup(args.database, args.output, passphrase(confirm=True)))
            print("Encrypted backup created:", args.output.absolute())
        else:
            secret = passphrase()
            _, manifest = decrypt_backup(args.input, secret)
            preview(manifest, args.destination)
            confirm, recovery_secret = "", None
            if args.destination.exists():
                if not args.replace_existing or not args.recovery_backup:
                    raise BackupError("Existing destination requires --replace-existing and --recovery-backup. Prefer a fresh destination.")
                print("Stop all Scrubbr processes and other SQLite tools for this database first.")
                confirm = input("Type REPLACE to replace the entire database (no merging): ")
                if confirm != "REPLACE":
                    raise BackupError("Replacement cancelled. No data was changed.")
                print("Choose a passphrase for the encrypted recovery snapshot:")
                recovery_secret = passphrase(confirm=True)
            elif input("Type RESTORE to create this isolated database: ") != "RESTORE":
                raise BackupError("Restore cancelled. No data was changed.")
            restore_backup(args.input, args.destination, secret, replace=args.replace_existing,
                           confirmation=confirm, recovery=args.recovery_backup,
                           recovery_passphrase=recovery_secret)
            print("Restore validated and completed. No profile/email configuration was changed.")
        return 0
    except (BackupError, OSError):
        # Never print exception details from SQLite, filesystem or crypto internals.
        import sys
        exc = sys.exception()
        print(str(exc) if isinstance(exc, BackupError) else "Local file operation failed; check paths and permissions.")
        return 1
    except (KeyboardInterrupt, EOFError):
        print("Cancelled. Keep any encrypted recovery snapshot if replacement had begun.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
