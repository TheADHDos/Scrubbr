"""Explicit GitHub-only update preview/apply; never accesses SQLite or credentials."""
import argparse
import json
import os
import re
import tempfile
import urllib.request
from pathlib import Path

from app import broker_guidance as guides
from app.config import ROOT


def fetch_source(revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("A full lowercase 40-character commit SHA is required.")
    files = []
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, message, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect())
    for name in ("README.md", "LICENSE.md"):
        url = f"https://raw.githubusercontent.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List/{revision}/{name}"
        with opener.open(url, timeout=20) as response:
            data = response.read(guides.MAX_SOURCE + 1)
        if len(data) > guides.MAX_SOURCE:
            raise ValueError("Source exceeds its size limit.")
        files.append(data.decode("utf-8"))
    return files


def source_changes(old, readme):
    before = {entry["id"]: entry for entry in guides.parse_readme(old["source_readme"])}
    after = {entry["id"]: entry for entry in guides.parse_readme(readme)}
    return {"added": [after[key]["name"] for key in sorted(after.keys()-before.keys())],
            "removed": [before[key]["name"] for key in sorted(before.keys()-after.keys())],
            "changed": [after[key]["name"] for key in sorted(before.keys() & after.keys()) if before[key] != after[key]]}


def publish(path, catalog):
    fd, stage = tempfile.mkstemp(prefix=".guidance-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(catalog, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        guides.load_catalog(Path(stage))
        os.replace(stage, path)  # one atomic catalog; source/license/entries stay consistent
    finally:
        if os.path.exists(stage):
            os.unlink(stage)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Preview local guidance or explicitly fetch/apply a pinned GitHub revision")
    parser.add_argument("--revision", help="Fetch this full commit SHA; otherwise work offline")
    parser.add_argument("--select", action="append", default=[], help="Additional exact site name to source-review/import")
    parser.add_argument("--deselect", action="append", default=[], help="Stop showing this guide; does not delete any tracker records")
    parser.add_argument("--apply", action="store_true", help="Preview then require typed confirmation before changing the local dataset")
    args = parser.parse_args(argv)
    try:
        old = guides.load_catalog()
        brokers = json.loads((ROOT / "data" / "brokers.json").read_text())["brokers"]
        print(json.dumps(guides.compare(old, brokers), ensure_ascii=False, indent=2))
        readme, license_text = fetch_source(args.revision) if args.revision else (old["source_readme"], old["source_license"])
        if license_text != old["source_license"]:
            raise ValueError("Source license text changed. Review licensing separately before importing.")
        revision = args.revision or old["revision"]
        changes = source_changes(old, readme)
        print("Source changes:", json.dumps(changes, ensure_ascii=False))
        selected = {entry["id"] for entry in old["entries"]}
        selected.update(guides.normalize(name) for name in args.select)
        for name in args.deselect:
            key = guides.normalize(name)
            if key not in selected:
                raise ValueError("Cannot deselect a guide that is not currently selected.")
            selected.remove(key)
        candidate = guides.make_catalog(readme, license_text, revision, selected, old["review_flags"])
        print("Proposed source-reviewed guides:", json.dumps(candidate["entries"], ensure_ascii=False, indent=2))
        print("Source license: CC BY-NC-SA 4.0. Attribution/noncommercial/share-alike terms apply to imported data.")
        print("This updates local guidance only. No broker IDs, removal records, scan settings, or email settings are changed.")
        if not args.apply:
            print("Preview only. No files changed. Review instructions and use --apply if appropriate.")
            return 0
        if input(f"Type APPLY {revision} to accept this reviewed guidance: ") != f"APPLY {revision}":
            print("Cancelled. No files changed.")
            return 1
        if guides.load_catalog() != old:
            raise ValueError("The catalog changed after preview; rerun the review.")
        publish(guides.CATALOG, candidate)
        print("Local guidance updated. Review the Git diff before committing.")
        return 0
    except (ValueError, OSError, KeyError, TypeError):
        print("Unable to validate/update guidance. Check the source revision, format, license and selected names. No database was changed.")
        return 1
    except (KeyboardInterrupt, EOFError):
        print("Cancelled. No database was changed.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
