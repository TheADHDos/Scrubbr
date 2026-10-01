"""Read-only local opt-out guidance. Rendering/selection never contacts brokers."""
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from .config import ROOT

CATALOG = ROOT / "data" / "sources" / "badbool" / "catalog.json"
UPSTREAM = "https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List"
LICENSE = "CC-BY-NC-SA-4.0"
PRIORITIES = {"crucial": "Crucial", "high": "High priority", "standard": "Standard"}
FLAGS = {"phone": "Phone verification may be required", "identity": "Identity document may be required",
         "paid": "Paid access or removal may be involved"}
ALIASES = {"fastpeoplesearchcom": "fastpeoplesearch", "truepeoplesearchcom": "truepeoplesearch",
           "ancestrycom": "ancestry", "classmatescom": "classmates"}
MAX_SOURCE = 256 * 1024


def normalize(name):
    value = re.sub(r"[^a-z0-9]", "", name.casefold())
    return ALIASES.get(value, value)


def safe_url(value):
    try:
        parsed = urlsplit(value)
        _ = parsed.port
        return (len(value) <= 2048 and parsed.scheme in {"https", "http"} and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None
                and not any(c.isspace() or ord(c) < 32 for c in value))
    except ValueError:
        return False


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_readme(text):
    """Parse only named people-search sections; fail closed on format changes.

    Keep prose as escaped plain text. URLs are separately validated and linked;
    no raw Markdown/HTML rendering, inferred scan selectors, or contact methods.
    """
    if len(text.encode()) > MAX_SOURCE or "## People Search Sites\n" not in text:
        raise ValueError("Unsupported source format or size.")
    section = text.split("## People Search Sites\n", 1)[1].split("\n## ", 1)[0]
    blocks = list(re.finditer(r"^### (.+)\n", section, re.M))
    if not blocks or len(blocks) > 500:
        raise ValueError("Unsupported source entry count.")
    entries = []
    seen = set()
    for i, match in enumerate(blocks):
        heading = match[1]
        name = re.sub(r"[💐☠🎫📞💰\ufe0f]", "", heading).strip()
        key = normalize(name)
        if not key or key in seen or len(name) > 200:
            raise ValueError("Duplicate or invalid source name.")
        seen.add(key)
        body = section[match.end():blocks[i+1].start() if i+1 < len(blocks) else len(section)].strip()
        if not body or len(body) > 10000:
            raise ValueError("Missing or oversized source instructions.")
        links = []
        for label, url in re.findall(r"\[([^\]\n]+)\]\(([^\s)]+)\)", body):
            if safe_url(url) and not any(link["url"] == url for link in links):
                links.append({"label": label, "url": url})
        instructions = re.sub(r"\[([^\]\n]+)\]\(([^\s)]+)\)", r"\1", body)
        entries.append({"id": key, "name": name, "priority": "crucial" if "💐" in heading else "high" if "☠" in heading else "standard",
                        "flags": [key for symbol, key in (("📞", "phone"), ("🎫", "identity"), ("💰", "paid")) if symbol in heading],
                        "instructions": instructions, "links": links,
                        "section_sha256": digest(heading + "\n" + body)})
    return entries


def make_catalog(readme, license_text, revision, selected, review_flags=()):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Use a full lowercase 40-character Git commit SHA.")
    if (len(license_text.encode()) > MAX_SOURCE
            or "Attribution-NonCommercial-ShareAlike 4.0 International" not in license_text):
        raise ValueError("Expected source license is missing or changed; review manually.")
    all_entries = {entry["id"]: entry for entry in parse_readme(readme)}
    missing = set(selected) - all_entries.keys()
    if missing:
        raise ValueError("Selected guide is missing from the source. Review removals or renames; nothing was applied.")
    return {"format": 1, "title": "Big Ass Data Broker Opt-Out List", "creator": "Yael Grauer and contributors",
            "license": LICENSE, "revision": revision, "upstream": UPSTREAM,
            "readme_sha256": digest(readme), "license_sha256": digest(license_text),
            "source_readme": readme, "source_license": license_text,
            "entries": [all_entries[key] for key in sorted(set(selected))], "review_flags": list(review_flags)}


def load_catalog(path=None):
    path = path or CATALOG
    if Path(path).stat().st_size > 2 * MAX_SOURCE + 100000:
        raise ValueError("Catalog exceeds its size limit.")
    catalog = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(catalog, dict) or any(not isinstance(catalog.get(key), str)
                                          for key in ("source_readme", "source_license", "revision")):
        raise ValueError("Invalid source metadata.")
    if (catalog["format"] != 1 or catalog["license"] != LICENSE or catalog["upstream"] != UPSTREAM
            or digest(catalog["source_readme"]) != catalog["readme_sha256"]
            or digest(catalog["source_license"]) != catalog["license_sha256"]):
        raise ValueError("Invalid source provenance.")
    rebuilt = make_catalog(catalog["source_readme"], catalog["source_license"], catalog["revision"],
                           [entry["id"] for entry in catalog["entries"]], catalog["review_flags"])
    if catalog != rebuilt:
        raise ValueError("Catalog does not match the reviewed source.")
    for flag in catalog["review_flags"]:
        if (set(flag) != {"broker_name", "note", "revision"}
                or not isinstance(flag["broker_name"], str) or len(flag["broker_name"]) > 200
                or not isinstance(flag["note"], str) or len(flag["note"]) > 2000
                or not re.fullmatch(r"[0-9a-f]{40}", flag["revision"])):
            raise ValueError("Invalid review flag.")
    return catalog


def guide_for(catalog, name):
    key = normalize(name)
    return next((entry for entry in catalog["entries"] if entry["id"] == key), None)


def compare(catalog, brokers):
    all_entries = parse_readme(catalog["source_readme"])
    source = {entry["id"]: entry for entry in all_entries}
    local = {}
    for broker in brokers:
        # Exact normalized names and a few explicit aliases only; never guess ownership.
        local.setdefault(normalize(broker["name"]), []).append(broker["name"])
    return {"source": {key: catalog[key] for key in ("title", "creator", "revision", "upstream", "license")},
            "source_count": len(source), "local_count": len(brokers),
            "matches": [{"source_name": entry["name"], "local_names": local[key]} for key, entry in source.items() if key in local],
            "source_only": [entry["name"] for key, entry in source.items() if key not in local],
            "local_only": [name for key, names in local.items() if key not in source for name in names],
            "review_flags": [flag for flag in catalog["review_flags"] if normalize(flag["broker_name"]) in local]}
