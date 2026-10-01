"""Curated public property events; no networking or changes to removal outcomes."""
from urllib.parse import urlsplit

from .broker_guidance import normalize

LABELS = {
    "transferred": "Court-ordered domain transfer",
    "related": "Related property — impact unconfirmed",
}
REVIEWED = "2026-10-01"
CASE = "NJ Superior Court, Middlesex County, MID-L-000847-24"
DIAGRAM = "User-supplied Radaris relationship diagram (radaris-mm.png); relationships not independently verified"


def _entry(domain, name, judgment="", source=""):
    return {"domain": domain, "name": name,
            "impact": "transferred" if judgment else "related",
            "judgment_date": judgment, "reviewed_date": REVIEWED,
            "source_url": source, "source_label": "Atlas published transfer notice" if source else DIAGRAM,
            "case": CASE if judgment else ""}


ENTRIES = tuple(sorted([
    *[_entry(domain, name, "2026-08-27", "https://trustoria.com/") for domain, name in (
        ("radaris.com", "Radaris"), ("rehold.com", "Rehold"), ("trustoria.com", "Trustoria"))],
    *[_entry(domain, name, "2026-06-12", "https://centeda.com/") for domain, name in (
        ("centeda.com", "Centeda"), ("clubset.com", "Clubset"), ("comfibook.com", "Comfibook"),
        ("dataveria.com", "Dataveria"), ("difive.com", "DiFive"), ("hudwayglass.com", "Hudwayglass"),
        ("kwold.com", "Kwold"), ("newenglandfacts.com", "NewEnglandFacts"),
        ("pub360.com", "Pub360"), ("rain-street.org", "Rain-street"),
        ("verecor.com", "Verecor"), ("veriforia.com", "Veriforia"))],
    *[_entry(domain, name) for domain, name in (
        ("radaris.net", "Radaris.net"), ("radaris.co.uk", "Radaris.co.uk"),
        ("radaris.biz", "Radaris.biz"), ("radaris.info", "Radaris.info"),
        ("radaris.mobi", "Radaris.mobi"), ("radaris.org", "Radaris.org"),
        ("radaris.us", "Radaris.us"), ("radaris.ru", "Radaris.ru"),
        ("radarisaustralia.com", "Radaris Australia"), ("radaris.asia", "Radaris.asia"),
        ("arrestfacts.com", "Arrestfacts"), ("phoneowner.com", "Phoneowner"),
        ("virty.com", "Virty"), ("publicreports.com", "PublicReports"),
        ("persontrust.com", "Persontrust"), ("bizstanding.com", "Bizstanding"),
        ("homemetry.com", "Homemetry"), ("homeflock.com", "Homeflock"),
        ("projectlab.com", "Projectlab"))],
], key=lambda entry: entry["domain"]))


def flag_for(name, url=""):
    """Exact domain first; a different listing domain never inherits a name flag.

    Strip www only, not arbitrary subdomains. Without a URL use curated exact
    names/domain spellings, never a shared-owner network or substring match.
    """
    if url:
        try:
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return None
            host = parsed.hostname.lower()
            if host.startswith("www."):
                host = host[4:]
            return next((e for e in ENTRIES if e["domain"] == host), None)
        except ValueError:
            return None
    key = normalize(name)
    matches = [e for e in ENTRIES if key in {normalize(e["name"]), normalize(e["domain"])}]
    return matches[0] if len(matches) == 1 else None


def filtered(impact="", query=""):
    query = query.strip().casefold()
    return [e for e in ENTRIES if (not impact or e["impact"] == impact)
            and (not query or query in e["domain"] or query in e["name"].casefold())]
