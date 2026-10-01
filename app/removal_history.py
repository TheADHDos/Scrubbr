"""Validation for manual removal records; never contacts a website or mailbox."""
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from urllib.parse import urlsplit

STATUSES = {
    "not_requested": "Not requested",
    "requested": "Requested",
    "needs_verification": "Needs verification",
    "confirmed": "Confirmed by broker",
    "verified": "Removal independently verified",
    "reappeared": "Reappeared",
    "rejected": "Rejected",
}
METHODS = {"": "Not recorded", "web_form": "Web form", "email": "Email",
           "phone": "Phone", "mail": "Postal mail", "other": "Other"}
FIELDS = ("site_name", "listing_url", "request_date", "method", "status",
          "evidence_url", "last_checked_date", "follow_up_date", "recheck_date", "notes",
          "broker_id", "check_outcome")
CHECK_OUTCOMES = {"": "Not recorded", "absent": "Listing absent", "present": "Listing present",
                  "inconclusive": "Inconclusive"}
DATE_FIELDS = ("request_date", "last_checked_date", "follow_up_date", "recheck_date")


def validate(data):
    """Return normalized values and field errors, preserving input on failure."""
    values = {field: str(data.get(field, "")).strip() for field in FIELDS}
    errors = {}
    if values["broker_id"] and (not values["broker_id"].isascii()
                               or not values["broker_id"].isdigit()
                               or len(values["broker_id"]) > 19
                               or int(values["broker_id"]) > 9223372036854775807):
        errors["broker_id"] = "Choose a broker from the directory or a custom site."
    if values["check_outcome"] not in CHECK_OUTCOMES:
        errors["check_outcome"] = "Choose a manual check outcome."
    if values["status"] == "verified" and values["check_outcome"] in {"present", "inconclusive"}:
        errors["check_outcome"] = "A present or inconclusive listing cannot be a verified removal."
    if not values["site_name"]:
        errors["site_name"] = "Enter a website name."
    if len(values["site_name"]) > 200:
        errors["site_name"] = "Use 200 characters or fewer."
    if values["status"] not in STATUSES:
        errors["status"] = "Choose a status from the list."
    if values["method"] not in METHODS:
        errors["method"] = "Choose a removal method from the list."
    if len(values["notes"]) > 10000:
        errors["notes"] = "Use 10,000 characters or fewer."
    for field in ("listing_url", "evidence_url"):
        value = values[field]
        if not value:
            continue
        try:
            parsed = urlsplit(value)
            _ = parsed.port  # reject malformed ports
            if (len(value) > 2048 or parsed.scheme not in {"http", "https"}
                    or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or any(c.isspace() or ord(c) < 32 for c in value)):
                raise ValueError
        except ValueError:
            errors[field] = "Use a full http:// or https:// URL without embedded credentials."
    for field in DATE_FIELDS:
        value = values[field]
        if value:
            try:
                if date.fromisoformat(value).isoformat() != value:
                    raise ValueError
            except ValueError:
                errors[field] = "Use a valid date in YYYY-MM-DD format."
    return values, errors


def is_due(value, today):
    return bool(value) and value <= today


def local_today(config, now=None):
    """Configured IANA timezone, or the Mac's local calendar by default."""
    now = now or datetime.now(timezone.utc)
    name = config.get("app", {}).get("timezone", "")
    return now.astimezone(ZoneInfo(name) if name else None).date()


def weekly_actions(records, today):
    """One row per scheduled action, with overdue separate from the next 7 dates."""
    end = today + timedelta(days=7)
    groups = {"overdue": [], "week": []}
    for record in records:
        for kind in ("follow_up", "recheck"):
            value = record[kind + "_date"]
            if not value:
                continue
            due = date.fromisoformat(value)
            group = "overdue" if due < today else "week" if due < end else None
            if group:
                groups[group].append({"record": record, "kind": kind, "date": value})
    for rows in groups.values():
        rows.sort(key=lambda action: (action["date"], action["record"]["id"], action["kind"]))
    return groups
