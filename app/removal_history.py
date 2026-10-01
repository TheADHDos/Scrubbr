"""Validation for manual removal records; never contacts a website or mailbox."""
from datetime import date
from urllib.parse import urlsplit

STATUSES = {
    "not_requested": "Not requested",
    "requested": "Requested",
    "needs_verification": "Needs verification",
    "confirmed": "Removal confirmed",
    "verified": "Removal independently verified",
    "reappeared": "Reappeared",
    "rejected": "Rejected",
}
METHODS = {"": "Not recorded", "web_form": "Web form", "email": "Email",
           "phone": "Phone", "mail": "Postal mail", "other": "Other"}
FIELDS = ("site_name", "listing_url", "request_date", "method", "status",
          "evidence_url", "last_checked_date", "follow_up_date", "recheck_date", "notes")
DATE_FIELDS = ("request_date", "last_checked_date", "follow_up_date", "recheck_date")


def validate(data):
    """Return normalized values and field errors, preserving input on failure."""
    values = {field: str(data.get(field, "")).strip() for field in FIELDS}
    errors = {}
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
