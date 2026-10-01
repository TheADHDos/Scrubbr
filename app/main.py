"""FastAPI app: profile, broker directory, per-broker action page, dashboard,
and IMAP-driven review queue. Server-rendered HTML, no front-end framework.
"""
import json
import threading
import os
from contextlib import asynccontextmanager
from collections import Counter
from datetime import timedelta
from zoneinfo import ZoneInfoNotFoundError

from fastapi import BackgroundTasks, FastAPI, Form, Request as HttpRequest
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .security import LocalBrowserProtection
from . import removal_history, broker_guidance, property_flags

from . import db, fetcher, inbox, ratelimit, scan_service, scanner, send_service, sender, templater
from .config import ROOT, DEFAULT_DB_PATH, load_config
from .storage import database_lock
from .models import (
    DRIFT_STREAK_THRESHOLD,
    EXPOSURE_ASSUMED,
    EXPOSURE_FOUND,
    EXPOSURE_LIKELY,
    EXPOSURE_NOT_FOUND,
    EXPOSURE_POSSIBLE,
    EXPOSURE_UNKNOWN,
    EXPOSURE_UNREACHABLE,
    STATUS_CONFIRMED,
    STATUS_NEEDS_VERIFICATION,
    STATUS_NOT_STARTED,
    STATUS_REJECTED,
    STATUS_SENT,
    CONTACT_FORM,
    Profile,
    effective_exposure,
    found_networks,
    row_visible,
)

@asynccontextmanager
async def lifespan(app):
    with database_lock(DEFAULT_DB_PATH):
        yield


app = FastAPI(
    lifespan=lifespan,
    title="Scrubbr", docs_url=None, redoc_url=None, openapi_url=None,
    telemetry={"tracing": False, "metrics": False, "logs": False,
               "operation_spans": False, "auto_configure": False},
)
app.add_middleware(LocalBrowserProtection)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"], www_redirect=False)
app.mount("/static", StaticFiles(directory=str(ROOT / "app" / "static")), name="static")
views = Jinja2Templates(directory=str(ROOT / "app" / "templates"))


@app.middleware("http")
async def manual_only_guard(request, call_next):
    path = request.url.path
    if os.environ.get("SCRUBBR_MANUAL_ONLY") == "1" and (
        path in {"/scan/all", "/send/all", "/inbox/poll"}
        or (path.startswith("/scan/") and path.endswith("/auto"))
    ):
        return PlainTextResponse("External actions are disabled in manual-only mode.", status_code=403)
    return await call_next(request)

def asset_version() -> str:
    """Cache-bust the stylesheet: StaticFiles sends no Cache-Control, so without
    this the browser happily serves a stale style.css across server restarts."""
    return str(int((ROOT / "app" / "static" / "style.css").stat().st_mtime))


views.env.globals["asset_version"] = asset_version

STATUS_LABELS = {
    STATUS_NOT_STARTED: "Not started",
    STATUS_SENT: "Sent",
    STATUS_CONFIRMED: "Confirmed",
    STATUS_REJECTED: "Rejected",
    STATUS_NEEDS_VERIFICATION: "Needs verification",
}
views.env.globals["STATUS_LABELS"] = STATUS_LABELS

EXPOSURE_LABELS = {
    EXPOSURE_UNKNOWN: "Unknown",
    EXPOSURE_FOUND: "Found",
    EXPOSURE_NOT_FOUND: "Not found",
    EXPOSURE_POSSIBLE: "Possible match — review",
    EXPOSURE_UNREACHABLE: "Couldn't check",
    EXPOSURE_ASSUMED: "Assumed exposed",
    EXPOSURE_LIKELY: "Likely exposed",
}
views.env.globals["EXPOSURE_LABELS"] = EXPOSURE_LABELS

# Verdicts a user can set by hand, in menu order. `unknown` clears the stored row
# instead of writing one; `possible`/`unreachable` are scan outcomes and `likely` is
# network-derived, so none of them are settable -- only displayable as the current value.
EXPOSURE_CHOICES = [
    EXPOSURE_FOUND, EXPOSURE_ASSUMED, EXPOSURE_NOT_FOUND, EXPOSURE_UNKNOWN,
]
views.env.globals["EXPOSURE_CHOICES"] = EXPOSURE_CHOICES

# Auto-scan rows are grouped by outcome, worst-first, rather than listed alphabetically.
SCAN_GROUP_ORDER = [
    EXPOSURE_FOUND, EXPOSURE_POSSIBLE, EXPOSURE_LIKELY, EXPOSURE_ASSUMED,
    EXPOSURE_UNREACHABLE, EXPOSURE_UNKNOWN, EXPOSURE_NOT_FOUND,
]

_EXPOSURE_RANK = {s: i for i, s in enumerate(SCAN_GROUP_ORDER)}  # worst-first
_STATUS_RANK = {s: i for i, s in enumerate(STATUS_LABELS)}       # pipeline order


def _sort_rows(rows, sort, direction, keys):
    key_fn = keys.get(sort)
    if key_fn is None:
        return rows
    present = [r for r in rows if key_fn(r) is not None]
    absent = [r for r in rows if key_fn(r) is None]
    present.sort(key=key_fn, reverse=direction == "desc")
    return present + absent


def get_conn():
    conn = db.connect()
    db.init_db(conn)
    return conn


def _profile_scope(profile_id: str, profiles: list[Profile]) -> tuple[list[Profile], str]:
    """Resolve a `profile_id` query param ("", "all", or an id) against the
    profile list. Returns (profiles in scope, normalized selector)."""
    if not profiles:
        return [], ""
    if profile_id in ("", "all"):
        return profiles, "all"
    match = [p for p in profiles if str(p.id) == profile_id]
    if match:
        return match, str(match[0].id)
    return profiles, "all"


@app.get("/", response_class=HTMLResponse)
def dashboard(request: HttpRequest, profile_id: str = "", show_all: str = "", sort: str = "", dir: str = ""):
    conn = get_conn()
    try:
        profiles = db.all_profiles(conn)
        if not profiles:
            return RedirectResponse("/profiles", status_code=303)
        brokers = db.all_brokers(conn)
        scope, selected = _profile_scope(profile_id, profiles)
        exposures = {p.id: db.exposures_for_profile(conn, p.id) for p in scope}
        networks = {p.id: found_networks(brokers, exposures[p.id]) for p in scope}
        requests = {p.id: db.ensure_requests(conn, p.id) for p in scope}
        all_rows = [
            (b, p, requests[p.id][b.id],
             effective_exposure(b, exposures[p.id].get(b.id), networks[p.id]))
            for b in brokers for p in scope
        ]
        rows = [row for row in all_rows if row_visible(row[3], row[2].status, bool(show_all))]
        counts = Counter(r.status for _, _, r, _ in rows)
        scope_ids = {p.id for p in scope}
        due = [r for r in db.due_requests(conn) if r.profile_id in scope_ids]
        due_brokers = [(db.get_broker(conn, r.broker_id), db.get_profile(conn, r.profile_id), r) for r in due]
        review = db.review_queue(conn)
        rows.sort(key=lambda x: (x[2].status != STATUS_NEEDS_VERIFICATION, x[0].name.lower(), x[1].name.lower()))
        rows = _sort_rows(rows, sort, dir, {
            "broker": lambda t: t[0].name.casefold(),
            "profile": lambda t: t[1].name.casefold(),
            "category": lambda t: t[0].category.casefold(),
            "exposure": lambda t: _EXPOSURE_RANK[t[3]],
            "status": lambda t: _STATUS_RANK[t[2].status],
            "next_due": lambda t: t[2].next_due,
        })
        cfg = load_config()
        return views.TemplateResponse(request=request, name="dashboard.html", context={
            "request": request, "rows": rows, "counts": counts,
            "hidden": len(all_rows) - len(rows), "show_all": bool(show_all),
            "total": len(brokers), "due_brokers": due_brokers,
            "review_count": len(review), "profile_ready": all(p.full_name for p in profiles),
            "profiles": profiles, "selected_profile": selected, "multi_profile": len(profiles) > 1,
            "imap_enabled": cfg.get("imap", {}).get("enabled", False),
            "sort": sort, "dir": dir,
        })
    finally:
        conn.close()


@app.get("/brokers", response_class=HTMLResponse)
def broker_list(request: HttpRequest, category: str = "", status: str = "",
                exposure: str = "", profile_id: str = "", show_all: str = "",
                name: str = "", sort: str = "", dir: str = ""):
    conn = get_conn()
    try:
        profiles = db.all_profiles(conn)
        if not profiles:
            return RedirectResponse("/profiles", status_code=303)
        brokers = db.all_brokers(conn)
        scope, selected = _profile_scope(profile_id, profiles)
        exposures = {p.id: db.exposures_for_profile(conn, p.id) for p in scope}
        networks = {p.id: found_networks(brokers, exposures[p.id]) for p in scope}
        requests = {p.id: db.ensure_requests(conn, p.id) for p in scope}
        rows = []
        hidden = 0
        for b in brokers:
            if category and b.category != category:
                continue
            if name and name.lower() not in b.name.lower():
                continue
            for p in scope:
                r = requests[p.id][b.id]
                if status and r.status != status:
                    continue
                exp = effective_exposure(b, exposures[p.id].get(b.id), networks[p.id])
                if exposure and exp != exposure:
                    continue
                # An explicit exposure filter overrides the default hiding.
                if not exposure and not row_visible(exp, r.status, bool(show_all)):
                    hidden += 1
                    continue
                rows.append((b, p, r, exp))
        rows = _sort_rows(rows, sort, dir, {
            "broker": lambda t: t[0].name.casefold(),
            "profile": lambda t: t[1].name.casefold(),
            "category": lambda t: t[0].category.casefold(),
            "method": lambda t: t[0].contact_method,
            "difficulty": lambda t: t[0].difficulty,
            "exposure": lambda t: _EXPOSURE_RANK[t[3]],
            "status": lambda t: _STATUS_RANK[t[2].status],
        })
        categories = sorted({b.category for b in brokers})
        return views.TemplateResponse(request=request, name="brokers.html", context={
            "request": request, "rows": rows, "categories": categories,
            "property_flag_for": property_flags.flag_for, "property_labels": property_flags.LABELS,
            "sel_category": category, "sel_status": status, "sel_exposure": exposure,
            "sel_name": name,
            "hidden": hidden, "show_all": bool(show_all),
            "statuses": STATUS_LABELS,
            "profiles": profiles, "selected_profile": selected, "multi_profile": len(profiles) > 1,
            "sort": sort, "dir": dir,
        })
    finally:
        conn.close()


@app.get("/broker/{broker_id}", response_class=HTMLResponse)
def broker_detail(request: HttpRequest, broker_id: int, profile_id: str = ""):
    conn = get_conn()
    try:
        broker = db.get_broker(conn, broker_id)
        if broker is None:
            return RedirectResponse("/brokers", status_code=303)
        profiles = db.all_profiles(conn)
        if not profiles:
            return RedirectResponse("/profiles", status_code=303)
        scope, selected = _profile_scope(profile_id, profiles)
        cfg = load_config()
        prefix = cfg.get("app", {}).get("request_tag_prefix", "PIR")
        brokers = db.all_brokers(conn)
        entries = []
        for p in scope:
            req = db.get_or_create_request(conn, broker_id, p.id)
            rendered = templater.render(broker, p, req.id, prefix)
            to_addr = broker.opt_out_email or ""
            mailto = sender.mailto_link(to_addr, rendered) if to_addr else ""
            exposures = db.exposures_for_profile(conn, p.id)
            ctx = scanner.search_context(p)
            search_link = (scanner.build_search_url(broker.search_url, ctx) if broker.search_url and ctx else "") or ""
            entries.append({
                "profile": p, "req": req, "rendered": rendered, "mailto": mailto,
                "profile_ready": bool(p.full_name),
                "exposure": effective_exposure(broker, exposures.get(broker_id), found_networks(brokers, exposures)),
                "search_link": search_link,
            })
        return views.TemplateResponse(request=request, name="broker_detail.html", context={
            "request": request, "broker": broker, "entries": entries,
            "is_form": broker.contact_method == CONTACT_FORM,
            "profiles": profiles, "selected_profile": selected, "multi_profile": len(profiles) > 1,
        })
    finally:
        conn.close()


@app.post("/broker/{broker_id}/status")
def update_status(broker_id: int, profile_id: int = Form(...), status: str = Form(...), back: str = Form("")):
    conn = get_conn()
    try:
        req = db.get_or_create_request(conn, broker_id, profile_id)
        if status in STATUS_LABELS:
            db.set_status(conn, req.id, status)
        target = _safe_redirect_target(back, f"/broker/{broker_id}?profile_id={profile_id}")
        return RedirectResponse(target, status_code=303)
    finally:
        conn.close()


# profile_id -> {"running": bool, "total": int, "done": int, "results": {broker_id: {...}}}
_bulk_scans: dict[int, dict] = {}
# Guards _bulk_scans/its per-profile state dicts: the background scan thread
# inserts into state["results"] while /scan/status concurrently serializes it,
# which without a lock intermittently raises "dict changed size during iteration".
_bulk_scans_lock = threading.Lock()


def _run_bulk_scan(profile_id: int, broker_ids: list[int]) -> None:
    conn = get_conn()
    state = _bulk_scans[profile_id]
    try:
        profile = db.get_profile(conn, profile_id)
        with fetcher.browser_session():
            for broker_id in broker_ids:
                result = None
                try:
                    broker = db.get_broker(conn, broker_id)
                    if broker is None or profile is None:
                        continue
                    if scan_service.is_cooled_down_for(conn, broker, profile):
                        result = {"status": EXPOSURE_UNREACHABLE, "detail": "Cooling down after rate limiting"}
                    else:
                        outcome = scan_service.scan_and_persist(conn, broker, profile)
                        result = {"status": outcome.status, "detail": outcome.detail}
                except Exception as exc:
                    # One broker's failure must not abandon the rest of the run,
                    # or strand `running: True` forever (which would permanently
                    # disable the "Scan all" button).
                    result = {"status": EXPOSURE_UNREACHABLE, "detail": str(exc)}
                finally:
                    with _bulk_scans_lock:
                        if result is not None:
                            state["results"][broker_id] = result
                        state["done"] += 1
    finally:
        with _bulk_scans_lock:
            state["running"] = False
        conn.close()


@app.get("/scan", response_class=HTMLResponse)
def scan_page(request: HttpRequest, profile_id: str = "", sort: str = "", dir: str = "",
              asort: str = "", adir: str = ""):
    conn = get_conn()
    try:
        profiles = db.all_profiles(conn)
        if not profiles:
            return RedirectResponse("/profiles", status_code=303)
        match = [p for p in profiles if str(p.id) == profile_id]
        profile = match[0] if match else profiles[0]
        brokers = db.all_brokers(conn)
        exposures = db.exposures_for_profile(conn, profile.id)
        networks = found_networks(brokers, exposures)
        ctx = scanner.search_context(profile)
        rescan_after_days = fetcher.scan_settings()["rescan_after_days"]
        searchable = []
        for b in brokers:
            if not b.search_url:
                continue
            exp = exposures.get(b.id)
            snapshot = json.loads(exp.snapshot) if exp and exp.snapshot else None
            searchable.append({
                "broker": b,
                "category": b.category,
                "status": effective_exposure(b, exp, networks),
                "link": (scanner.build_search_url(b.search_url, ctx) if ctx else "") or "",
                "snapshot": snapshot,
                "reason": snapshot.get("reason") if snapshot and exp and exp.status == EXPOSURE_UNREACHABLE else "",
                "source": exp.source if exp else "",
                "stale": ratelimit.is_stale(exp.checked_at if exp else None, rescan_after_days),
                "manual_only": scan_service.is_skipped(b),
                "likely_via": exp.evidence if exp and exp.source == "network" else networks.get(b.network, ""),
                "weak": bool(snapshot) and snapshot.get("page_scope") == scanner.SCOPE_UNSCOPED,
            })
        searchable.sort(key=lambda row: row["broker"].name.lower())
        searchable = _sort_rows(searchable, sort, dir, {
            "broker": lambda r: r["broker"].name.casefold(),
            "category": lambda r: r["category"].casefold(),
        })
        groups = [
            (status, [row for row in searchable if row["status"] == status])
            for status in SCAN_GROUP_ORDER
        ]
        groups = [(status, rows) for status, rows in groups if rows]
        assumed = [
            {
                "broker": b,
                "status": effective_exposure(b, exposures.get(b.id), networks),
                "source": exposures[b.id].source if b.id in exposures else "",
                "likely_via": exposures[b.id].evidence if b.id in exposures and exposures[b.id].source == "network" else networks.get(b.network, ""),
            }
            for b in brokers if not b.search_url
        ]
        assumed = _sort_rows(assumed, asort, adir, {
            "broker": lambda r: r["broker"].name.casefold(),
            "category": lambda r: r["broker"].category.casefold(),
            "exposure": lambda r: _EXPOSURE_RANK[r["status"]],
        })
        drifting = [
            (b, streak, reason) for b, streak, reason in db.drifting_brokers(conn, DRIFT_STREAK_THRESHOLD)
            if not scan_service.is_skipped(b)
        ]
        return views.TemplateResponse(request=request, name="scan.html", context={
            "request": request, "profile": profile, "profiles": profiles,
            "multi_profile": len(profiles) > 1,
            "groups": groups, "assumed": assumed, "ctx_ready": ctx is not None,
            "bulk": _bulk_scans.get(profile.id), "drifting": drifting,
            "sort": sort, "dir": dir, "asort": asort, "adir": adir,
        })
    finally:
        conn.close()


@app.post("/scan/{broker_id}/auto")
def scan_auto(request: HttpRequest, broker_id: int, profile_id: int = Form(...)):
    conn = get_conn()
    try:
        broker = db.get_broker(conn, broker_id)
        profile = db.get_profile(conn, profile_id)
        if broker is None or profile is None or not scan_service.is_auto_scannable(broker):
            outcome = scan_service.ScanOutcome(EXPOSURE_UNREACHABLE, detail="Broker is not auto-scannable")
        else:
            outcome = scan_service.scan_and_persist(conn, broker, profile)
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({
                "outcome": outcome.status, "url": outcome.url, "detail": outcome.detail,
                "snapshot": outcome.snapshot,
            })
        return RedirectResponse(f"/scan?profile_id={profile_id}", status_code=303)
    finally:
        conn.close()


@app.post("/scan/all")
def scan_all(background_tasks: BackgroundTasks, profile_id: int = Form(...)):
    conn = get_conn()
    try:
        profile = db.get_profile(conn, profile_id)
        if profile is None:
            return RedirectResponse("/scan", status_code=303)
        settings = fetcher.scan_settings()
        broker_ids = scan_service.stale_searchable_broker_ids(
            conn, db.all_brokers(conn), profile_id,
            settings["rescan_after_days"], settings["one_per_network"],
        )
        with _bulk_scans_lock:
            existing = _bulk_scans.get(profile_id)
            if not existing or not existing.get("running"):
                _bulk_scans[profile_id] = {"running": True, "total": len(broker_ids), "done": 0, "results": {}}
                background_tasks.add_task(_run_bulk_scan, profile_id, broker_ids)
        return RedirectResponse(f"/scan?profile_id={profile_id}", status_code=303)
    finally:
        conn.close()


@app.get("/scan/status")
def scan_status(profile_id: int):
    with _bulk_scans_lock:
        state = _bulk_scans.get(profile_id)
        if state is None:
            return JSONResponse({"running": False, "total": 0, "done": 0, "results": {}})
        return JSONResponse({**state, "results": dict(state["results"])})


# profile_id -> {"running","total","done","error","results": {broker_id: {...}}}
_bulk_sends: dict[int, dict] = {}
_bulk_sends_lock = threading.Lock()


def _run_bulk_send(profile_id: int, broker_ids: list[int], dry_run: bool) -> None:
    conn = get_conn()
    state = _bulk_sends[profile_id]
    cfg = load_config()
    scfg = sender.SmtpConfig.from_dict(cfg)
    prefix = cfg.get("app", {}).get("request_tag_prefix", "PIR")
    client = None
    try:
        profile = db.get_profile(conn, profile_id)
        if not dry_run:
            client = sender.open_smtp(scfg)
        for i, broker_id in enumerate(broker_ids):
            result = None
            try:
                broker = db.get_broker(conn, broker_id)
                if broker is None or profile is None:
                    continue
                if i:
                    send_service.pace(scfg)
                result = send_service.send_and_persist(conn, broker, profile, prefix, scfg, client)
            except Exception as exc:
                # One broker's failure must not abandon the rest of the run,
                # or strand `running: True` forever.
                result = {"status": "failed", "detail": str(exc)}
            finally:
                with _bulk_sends_lock:
                    if result is not None:
                        state["results"][broker_id] = result
                    state["done"] += 1
    except Exception as exc:
        # Connection/auth failure: one visible error beats N identical failed rows.
        with _bulk_sends_lock:
            state["error"] = str(exc)
    finally:
        if client is not None:
            try:
                client.quit()
            except Exception:
                pass
        with _bulk_sends_lock:
            state["running"] = False
        conn.close()


@app.get("/send", response_class=HTMLResponse)
def send_page(request: HttpRequest, profile_id: str = "", sort: str = "", dir: str = ""):
    conn = get_conn()
    try:
        profiles = db.all_profiles(conn)
        if not profiles:
            return RedirectResponse("/profiles", status_code=303)
        match = [p for p in profiles if str(p.id) == profile_id]
        profile = match[0] if match else profiles[0]
        cfg = load_config()
        smtp_enabled = cfg.get("smtp", {}).get("enabled", False)
        brokers = db.all_brokers(conn)
        ids = send_service.eligible_broker_ids(conn, brokers, profile.id)
        by_id = {b.id: b for b in brokers}
        eligible = [by_id[i] for i in ids]
        eligible.sort(key=lambda b: b.name.lower())
        exposures = db.exposures_for_profile(conn, profile.id)
        networks = found_networks(brokers, exposures)
        form_count = len([b for b in brokers if b.contact_method == CONTACT_FORM])
        from_addr = cfg.get("smtp", {}).get("from_addr") or cfg.get("smtp", {}).get("username", "")
        bulk = _bulk_sends.get(profile.id)
        bulk_results = bulk["results"] if bulk else {}
        eligible = _sort_rows(eligible, sort, dir, {
            "broker": lambda b: b.name.casefold(),
            "category": lambda b: b.category.casefold(),
            "exposure": lambda b: _EXPOSURE_RANK[effective_exposure(b, exposures.get(b.id), networks)],
            "result": lambda b: bulk_results.get(b.id, {}).get("status"),
        })
        return views.TemplateResponse(request=request, name="send.html", context={
            "request": request, "profile": profile, "profiles": profiles,
            "multi_profile": len(profiles) > 1, "smtp_enabled": smtp_enabled,
            "eligible": eligible,
            "exposure_of": lambda b: effective_exposure(b, exposures.get(b.id), networks),
            "form_count": form_count, "from_addr_ok": not from_addr or from_addr in profile.email_list(),
            "bulk": bulk,
            "sort": sort, "dir": dir,
        })
    finally:
        conn.close()


@app.post("/send/all")
def send_all(background_tasks: BackgroundTasks, profile_id: int = Form(...),
             broker_ids: list[int] = Form([]), mode: str = Form("dry_run")):
    conn = get_conn()
    try:
        cfg = load_config()
        if not cfg.get("smtp", {}).get("enabled", False):
            return RedirectResponse("/send?smtp=disabled", status_code=303)
        dry_run = mode != "send"
        selected = set(broker_ids)
        # Never trust posted ids -- re-filter through the same predicate the
        # page rendered from, so a stale page or hand-made POST can't re-send
        # an already-sent request or hit a form-only broker.
        ids = [
            i for i in send_service.eligible_broker_ids(conn, db.all_brokers(conn), profile_id)
            if i in selected
        ]
        if ids:
            with _bulk_sends_lock:
                existing = _bulk_sends.get(profile_id)
                if not existing or not existing.get("running"):
                    _bulk_sends[profile_id] = {
                        "running": True, "total": len(ids), "done": 0,
                        "error": "", "dry_run": dry_run, "results": {},
                    }
                    background_tasks.add_task(_run_bulk_send, profile_id, ids, dry_run)
        return RedirectResponse(f"/send?profile_id={profile_id}", status_code=303)
    finally:
        conn.close()


@app.get("/send/status")
def send_status(profile_id: int):
    with _bulk_sends_lock:
        state = _bulk_sends.get(profile_id)
        if state is None:
            return JSONResponse({
                "running": False, "total": 0, "done": 0, "error": "", "dry_run": False, "results": {},
            })
        return JSONResponse({**state, "results": dict(state["results"])})


def _safe_redirect_target(back: str, default: str) -> str:
    """Only honor `back` as a same-site relative path -- an unvalidated value
    from a form field could otherwise redirect off-site ('//evil.example')."""
    if back.startswith("/") and not back.startswith("//"):
        return back
    return default


@app.post("/scan/{broker_id}/mark")
def scan_mark(broker_id: int, profile_id: int = Form(...), status: str = Form(...), back: str = Form("")):
    conn = get_conn()
    try:
        broker = db.get_broker(conn, broker_id)
        if status == EXPOSURE_UNKNOWN:
            db.clear_exposure(conn, broker_id, profile_id)
            if broker and broker.network:
                db.clear_propagated_in_network(conn, broker.network, profile_id)
        elif status in EXPOSURE_CHOICES:
            db.set_exposure(conn, broker_id, profile_id, status, "manual")
            if broker and broker.network:
                db.propagate_exposure(conn, broker, profile_id, status)
        target = _safe_redirect_target(back, f"/scan?profile_id={profile_id}")
        return RedirectResponse(target, status_code=303)
    finally:
        conn.close()


@app.get("/profiles", response_class=HTMLResponse)
def profiles_page(request: HttpRequest, sort: str = "", dir: str = ""):
    conn = get_conn()
    try:
        profiles = db.all_profiles(conn)
        profiles = _sort_rows(list(profiles), sort, dir, {
            "label": lambda p: p.name.casefold(),
            "full_name": lambda p: p.full_name.casefold() or None,
            "state": lambda p: p.state.casefold() or None,
        })
        return views.TemplateResponse(request=request, name="profiles.html", context={
            "request": request, "profiles": profiles, "sort": sort, "dir": dir,
        })
    finally:
        conn.close()


@app.get("/profiles/new", response_class=HTMLResponse)
def new_profile_page(request: HttpRequest):
    return views.TemplateResponse(request=request, name="profile_form.html", context={
        "request": request, "profile": Profile(), "is_new": True,
    })


@app.post("/profiles")
def create_profile(
    name: str = Form(...), full_name: str = Form(""), aliases: str = Form(""),
    emails: str = Form(""), phones: str = Form(""), addresses: str = Form(""),
    date_of_birth: str = Form(""), state: str = Form(""),
):
    conn = get_conn()
    try:
        db.create_profile(conn, {
            "name": name.strip() or "Me", "full_name": full_name.strip(),
            "aliases": aliases.strip(), "emails": emails.strip(),
            "phones": phones.strip(), "addresses": addresses.strip(),
            "date_of_birth": date_of_birth.strip(), "state": state.strip(),
        })
        return RedirectResponse("/profiles", status_code=303)
    finally:
        conn.close()


@app.get("/profiles/{profile_id}/edit", response_class=HTMLResponse)
def edit_profile_page(request: HttpRequest, profile_id: int):
    conn = get_conn()
    try:
        profile = db.get_profile(conn, profile_id)
        if profile is None:
            return RedirectResponse("/profiles", status_code=303)
        return views.TemplateResponse(request=request, name="profile_form.html", context={
            "request": request, "profile": profile, "is_new": False,
        })
    finally:
        conn.close()


@app.post("/profiles/{profile_id}")
def update_profile(
    profile_id: int, name: str = Form(...), full_name: str = Form(""), aliases: str = Form(""),
    emails: str = Form(""), phones: str = Form(""), addresses: str = Form(""),
    date_of_birth: str = Form(""), state: str = Form(""),
):
    conn = get_conn()
    try:
        db.save_profile(conn, profile_id, {
            "name": name.strip() or "Me", "full_name": full_name.strip(),
            "aliases": aliases.strip(), "emails": emails.strip(),
            "phones": phones.strip(), "addresses": addresses.strip(),
            "date_of_birth": date_of_birth.strip(), "state": state.strip(),
        })
        return RedirectResponse("/profiles", status_code=303)
    finally:
        conn.close()


@app.post("/profiles/{profile_id}/delete")
def delete_profile(profile_id: int):
    conn = get_conn()
    try:
        db.delete_profile(conn, profile_id)
        return RedirectResponse("/profiles", status_code=303)
    finally:
        conn.close()


@app.get("/review", response_class=HTMLResponse)
def review_page(request: HttpRequest):
    conn = get_conn()
    try:
        items = db.review_queue(conn)
        profiles = db.all_profiles(conn)
        enriched = []
        for m in items:
            broker = None
            profile = None
            if m["request_id"]:
                req = db.get_request(conn, m["request_id"])
                if req:
                    broker = db.get_broker(conn, req.broker_id)
                    profile = db.get_profile(conn, req.profile_id)
            enriched.append({**m, "broker": broker, "profile": profile})
        return views.TemplateResponse(request=request, name="review.html", context={
            "request": request, "items": enriched, "statuses": STATUS_LABELS,
            "profiles": profiles, "brokers": db.all_brokers(conn),
        })
    finally:
        conn.close()


@app.post("/review/resolve")
def resolve_review(message_id: str = Form(...), broker_id: int = Form(...), profile_id: int = Form(...), status: str = Form(...)):
    """Manually classify a review-queue message and apply status to its broker."""
    conn = get_conn()
    try:
        if db.get_broker(conn, broker_id) is None:
            # Bogus broker id from the free-text field: don't INSERT a dangling
            # FK (IntegrityError -> 500) or mark the item reviewed.
            return RedirectResponse("/review", status_code=303)
        req = db.get_or_create_request(conn, broker_id, profile_id)
        if status in STATUS_LABELS:
            db.set_status(conn, req.id, status, note="Manual review resolution")
        conn.execute(
            "UPDATE seen_messages SET needs_review = 0 WHERE message_id = ?",
            (message_id,),
        )
        conn.commit()
        return RedirectResponse("/review", status_code=303)
    finally:
        conn.close()


@app.post("/inbox/poll")
def poll_inbox():
    conn = get_conn()
    try:
        cfg = load_config()
        if not cfg.get("imap", {}).get("enabled", False):
            return RedirectResponse("/?imap=disabled", status_code=303)
        icfg = inbox.ImapConfig.from_dict(cfg)
        result = inbox.poll(conn, icfg)
        msg = f"scanned={result.scanned}&advanced={result.advanced}&review={result.review}"
        if result.errors:
            msg += "&error=1"
        return RedirectResponse(f"/?{msg}", status_code=303)
    finally:
        conn.close()


# Manual records are independent of broker automation and personal profiles.
@app.get("/history", response_class=HTMLResponse)
def removal_history_page(request: HttpRequest, status: str = "", due: str = "", impact: str = ""):
    conn = get_conn()
    try:
        records = db.removal_records(conn)
    finally:
        conn.close()
    try:
        local_date = removal_history.local_today(load_config())
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        return PlainTextResponse("Set [app].timezone to a valid IANA timezone, or leave it empty for the Mac's local timezone.", status_code=503)
    today = local_date.isoformat()
    queue = removal_history.weekly_actions(records, local_date)
    counts = {
        "total": len(records),
        "follow_up": sum(removal_history.is_due(r["follow_up_date"], today) for r in records),
        "recheck": sum(removal_history.is_due(r["recheck_date"], today) for r in records),
    }
    selected_impact = impact if impact in property_flags.LABELS else ""
    flags = {r["id"]: property_flags.flag_for(r["site_name"], r["listing_url"]) for r in records}
    selected_status = status if status in removal_history.STATUSES else ""
    selected_due = due if due in {"follow_up", "recheck"} else ""
    rows = [r for r in records if not selected_status or r["status"] == selected_status]
    if selected_due:
        rows = [r for r in rows if removal_history.is_due(r[selected_due + "_date"], today)]
        rows.sort(key=lambda r: (r[selected_due + "_date"], r["site_name"].casefold(), r["id"]))
    if selected_impact:
        rows = [r for r in rows if flags[r["id"]] and flags[r["id"]]["impact"] == selected_impact]
    return views.TemplateResponse(request=request, name="removal_history.html", context={
        "records": rows, "counts": counts, "today": today,
        "statuses": removal_history.STATUSES, "methods": removal_history.METHODS,
        "selected_status": selected_status, "selected_due": selected_due,
        "property_flags": flags, "property_labels": property_flags.LABELS, "selected_impact": selected_impact,
        "queue": queue, "week_end": (local_date + timedelta(days=6)).isoformat(),
    })


def removal_record_form(request, record=None, errors=None, status_code=200):
    values = record if record is not None else dict.fromkeys(removal_history.FIELDS, "")
    if record is None:
        values["status"] = "requested"
    conn = get_conn()
    try:
        brokers = db.all_brokers(conn)
        history = db.removal_record_history(conn, values["id"]) if values.get("id") else []
    finally:
        conn.close()
    catalog = broker_guidance.load_catalog()
    selected_broker = next((b for b in brokers if str(b.id) == values["broker_id"]), None)
    guide = broker_guidance.guide_for(catalog, selected_broker.name if selected_broker else values["site_name"])
    return views.TemplateResponse(request=request, name="removal_record_form.html", context={
        "record": values, "errors": errors or {}, "statuses": removal_history.STATUSES,
        "methods": removal_history.METHODS,
        "brokers": brokers, "history": history, "check_outcomes": removal_history.CHECK_OUTCOMES,
        "property_flag": property_flags.flag_for(selected_broker.name if selected_broker else values["site_name"], values["listing_url"]),
        "property_labels": property_flags.LABELS,
        "guide": guide, "catalog": catalog, "guide_priorities": broker_guidance.PRIORITIES,
        "guide_flags": broker_guidance.FLAGS,
    }, status_code=status_code)


@app.get("/history/new", response_class=HTMLResponse)
def new_removal_record(request: HttpRequest, guide: str = ""):
    if not guide:
        return removal_record_form(request)
    catalog = broker_guidance.load_catalog()
    selected = next((entry for entry in catalog["entries"] if entry["id"] == guide), None)
    if selected is None:
        return PlainTextResponse("Opt-out guide not found.", status_code=404)
    values = dict.fromkeys(removal_history.FIELDS, "")
    values.update(site_name=selected["name"], status="not_requested")
    conn = get_conn()
    try:
        matches = [b for b in db.all_brokers(conn) if broker_guidance.normalize(b.name) == selected["id"]]
        if len(matches) == 1:
            values.update(site_name=matches[0].name, broker_id=str(matches[0].id))
    finally:
        conn.close()
    return removal_record_form(request, values)


@app.get("/properties", response_class=HTMLResponse)
def property_flags_page(request: HttpRequest, impact: str = "", q: str = ""):
    impact = impact if impact in property_flags.LABELS else ""
    q = q[:200]
    return views.TemplateResponse(request=request, name="property_flags.html", context={
        "entries": property_flags.filtered(impact, q), "total": len(property_flags.ENTRIES),
        "labels": property_flags.LABELS, "impact": impact, "query": q, "reviewed": property_flags.REVIEWED,
    })


@app.get("/guidance", response_class=HTMLResponse)
def opt_out_guidance(request: HttpRequest):
    catalog = broker_guidance.load_catalog()
    return views.TemplateResponse(request=request, name="broker_guidance.html", context={
        "catalog": catalog, "guide_priorities": broker_guidance.PRIORITIES,
        "guide_flags": broker_guidance.FLAGS,
    })


@app.get("/guidance/license", response_class=PlainTextResponse)
def guidance_license():
    return PlainTextResponse(broker_guidance.load_catalog()["source_license"])


@app.get("/history/{record_id}/edit", response_class=HTMLResponse)
def edit_removal_record(request: HttpRequest, record_id: int):
    conn = get_conn()
    try:
        record = db.get_removal_record(conn, record_id)
    finally:
        conn.close()
    if record is None:
        return PlainTextResponse("Removal record not found.", status_code=404)
    return removal_record_form(request, record)


async def persist_removal_record(request, record_id=None):
    data, errors = removal_history.validate(await request.form())
    conn = get_conn()
    try:
        if record_id is not None and db.get_removal_record(conn, record_id) is None:
            return PlainTextResponse("Removal record not found.", status_code=404)
        if data["broker_id"] and "broker_id" not in errors:
            broker = db.get_broker(conn, int(data["broker_id"]))
            if broker is None:
                errors["broker_id"] = "Choose an existing broker or a custom site."
            else:
                data["site_name"] = broker.name
                errors.pop("site_name", None)
        if errors:
            if record_id is not None:
                data["id"] = record_id
            return removal_record_form(request, data, errors, status_code=422)
        db.save_removal_record(conn, data, record_id)
    finally:
        conn.close()
    return RedirectResponse("/history?saved=1", status_code=303)


@app.post("/history")
async def create_removal_record(request: HttpRequest):
    return await persist_removal_record(request)


@app.post("/history/{record_id}")
async def update_removal_record(request: HttpRequest, record_id: int):
    return await persist_removal_record(request, record_id)


@app.post("/history/{record_id}/delete")
def delete_removal_record(record_id: int):
    conn = get_conn()
    try:
        if db.get_removal_record(conn, record_id) is None:
            return PlainTextResponse("Removal record not found.", status_code=404)
        db.delete_removal_record(conn, record_id)
    finally:
        conn.close()
    return RedirectResponse("/history?deleted=1", status_code=303)
