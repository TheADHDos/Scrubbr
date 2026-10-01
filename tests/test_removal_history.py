from datetime import date

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from app import db, main, removal_history


@pytest.fixture
def browser(tmp_path, monkeypatch):
    import socket
    def blocked(*args, **kwargs):
        pytest.fail("Manual tracker invoked an external service")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(main.inbox, "poll", blocked)
    monkeypatch.setattr(main.scan_service, "scan_and_persist", blocked)
    monkeypatch.setattr(main.send_service, "send_and_persist", blocked)
    def get_conn():
        conn = db.connect(tmp_path / "history.db")
        db.init_db(conn)
        return conn
    monkeypatch.setattr(main, "get_conn", get_conn)
    with TestClient(main.app, base_url="http://127.0.0.1:3000", follow_redirects=False) as client:
        yield client


def data(**changes):
    return {**dict.fromkeys(removal_history.FIELDS, ""), "site_name": "Example People",
            "status": "requested", "request_date": "2026-09-01", "method": "web_form", **changes}


def post(browser, path, values=None):
    page = browser.get("/history/new")
    token = BeautifulSoup(page.text, "html.parser").select_one('input[name="csrf_token"]')["value"]
    return browser.post(path, data={**(values or {}), "csrf_token": token},
                        headers={"Origin": "http://127.0.0.1:3000"})


def records():
    conn = main.get_conn()
    try:
        return db.removal_records(conn)
    finally:
        conn.close()


def test_empty_history_does_not_require_or_create_profile(browser):
    response = browser.get("/history")
    assert response.status_code == 200
    assert "No removal records yet" in response.text
    assert browser.get("/history/new").status_code == 200
    conn = main.get_conn()
    assert db.all_profiles(conn) == []
    assert conn.execute("SELECT count(*) FROM requests").fetchone()[0] == 0
    conn.close()


def test_record_round_trip_edit_and_delete(browser):
    values = data(listing_url="https://example.test/listing", evidence_url="https://example.test/confirmation",
                  notes="Request submitted manually.\nCheck again later.", last_checked_date="2026-09-02",
                  follow_up_date="2026-10-01", recheck_date="2026-12-01")
    assert post(browser, "/history", values).status_code == 303
    first = records()[0]
    assert all(first[key] == values[key] for key in removal_history.FIELDS)
    updated = {**values, "status": "verified", "notes": "Checked the listing myself.", "follow_up_date": ""}
    assert post(browser, f"/history/{first['id']}", updated).status_code == 303
    second = records()[0]
    assert second["status"] == "verified"
    assert second["created_at"] == first["created_at"]
    assert second["follow_up_date"] == ""
    page = browser.get(f"/history/{first['id']}/edit")
    assert page.status_code == 200 and "Checked the listing myself." in page.text
    assert post(browser, f"/history/{first['id']}/delete").status_code == 303
    assert records() == []
    assert browser.get(f"/history/{first['id']}/edit").status_code == 404


def test_multiple_attempts_for_same_site_preserved(browser):
    post(browser, "/history", data(notes="First request"))
    post(browser, "/history", data(notes="Second request"))
    assert len(records()) == 2


@pytest.mark.parametrize("changes, field", [
    ({"site_name": "   "}, "site_name"),
    ({"site_name": "x" * 201}, "site_name"),
    ({"status": "unknown"}, "status"),
    ({"method": "automatic"}, "method"),
    ({"request_date": "2026-02-30"}, "request_date"),
    ({"last_checked_date": "20261001"}, "last_checked_date"),
    ({"follow_up_date": "2026-W01-1"}, "follow_up_date"),
    ({"recheck_date": "next week"}, "recheck_date"),
    ({"listing_url": "javascript:alert(1)"}, "listing_url"),
    ({"evidence_url": "file:///tmp/private"}, "evidence_url"),
    ({"listing_url": "https://user:password@example.test"}, "listing_url"),
    ({"listing_url": "https://example.test:wrong"}, "listing_url"),
    ({"evidence_url": "https://example.test/ bad"}, "evidence_url"),
    ({"notes": "x" * 10001}, "notes"),
])
def test_invalid_values_preserve_form_and_do_not_save(browser, changes, field):
    response = post(browser, "/history", data(notes="Keep my draft", **changes) if "notes" not in changes else data(**changes))
    assert response.status_code == 422
    soup = BeautifulSoup(response.text, "html.parser")
    assert soup.select_one(f'[name="{field}"]')["aria-invalid"] == "true"
    if "notes" not in changes:
        assert soup.select_one('[name="notes"]').text == "Keep my draft"
    assert records() == []


def test_failed_edit_does_not_replace_previous_record(browser):
    post(browser, "/history", data(notes="Preserved original"))
    record = records()[0]
    response = post(browser, f"/history/{record['id']}", data(status="bad", notes="Invalid edit"))
    assert response.status_code == 422
    assert records()[0]["notes"] == "Preserved original"
    form = BeautifulSoup(response.text, "html.parser").select_one('form[method="post"]')
    assert form["action"] == f"/history/{record['id']}"


def test_due_filters_include_today_exclude_future_and_blank(browser, monkeypatch):
    monkeypatch.setattr(removal_history, "local_today", lambda config: date(2026, 10, 1))
    post(browser, "/history", data(site_name="Overdue", follow_up_date="2026-09-30", status="reappeared"))
    post(browser, "/history", data(site_name="Due today", follow_up_date="2026-10-01", recheck_date="2026-10-01"))
    post(browser, "/history", data(site_name="Future", follow_up_date="2026-10-02", recheck_date="2026-10-02"))
    post(browser, "/history", data(site_name="No date"))
    def sites(url):
        soup = BeautifulSoup(browser.get(url).text, "html.parser")
        return [cell.text for cell in soup.select('tbody td:first-child > strong')]
    assert sites("/history?due=follow_up") == ["Overdue", "Due today"]
    assert sites("/history?due=recheck") == ["Due today"]
    assert sites("/history?due=follow_up&status=requested") == ["Due today"]
    assert sites("/history?status=reappeared") == ["Overdue"]
    assert len(sites("/history?status=invalid&due=invalid")) == 4


@pytest.mark.parametrize("path", ["/history", "/history/1", "/history/1/delete"])
def test_mutations_reject_missing_csrf_and_foreign_origin(browser, path):
    page = browser.get("/history/new")
    token = BeautifulSoup(page.text, "html.parser").select_one('input[name="csrf_token"]')["value"]
    assert browser.post(path, data=data()).status_code == 403
    assert browser.post(path, data={**data(), "csrf_token": token},
                        headers={"Origin": "https://evil.example"}).status_code == 403
    assert records() == []


def test_missing_edit_update_and_delete_are_404(browser):
    assert browser.get("/history/999/edit").status_code == 404
    assert post(browser, "/history/999", data()).status_code == 404
    assert post(browser, "/history/999/delete").status_code == 404


def test_sensitive_text_escaped_and_links_safe(browser):
    post(browser, "/history", data(site_name="<script>alert(1)</script>", notes="<img src=x onerror=alert(1)>",
                                  listing_url="https://example.test/listing"))
    soup = BeautifulSoup(browser.get("/history").text, "html.parser")
    assert soup.select_one('main script') is None and soup.select_one('main img') is None
    assert "<script>alert(1)</script>" in soup.select_one('tbody strong').text
    link = soup.select_one('a[href="https://example.test/listing"]')
    assert set(link["rel"]) >= {"noopener", "noreferrer"}


def test_schema_upgrade_preserves_existing_tables(conn, profile_id):
    conn.execute("DROP TABLE removal_records")
    conn.commit()
    db.init_db(conn)
    assert db.get_profile(conn, profile_id) is not None

    values, errors = removal_history.validate(data())
    assert errors == {}
    record_id = db.save_removal_record(conn, values)
    db.init_db(conn)
    assert db.get_removal_record(conn, record_id)["site_name"] == values["site_name"]
    assert db.get_profile(conn, profile_id) is not None


@pytest.mark.parametrize("status", ["confirmed", "verified"])
def test_historical_entry_unknown_date_and_manual_history(browser, status):
    post(browser, "/history", data(status=status, request_date=""))
    original = records()[0]
    post(browser, f"/history/{original['id']}", data(status="needs_verification", request_date="",
                                                    follow_up_date="2026-10-02"))
    post(browser, f"/history/{original['id']}", data(status=status, request_date="", follow_up_date=""))
    c = main.get_conn()
    history = db.removal_record_history(c, original["id"])
    assert [h["values"]["status"] for h in history] == [status, "needs_verification", status]
    assert all(h["effective_date"] == "" for h in history)
    assert history[1]["values"]["follow_up_date"] == "2026-10-02"
    assert db.get_removal_record(c, original["id"])["request_date"] == ""
    assert db.all_profiles(c) == []
    c.close()


def test_known_broker_entry_and_second_attempt(browser):
    c = main.get_conn()
    db.upsert_broker(c, {"name": "Example Broker Alpha", "category": "people_search"})
    c.commit()
    broker = db.all_brokers(c)[0]
    c.close()
    for _ in range(2):
        assert post(browser, "/history", data(site_name="", broker_id=str(broker.id), status="verified")).status_code == 303
    assert len(records()) == 2
    assert all(r["site_name"] == broker.name and r["broker_id"] == str(broker.id) for r in records())
    assert post(browser, "/history", data(broker_id="9999")).status_code == 422


@pytest.mark.parametrize("outcome", ["present", "inconclusive", "invented"])
def test_unverified_observations_cannot_be_verified(browser, outcome):
    assert post(browser, "/history", data(status="verified", check_outcome=outcome)).status_code == 422
    assert records() == []


def test_old_tracker_migration_retains_ids_and_labels_baseline(conn):
    # Reconstruct the actual previous tracker shape using a disposable database.
    conn.execute("DROP TABLE removal_record_history")
    conn.execute("ALTER TABLE removal_records DROP COLUMN broker_id")
    conn.execute("ALTER TABLE removal_records DROP COLUMN check_outcome")
    conn.execute("PRAGMA user_version=0")
    conn.execute("""INSERT INTO removal_records (id, site_name, status, created_at, updated_at)
                   VALUES (42, 'Example Legacy', 'confirmed', '2026-09-01', '2026-09-01')""")
    conn.commit()
    db.init_db(conn)
    db.init_db(conn)
    assert db.get_removal_record(conn, 42)["status"] == "confirmed"
    history = db.removal_record_history(conn, 42)
    assert len(history) == 1 and history[0]["action"] == "imported_baseline"


def test_manual_only_blocks_external_routes(browser, monkeypatch):
    monkeypatch.setenv("SCRUBBR_MANUAL_ONLY", "1")
    for path in ("/scan/1/auto", "/scan/all", "/send/all", "/inbox/poll"):
        assert post(browser, path).status_code == 403
    assert browser.get("/history").status_code == 200


def test_invalid_timezone_has_clear_failure(browser, monkeypatch):
    monkeypatch.setattr(main, "load_config", lambda: {"app": {"timezone": "Invalid/Timezone"}})
    response = browser.get("/history")
    assert response.status_code == 503 and "valid IANA timezone" in response.text
