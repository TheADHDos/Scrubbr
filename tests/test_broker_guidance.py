import copy
import json
import socket

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from app import broker_guidance as g, db, main, removal_history
from scripts import broker_guidance as cli


@pytest.fixture
def catalog():
    return g.load_catalog()


@pytest.fixture
def offline(monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("Manual guidance invoked a network, scan, send or inbox operation")
    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(socket.socket, "connect", fail)
    monkeypatch.setattr(main.scan_service, "scan_and_persist", fail)
    monkeypatch.setattr(main.send_service, "send_and_persist", fail)
    monkeypatch.setattr(main.inbox, "poll", fail)
    return fail


@pytest.fixture
def browser(tmp_path, monkeypatch, offline):
    path = tmp_path / "synthetic.db"
    def get_conn():
        conn = db.connect(path)
        db.init_db(conn)
        return conn
    monkeypatch.setattr(main, "get_conn", get_conn)
    conn = get_conn()
    db.upsert_broker(conn, {"name": "BeenVerified", "category": "people-search"})
    conn.commit()
    conn.close()
    with TestClient(main.app, base_url="http://127.0.0.1:3001", follow_redirects=False) as client:
        yield client


@pytest.fixture
def isolated_catalog(tmp_path, monkeypatch, catalog):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog))
    monkeypatch.setattr(g, "CATALOG", path)
    return path


def test_bundled_source_provenance_and_reviewed_subset(catalog):
    assert catalog["revision"] == "79f63fdc8a9791246af5e10865865aff584d809b"
    assert catalog["license"] == "CC-BY-NC-SA-4.0"
    assert len(catalog["entries"]) == 8
    assert len(g.parse_readme(catalog["source_readme"])) == 45
    assert g.guide_for(catalog, "Whitepages")["flags"] == ["phone", "paid"]
    assert g.guide_for(catalog, "Unknown synthetic site") is None


def test_comparison_is_exact_and_non_destructive(catalog):
    brokers = [{"name": "Whitepages"}, {"name": "Whitepages Premium"}, {"name": "Radaris"}]
    before = copy.deepcopy(brokers)
    result = g.compare(catalog, brokers)
    assert result["matches"] == [{"source_name": "White Pages", "local_names": ["Whitepages"]}]
    assert "Whitepages Premium" in result["local_only"]
    assert result["review_flags"][0]["broker_name"] == "Radaris"
    assert brokers == before


@pytest.mark.parametrize("url", ["javascript:alert(1)", "file:///tmp/test", "mailto:test@example.com", "https://user:secret@example.com", "https://example.com:bad", "https://example.com/bad path"])
def test_unsafe_source_links_are_not_clickable(url):
    text = f"## People Search Sites\n### Example Broker Alpha\nFind [here]({url}).\n## Other\n"
    assert g.parse_readme(text)[0]["links"] == []


def test_parser_keeps_priorities_and_requirements_without_html_rendering():
    entries = g.parse_readme("## People Search Sites\n### 💐 🎫 📞 💰 Example Broker Alpha\n<script>evil()</script> Use [form](https://alpha.example/optout).\n## Other\n### Ignored\n")
    assert len(entries) == 1
    entry = entries[0]
    assert entry["priority"] == "crucial"
    assert entry["flags"] == ["phone", "identity", "paid"]
    assert entry["instructions"].startswith("<script>")
    assert entry["links"] == [{"label": "form", "url": "https://alpha.example/optout"}]


@pytest.mark.parametrize("text", ["Unknown layout", "## People Search Sites\n", "## People Search Sites\n### Same\na\n### Same\nb\n", "x"*(g.MAX_SOURCE+1)])
def test_unsupported_or_duplicate_source_format_rejected(text):
    with pytest.raises(ValueError):
        g.parse_readme(text)


def test_catalog_tampering_detected(isolated_catalog):
    data = json.loads(isolated_catalog.read_text())
    data["entries"][0]["instructions"] = "Synthetic modified instructions"
    isolated_catalog.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        g.load_catalog()


def test_guide_page_requires_no_profile_or_database(browser, monkeypatch, offline):
    monkeypatch.setattr(main, "get_conn", offline)
    page = browser.get("/guidance")
    assert page.status_code == 200 and "EveryJoe" in page.text and "CC BY-NC-SA 4.0" in page.text
    assert browser.get("/guidance/license").status_code == 200
    soup = BeautifulSoup(page.text, "html.parser")
    for link in soup.select('a[target="_blank"]'):
        assert set(link["rel"]) >= {"noopener", "noreferrer"}


def test_select_guide_reuses_broker_or_custom_site_without_writes(browser):
    existing = BeautifulSoup(browser.get("/history/new?guide=beenverified").text, "html.parser")
    assert existing.select_one('[name="broker_id"] option[selected]')["value"] == "1"
    assert existing.select_one('[name="status"] option[selected]')["value"] == "not_requested"
    custom = BeautifulSoup(browser.get("/history/new?guide=everyjoe").text, "html.parser")
    assert custom.select_one('[name="site_name"]')["value"] == "EveryJoe"
    assert custom.select_one('[name="request_date"]')["value"] == ""
    assert custom.select_one('[name="notes"]').text == ""
    assert browser.get("/history/new?guide=unknown").status_code == 404
    conn = main.get_conn()
    assert len(db.all_brokers(conn)) == 1
    assert db.all_profiles(conn) == [] and db.removal_records(conn) == []
    assert conn.execute("SELECT count(*) FROM requests").fetchone()[0] == 0
    conn.close()


def test_guidance_survives_record_save_and_preserves_history(browser):
    conn = main.get_conn()
    values, errors = removal_history.validate({"site_name": "EveryJoe", "status": "confirmed",
                                                "notes": "Synthetic manual confirmation"})
    assert not errors
    record_id = db.save_removal_record(conn, values)
    before = db.get_removal_record(conn, record_id)
    history = db.removal_record_history(conn, record_id)
    conn.close()
    response = browser.get(f"/history/{record_id}/edit")
    assert "Manual opt-out guidance for EveryJoe" in response.text
    assert "Synthetic manual confirmation" in response.text
    conn = main.get_conn()
    assert db.get_removal_record(conn, record_id) == before
    assert db.removal_record_history(conn, record_id) == history
    conn.close()


def test_untrusted_source_prose_is_escaped(browser, monkeypatch, catalog):
    tampered = copy.deepcopy(catalog)
    tampered["entries"][0]["instructions"] = "<script>alert(1)</script>"
    monkeypatch.setattr(g, "load_catalog", lambda: tampered)
    page = browser.get("/guidance")
    soup = BeautifulSoup(page.text, "html.parser")
    assert not soup.select("main script")
    assert "<script>alert(1)</script>" in soup.select_one("main").text


def test_offline_preview_makes_no_changes(isolated_catalog, offline, capsys):
    before = isolated_catalog.read_bytes()
    assert cli.main([]) == 0
    assert isolated_catalog.read_bytes() == before
    assert "Preview only" in capsys.readouterr().out


def test_selection_preview_apply_and_cancel(isolated_catalog, monkeypatch, offline, catalog):
    before = isolated_catalog.read_bytes()
    assert cli.main(["--select", "PimEyes"]) == 0
    assert isolated_catalog.read_bytes() == before
    monkeypatch.setattr("builtins.input", lambda prompt: "CANCEL")
    assert cli.main(["--select", "PimEyes", "--apply"]) == 1
    assert isolated_catalog.read_bytes() == before
    monkeypatch.setattr("builtins.input", lambda prompt: "APPLY " + catalog["revision"])
    assert cli.main(["--select", "PimEyes", "--apply"]) == 0
    updated = g.load_catalog()
    assert len(updated["entries"]) == 9
    assert g.guide_for(updated, "PimEyes")["flags"] == ["identity"]
    assert not list(isolated_catalog.parent.glob(".guidance-*.tmp"))


def test_changed_source_preview_and_pinned_apply(isolated_catalog, monkeypatch, catalog, offline, capsys):
    new_revision = "b" * 40
    readme = catalog["source_readme"].replace("### EveryJoe\n", "### 💐 EveryJoe\n")
    monkeypatch.setattr(cli, "fetch_source", lambda revision: (readme, catalog["source_license"]))
    before = isolated_catalog.read_bytes()
    assert cli.main(["--revision", new_revision]) == 0
    assert isolated_catalog.read_bytes() == before
    assert '"changed": ["EveryJoe"]' in capsys.readouterr().out
    monkeypatch.setattr("builtins.input", lambda prompt: "APPLY " + new_revision)
    assert cli.main(["--revision", new_revision, "--apply"]) == 0
    assert g.load_catalog()["revision"] == new_revision
    assert g.guide_for(g.load_catalog(), "EveryJoe")["priority"] == "crucial"
    assert g.load_catalog()["review_flags"][0]["revision"] == catalog["revision"]


def test_source_removal_requires_explicit_deselection(isolated_catalog, monkeypatch, catalog, offline):
    readme = catalog["source_readme"].replace("### EveryJoe\n", "### Example Renamed Site\n")
    monkeypatch.setattr(cli, "fetch_source", lambda revision: (readme, catalog["source_license"]))
    before = isolated_catalog.read_bytes()
    assert cli.main(["--revision", "b" * 40, "--apply"]) == 1
    assert isolated_catalog.read_bytes() == before
    monkeypatch.setattr("builtins.input", lambda prompt: "APPLY " + "b" * 40)
    assert cli.main(["--revision", "b" * 40, "--deselect", "EveryJoe", "--select", "Example Renamed Site", "--apply"]) == 0
    assert g.guide_for(g.load_catalog(), "EveryJoe") is None


def test_changed_license_aborts(isolated_catalog, monkeypatch, catalog, offline):
    before = isolated_catalog.read_bytes()
    monkeypatch.setattr(cli, "fetch_source", lambda revision: (catalog["source_readme"], catalog["source_license"] + "\nChanged terms"))
    assert cli.main(["--revision", "b" * 40, "--apply"]) == 1
    assert isolated_catalog.read_bytes() == before


def test_disk_failure_keeps_original_catalog(isolated_catalog, monkeypatch, catalog, offline):
    before = isolated_catalog.read_bytes()
    def fail(*args):
        raise OSError("Synthetic disk error")
    monkeypatch.setattr(cli.os, "replace", fail)
    monkeypatch.setattr("builtins.input", lambda prompt: "APPLY " + catalog["revision"])
    assert cli.main(["--select", "PimEyes", "--apply"]) == 1
    assert isolated_catalog.read_bytes() == before
    assert not list(isolated_catalog.parent.glob(".guidance-*.tmp"))


def test_revision_and_download_size_limits(monkeypatch):
    with pytest.raises(ValueError):
        cli.fetch_source("master")
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size): return b"x" * size
    class Opener:
        def open(self, url, timeout):
            assert url.startswith("https://raw.githubusercontent.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List/")
            return Response()
    monkeypatch.setattr(cli.urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(ValueError):
        cli.fetch_source("b" * 40)
