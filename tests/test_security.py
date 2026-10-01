import ssl
import shutil
import socket
import subprocess
import threading

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from app import db, inbox, main, sender
from app.security import COOKIE_NAME, MAX_FORM_BYTES


@pytest.fixture
def browser(tmp_path, monkeypatch):
    def get_conn():
        conn = db.connect(tmp_path / "security.db")
        db.init_db(conn)
        return conn
    monkeypatch.setattr(main, "get_conn", get_conn)
    monkeypatch.setattr(main, "load_config", lambda: {"imap": {"enabled": False}, "smtp": {"enabled": False}})
    with TestClient(main.app, base_url="http://127.0.0.1:3000", follow_redirects=False) as client:
        yield client


def token(browser):
    page = browser.get("/profiles/new")
    value = BeautifulSoup(page.text, "html.parser").select_one('input[name="csrf_token"]')["value"]
    assert value == browser.cookies[COOKIE_NAME]
    return value


@pytest.mark.parametrize("host", ["evil.example", "127.0.0.1.evil.example", "localhost.evil.example"])
def test_foreign_host_rejected(browser, host):
    assert browser.get("/profiles", headers={"Host": host}).status_code == 400


@pytest.mark.parametrize("host", ["127.0.0.1:3000", "localhost:3000"])
def test_loopback_host_allowed(browser, host):
    assert browser.get("/profiles", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://127.0.0.1:4000", "http://localhost:3000", "http://["])
def test_foreign_origin_rejected_even_with_token(browser, origin):
    value = token(browser)
    response = browser.post("/profiles", data={"name": "Test", "csrf_token": value}, headers={"Origin": origin})
    assert response.status_code == 403
    conn = main.get_conn()
    assert db.all_profiles(conn) == []
    conn.close()


@pytest.mark.parametrize("path", ["/profiles", "/profiles/1/delete", "/inbox/poll", "/send/all", "/scan/all", "/scan/1/auto", "/scan/1/mark", "/broker/1/status", "/review/resolve"])
def test_mutation_requires_token(browser, path):
    token(browser)
    assert browser.post(path, data={"profile_id": 1}).status_code == 403


def test_same_origin_form_is_accepted(browser):
    value = token(browser)
    response = browser.post("/profiles", data={"name": "Verification only", "csrf_token": value},
                            headers={"Origin": "http://127.0.0.1:3000"})
    assert response.status_code == 303
    conn = main.get_conn()
    assert len(db.all_profiles(conn)) == 1
    conn.close()


def test_valid_token_without_origin_is_accepted(browser):
    assert browser.post("/inbox/poll", data={"csrf_token": token(browser)}).status_code == 303


def test_foreign_referer_rejected_when_origin_absent(browser):
    assert browser.post("/inbox/poll", data={"csrf_token": token(browser)},
                        headers={"Referer": "https://evil.example/"}).status_code == 403


def test_cross_site_fetch_rejected(browser):
    assert browser.post("/inbox/poll", data={"csrf_token": token(browser)},
                        headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


@pytest.mark.parametrize("value", ["wrong", "é" * 129, "a" * 64 + "." + "b" * 64])
def test_forged_cookie_cannot_authorize_post(browser, value):
    assert browser.post("/inbox/poll", data={"csrf_token": value},
                        headers={"Cookie": f"{COOKIE_NAME}={value}".encode("latin-1")}).status_code == 403


def test_token_cannot_be_reused_in_another_browser(browser):
    value = token(browser)
    with TestClient(main.app, base_url="http://127.0.0.1:3000") as other:
        other.get("/profiles")
        assert other.post("/inbox/poll", data={"csrf_token": value}).status_code == 403


def test_duplicate_and_nonascii_tokens_rejected(browser):
    value = token(browser)
    response = browser.post("/inbox/poll", content=f"csrf_token={value}&csrf_token={value}",
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 403
    assert browser.post("/inbox/poll", data={"csrf_token": "é"}).status_code == 403


def test_oversized_post_rejected(browser):
    value = token(browser)
    response = browser.post("/profiles", data={"csrf_token": value, "name": "x" * MAX_FORM_BYTES})
    assert response.status_code == 413


def test_browser_security_headers_and_cookie(browser):
    response = browser.get("/profiles")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "form-action 'self'" in response.headers["Content-Security-Policy"]
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert "Domain=" not in cookie


def test_all_post_forms_include_token(browser):
    conn = main.get_conn()
    db.upsert_broker(conn, {"name": "Test Broker", "category": "people-search", "search_url": "https://example.test/{first}"})
    profile = db.create_profile(conn, {"name": "Verification", **dict.fromkeys(
        ["full_name", "aliases", "emails", "phones", "addresses", "date_of_birth", "state"], "")})
    db.record_message(conn, {"message_id": "test", "request_id": None, "classification": "unknown",
                            "subject": "Test", "from_addr": "", "received_at": "", "needs_review": 1})
    conn.commit()
    conn.close()
    for path in ["/", "/profiles", "/profiles/new", f"/profiles/{profile.id}/edit", "/brokers", "/broker/1", "/scan", "/send", "/review"]:
        response = browser.get(path)
        assert response.status_code == 200, path
        for form in BeautifulSoup(response.text, "html.parser").select('form[method="post"]'):
            fields = form.select('input[name="csrf_token"]')
            assert len(fields) == 1 and fields[0]["value"] == browser.cookies[COOKIE_NAME], path


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_external_documentation_assets_disabled(browser, path):
    assert browser.get(path).status_code == 404



@pytest.fixture(scope="module")
def tls_server(tmp_path_factory):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("OpenSSL required for offline TLS handshake regression")
    directory = tmp_path_factory.mktemp("tls")
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert), "-days", "1",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   check=True, capture_output=True)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert, key)
    return server, cert


def handshake(context, tls_server, hostname="localhost"):
    # A Unix socket pair exercises real certificate verification without any
    # listening port, SMTP/IMAP provider, email credentials or external traffic.
    server_context, _ = tls_server
    local, remote = socket.socketpair()
    local.settimeout(3)
    remote.settimeout(3)

    def serve():
        try:
            with server_context.wrap_socket(remote, server_side=True):
                pass
        except ssl.SSLError:
            pass  # The client deliberately rejects the test certificate.
        finally:
            remote.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with context.wrap_socket(local, server_hostname=hostname):
            pass
    finally:
        local.close()
        thread.join(timeout=4)
        assert not thread.is_alive()


@pytest.mark.parametrize("hostname", ["localhost", "wrong.test"])
def test_tls_fixture_valid_and_hostname_verification_enforced(tls_server, hostname):
    context = ssl.create_default_context(cafile=str(tls_server[1]))
    if hostname == "localhost":
        handshake(context, tls_server, hostname)
    else:
        with pytest.raises(ssl.SSLCertVerificationError):
            handshake(context, tls_server, hostname)


@pytest.mark.parametrize("implicit_ssl", [False, True])
def test_smtp_verifies_certificates_before_auth(monkeypatch, implicit_ssl, tls_server):
    seen = []

    def verify(context):
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname
        seen.append(context)
        handshake(context, tls_server)

    class Client:
        def starttls(self, *, context):
            verify(context)
        def close(self):
            pass
        def login(self, *args):
            pytest.fail("Credentials must not be sent after a TLS failure")

    def factory(host, port, **kwargs):
        if implicit_ssl:
            verify(kwargs["context"])
        return Client()

    monkeypatch.setattr(sender.smtplib, "SMTP_SSL" if implicit_ssl else "SMTP", factory)
    cfg = sender.SmtpConfig("smtp.test", 465 if implicit_ssl else 587, "u", "p", "u", use_ssl=implicit_ssl)
    with pytest.raises(ssl.SSLCertVerificationError):
        sender.open_smtp(cfg)
    assert len(seen) == 1


def test_imap_verifies_certificates_and_reports_failure(conn, monkeypatch, tls_server):
    def factory(host, port, *, ssl_context):
        assert ssl_context.verify_mode == ssl.CERT_REQUIRED
        assert ssl_context.check_hostname
        handshake(ssl_context, tls_server)
    monkeypatch.setattr(inbox.imaplib, "IMAP4_SSL", factory)
    result = inbox.poll(conn, inbox.ImapConfig("imap.test", 993, "u", "p"))
    assert result.scanned == 0
    assert "CERTIFICATE_VERIFY_FAILED" in result.errors[0]
