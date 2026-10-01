"""Browser request protection for the single-user, loopback-only app.

Signed double-submit tokens bind POSTs to the browser's host-only cookie.
The signing key is process-local: restart the server, then reload open forms.
This is CSRF protection, not authentication against other local applications.
"""
import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

COOKIE_NAME = "scrubbr_csrf"
MAX_FORM_BYTES = 1024 * 1024
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class LocalBrowserProtection:
    def __init__(self, app):
        self.app = app
        self.key = secrets.token_bytes(32)

    def _signature(self, nonce):
        return hmac.new(self.key, nonce.encode(), hashlib.sha256).hexdigest()

    def _valid(self, token):
        if not token or len(token) != 129 or not token.isascii():
            return False
        nonce, separator, signature = token.partition(".")
        return bool(separator) and hmac.compare_digest(signature, self._signature(nonce))

    @staticmethod
    def _origin(url):
        try:
            parsed = urlsplit(url)
            return parsed.scheme, parsed.netloc.lower()
        except ValueError:
            return None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        cookie = request.cookies.get(COOKIE_NAME, "")
        valid_cookie = self._valid(cookie)
        nonce = secrets.token_hex(32)
        token = cookie if valid_cookie else f"{nonce}.{self._signature(nonce)}"
        scope.setdefault("state", {})["csrf_token"] = token

        if request.method not in SAFE_METHODS:
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")
            source = origin if origin is not None else referer
            # Missing Origin is permitted for non-browser clients only with a
            # valid CSRF token. Explicit null/foreign origins are always denied.
            if (request.headers.get("sec-fetch-site") == "cross-site"
                    or source is not None and self._origin(source) != self._origin(str(request.url))):
                await PlainTextResponse("Cross-origin request rejected.", status_code=403)(scope, receive, send)
                return
            if not valid_cookie:
                await PlainTextResponse("Reload the page before submitting.", status_code=403)(scope, receive, send)
                return

            chunks, size = [], 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_FORM_BYTES:
                    await PlainTextResponse("Form is too large.", status_code=413)(scope, receive, send)
                    return
                chunks.append(chunk)
            body = b"".join(chunks)

            def replay():
                delivered = False

                async def body_receive():
                    nonlocal delivered
                    if not delivered:
                        delivered = True
                        return {"type": "http.request", "body": body, "more_body": False}
                    return await receive()
                return body_receive

            try:
                async with Request(scope, replay()).form(max_files=0, max_fields=1000) as form:
                    submitted = form.getlist("csrf_token")
            except Exception:
                await PlainTextResponse("Invalid form.", status_code=400)(scope, receive, send)
                return
            if len(submitted) != 1 or not isinstance(submitted[0], str) or not submitted[0].isascii() or not hmac.compare_digest(submitted[0], cookie):
                await PlainTextResponse("Invalid CSRF token. Reload the page.", status_code=403)(scope, receive, send)
                return
            receive = replay()

        async def protected_send(message):
            if message["type"] == "http.response.start":
                headers = list(message["headers"])
                headers.extend([
                    (b"cache-control", b"no-store"),
                    (b"x-frame-options", b"DENY"),
                    (b"x-content-type-options", b"nosniff"),
                    # no-referrer turns same-origin navigation POSTs into Origin:null
                    # in Chromium. Keep local origins while suppressing foreign referrers.
                    (b"referrer-policy", b"same-origin"),
                    (b"content-security-policy", b"frame-ancestors 'none'; form-action 'self'; base-uri 'self'"),
                ])
                if not valid_cookie:
                    response = Response()
                    response.set_cookie(COOKIE_NAME, token, httponly=True, samesite="strict",
                                        secure=request.url.scheme == "https", path="/")
                    headers.extend(response.raw_headers[-1:])
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, protected_send)
