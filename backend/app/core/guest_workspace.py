"""Signed anonymous browser workspaces; no login or shared editing required."""
import re
import secrets
import time
from http.cookies import SimpleCookie, CookieError

from cryptography.fernet import InvalidToken
from app.core.security import _get_fernet

COOKIE_NAME = "crisp_workspace"
LIFETIME = 24 * 60 * 60


def is_guest():
    from app.core.tenancy import principal_context
    identity = principal_context.get()
    return bool(identity and identity["tenant"].startswith("guest:"))


def enforce_limits(snapshot):
    if is_guest():
        from fastapi import HTTPException
        if len(snapshot.get("assets", [])) > 200 or len(snapshot.get("findings", [])) > 500:
            raise HTTPException(422, "Public workspaces support up to 200 assets and 500 findings")


def browser_workspace(cookie_header):
    cookies = SimpleCookie()
    try:
        cookies.load(cookie_header)
        token = cookies[COOKIE_NAME].value if COOKIE_NAME in cookies else ""
        if token:
            cipher = _get_fernet()
            tenant = cipher.decrypt(token.encode(), ttl=LIFETIME).decode()
            if re.fullmatch(r"guest:[A-Za-z0-9_-]{32}", tenant):
                issued = cipher.extract_timestamp(token.encode())
                return {"tenant": tenant, "subject": "guest-browser", "expires": issued + LIFETIME}, None
    except (InvalidToken, ValueError, UnicodeError, KeyError, CookieError):
        pass
    tenant = "guest:" + secrets.token_urlsafe(24)
    token = _get_fernet().encrypt(tenant.encode()).decode()
    return {"tenant": tenant, "subject": "guest-browser", "expires": int(time.time()) + LIFETIME}, token


def cookie_value(token, secure):
    cookies = SimpleCookie()
    cookies[COOKIE_NAME] = token
    cookies[COOKIE_NAME]["path"] = "/api"
    cookies[COOKIE_NAME]["max-age"] = LIFETIME
    cookies[COOKIE_NAME]["httponly"] = True
    cookies[COOKIE_NAME]["samesite"] = "Strict"
    cookies[COOKIE_NAME]["secure"] = secure
    return cookies.output(header="").strip().encode("ascii")


def remember_workspace(db, identity):
    db.execute('''INSERT INTO guest_sessions(tenant,expires) VALUES(?,?)
        ON CONFLICT(tenant) DO NOTHING''', (identity["tenant"], identity["expires"]))


def cleanup_workspaces(db, now):
    # Only sessions recorded in this table can be removed. Never touch the
    # original owner's workspace or delete append-only audit records.
    db.execute('''DELETE FROM tenant_documents WHERE tenant IN
        (SELECT tenant FROM guest_sessions WHERE expires <= ?)''', (now,))
    db.execute("DELETE FROM guest_sessions WHERE expires <= ?", (now,))
