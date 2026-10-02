"""Public-demo access policy and resource limits, before workspace transactions."""
import hashlib
import logging
import os
import threading
import time
from urllib.parse import unquote, parse_qs

import anyio
from starlette.responses import JSONResponse
from app.core.deployment import production

logger = logging.getLogger(__name__)


def public_demo():
    # Production has no authenticated administration surface. Never expose local
    # editing simply because a deployment variable was omitted or misspelled.
    return production() or os.getenv("CRISP_ACCESS_MODE") == "public_demo"


PUBLIC_GETS = frozenset({
    "/", "/health", "/api/health", "/api/security/capabilities",
    "/api/risk/summary", "/api/risk/entities", "/api/risk/drivers",
    "/api/risk/curve", "/api/risk/explanation", "/api/pareto",
    "/api/health/data-quality", "/api/sensitivity/tornado",
    "/api/sensitivity/convergence", "/api/compliance/summary",
})
PUBLIC_POSTS = frozenset({"/api/simulate", "/api/optimize"})
FRAMEWORKS = frozenset({"sebi", "rbi", "iso", "nist", "cis", "dpdp"})


def public_route(method, path):
    if method in ("GET", "HEAD"):
        if path in PUBLIC_GETS:
            return True
        parts = path.strip("/").split("/")
        if len(parts) >= 3 and parts[:2] == ["api", "compliance"] and parts[2] in FRAMEWORKS:
            return parts[3:] in ([], ["evidence-report"], ["evidence-report", "csv"], ["evidence-report", "html"])
        if len(parts) == 3 and parts[:2] == ["api", "report"] and parts[2] in FRAMEWORKS:
            return True
    return method == "POST" and path in PUBLIC_POSTS


class RateLimiter:
    """Fixed-window quotas. Production counters are transactional and shared.

    Peer addresses come from the ASGI server, never arbitrary forwarding headers.
    A separate global quota caps abuse even when peers share a proxy or rotate.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._buckets = {}

    def check(self, peer, expensive=False, now=None):
        now = int(time.time() if now is None else now)
        expires = (now // 60 + 1) * 60
        peer_key = hashlib.sha256(peer.encode()).hexdigest()
        limits = [("global", int(os.getenv("CRISP_RATE_GLOBAL", "600"))),
                  ("peer:" + peer_key, int(os.getenv("CRISP_RATE_PEER", "120")))]
        if expensive:
            limits += [("compute:global", int(os.getenv("CRISP_RATE_COMPUTE_GLOBAL", "20"))),
                       ("compute:" + peer_key, int(os.getenv("CRISP_RATE_COMPUTE_PEER", "6")))]
        if production():
            from app.core.tenancy import connect, begin_transaction
            db = connect()
            try:
                begin_transaction(db, "__security_limits__")
                db.execute("DELETE FROM security_rate_limits WHERE expires <= ?", (now,))
                allowed = True
                for key, limit in limits:
                    db.execute('''INSERT INTO security_rate_limits(bucket,hits,expires) VALUES(?,1,?)
                        ON CONFLICT(bucket) DO UPDATE SET
                        hits=CASE WHEN security_rate_limits.expires <= ? THEN 1 ELSE security_rate_limits.hits+1 END,
                        expires=?''', (key, expires, now, expires))
                    hits = db.execute("SELECT hits FROM security_rate_limits WHERE bucket=?", (key,)).fetchone()[0]
                    if hits > limit:
                        allowed = False
                        break
                db.commit()
                return allowed, max(1, expires - now)
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
        with self._lock:
            self._buckets = {k: v for k, v in self._buckets.items() if v[1] > now}
            for key, limit in limits:
                hits = self._buckets.get(key, (0, expires))[0] + 1
                self._buckets[key] = (hits, expires)
                if hits > limit:
                    return False, max(1, expires - now)
        return True, 0


class WebSecurityMiddleware:
    def __init__(self, app):
        self.app = app
        self.rate_limiter = RateLimiter()
        self.capacity = anyio.CapacityLimiter(8)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        started = False

        async def secure_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                headers = list(message.get("headers", []))
                policy = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
                    b"cache-control": b"no-store",
                    b"content-security-policy": b"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
                }
                if production():
                    policy[b"strict-transport-security"] = b"max-age=31536000"
                existing = {k.lower() for k, _ in headers}
                headers += [(k, v) for k, v in policy.items() if k not in existing]
                message = {**message, "headers": headers}
            await send(message)

        async def reject(status, detail, retry=None):
            response = JSONResponse({"detail": detail}, status_code=status,
                                    headers={"Retry-After": str(retry)} if retry else None)
            await response(scope, receive, secure_send)

        path = scope.get("path", "")
        method = scope["method"]
        query = scope.get("query_string", b"")
        if len(query) > 4096 or len(path) > 2048:
            return await reject(414, "Request URL exceeds the allowed size")
        # Reject alternate encodings/control characters before policy checks.
        if unquote(path) != path or any(ord(c) < 32 for c in path) or "\\" in path:
            return await reject(400, "Invalid request path")
        if public_demo() and method != "OPTIONS" and not public_route(method, path):
            return await reject(403, "This public demo is read-only; administration is unavailable")
        if method == "OPTIONS":
            return await self.app(scope, receive, secure_send)
        if path in ("/health", "/api/health"):
            return await self.app(scope, receive, secure_send)
        try:
            self.capacity.acquire_nowait()
        except anyio.WouldBlock:
            return await reject(503, "Server busy; retry shortly", 5)
        try:
            if not (os.getenv("CRISP_TESTING") == "1" and not production()):
                peer = (scope.get("client") or ("unknown", 0))[0]
                refresh_requested = any(value.lower() in ("1", "true", "t", "yes", "y", "on")
                                        for value in parse_qs(query.decode("utf-8", errors="replace")).get("refresh", []))
                expensive = refresh_requested or method not in ("GET", "HEAD") or path in (
                    "/api/pareto", "/api/sensitivity/tornado", "/api/sensitivity/convergence")
                try:
                    allowed, retry = await anyio.to_thread.run_sync(lambda: self.rate_limiter.check(peer, expensive))
                except Exception:
                    logger.warning("Rate limit store unavailable")
                    return await reject(503, "Request protection unavailable; retry shortly", 5)
                if not allowed:
                    return await reject(429, "Too many requests; retry after the indicated delay", retry)
            headers = {k.lower(): v for k, v in scope.get("headers", [])}
            max_body = 10 * 1024 * 1024 if headers.get(b"content-type", b"").startswith(b"multipart/form-data") else 512 * 1024
            try:
                declared = int(headers.get(b"content-length", b"0"))
                if declared < 0:
                    raise ValueError
            except ValueError:
                return await reject(400, "Invalid Content-Length")
            if declared > max_body:
                return await reject(413, "Request body exceeds the allowed size")
            if headers.get(b"content-encoding", b"identity") != b"identity":
                return await reject(415, "Compressed request bodies are not supported")
            body = bytearray()
            try:
                with anyio.fail_after(15):
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            return
                        body.extend(message.get("body", b""))
                        if len(body) > max_body:
                            return await reject(413, "Request body exceeds the allowed size")
                        if not message.get("more_body", False):
                            break
            except TimeoutError:
                return await reject(408, "Request body timed out")
            consumed = False

            async def bounded_receive():
                nonlocal consumed
                if not consumed:
                    consumed = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, bounded_receive, secure_send)
        except Exception as exc:
            logger.error("Request failed (%s)", type(exc).__name__)
            if started:
                raise
            await reject(500, "Unable to complete the request")
        finally:
            self.capacity.release()
