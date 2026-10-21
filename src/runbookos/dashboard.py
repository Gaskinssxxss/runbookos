"""Loopback-only authenticated operator dashboard.

The dashboard deliberately reuses IncidentStore for every lifecycle transition. It
does not execute runbooks, SSH, AI, or remediation actions.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

from .errors import ConfigurationError, PolicyDenied
from .incidents import IncidentStore
from .store import SQLiteStore

_PBKDF2_ITERATIONS = 310_000
_SESSION_TTL = 3600
_MAX_AUTH_ATTEMPTS = 5
_AUTH_WINDOW = 300
_MAX_SESSIONS = 256


def _hash_password(password: str, salt: bytes, iterations: int = _PBKDF2_ITERATIONS) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations).hex()


def create_auth_file(path: Path, operator_id: str, password: str) -> None:
    """Create a password verifier without storing the password itself."""
    if not operator_id or len(operator_id) > 128 or any(ord(c) < 32 for c in operator_id):
        raise ValueError("operator identity must be a printable string up to 128 characters")
    if len(password) < 14:
        raise ValueError("dashboard password must contain at least 14 characters")
    path = path.expanduser()
    if path.exists() or path.is_symlink():
        raise FileExistsError(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    salt = secrets.token_bytes(16)
    content = json.dumps(
        {
            "version": 1,
            "operator_id": operator_id,
            "iterations": _PBKDF2_ITERATIONS,
            "salt": salt.hex(),
            "password_hash": _hash_password(password, salt),
        },
        sort_keys=True,
    ).encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


@dataclass(frozen=True)
class AuthConfig:
    operator_id: str
    salt: bytes
    password_hash: str
    iterations: int

    @classmethod
    def load(cls, path: Path) -> AuthConfig:
        path = path.expanduser()
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise ConfigurationError("dashboard auth file is unavailable or is a symlink") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise ConfigurationError(
                    "dashboard auth file must be a regular file owned by this user"
                )
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise ConfigurationError(
                    "dashboard auth file permissions must not grant group/other access"
                )
            with os.fdopen(fd, "r", encoding="utf-8") as stream:
                fd = -1
                raw = stream.read(4097)
            if len(raw) > 4096:
                raise ValueError("auth file too large")
            data = json.loads(raw)
            if set(data) != {"version", "operator_id", "iterations", "salt", "password_hash"}:
                raise ValueError("unexpected auth fields")
            if (
                type(data["version"]) is not int
                or data["version"] != 1
                or type(data["iterations"]) is not int
                or not 100_000 <= data["iterations"] <= 2_000_000
            ):
                raise ValueError("unsupported auth configuration")
            salt = bytes.fromhex(data["salt"])
            digest = data["password_hash"]
            operator_id = data["operator_id"]
            if (
                len(salt) != 16
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or not isinstance(operator_id, str)
                or not operator_id
                or len(operator_id) > 128
                or any(ord(char) < 32 for char in operator_id)
            ):
                raise ValueError("invalid auth configuration")
            return cls(operator_id, salt, digest, data["iterations"])
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            TypeError,
            KeyError,
            ValueError,
        ) as exc:
            raise ConfigurationError("invalid dashboard auth file") from exc
        finally:
            if fd >= 0:
                os.close(fd)

    def verify(self, password: str) -> bool:
        candidate = _hash_password(password, self.salt, self.iterations)
        return hmac.compare_digest(candidate, self.password_hash)


@dataclass
class Session:
    operator_id: str
    csrf: str
    expires_at: float


class DashboardState:
    def __init__(self, database: Path, auth: AuthConfig) -> None:
        self.incidents = IncidentStore(SQLiteStore(database))
        self.auth = auth
        self.lock = threading.Lock()
        self.sessions: dict[str, Session] = {}
        self.attempts: dict[str, list[float]] = {}

    def authenticate(self, remote: str, password: str) -> str | None:
        now = time.monotonic()
        with self.lock:
            attempts = [t for t in self.attempts.get(remote, []) if now - t < _AUTH_WINDOW]
            if len(attempts) >= _MAX_AUTH_ATTEMPTS:
                self.attempts[remote] = attempts
                return None
            attempts.append(now)
            self.attempts[remote] = attempts
        if not self.auth.verify(password):
            return None
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions = {
                key: value for key, value in self.sessions.items() if value.expires_at > now
            }
            if len(self.sessions) >= _MAX_SESSIONS:
                return None
            self.sessions[token] = Session(
                self.auth.operator_id, secrets.token_urlsafe(24), now + _SESSION_TTL
            )
            self.attempts.pop(remote, None)
        return token

    def session(self, token: str | None) -> Session | None:
        if not token:
            return None
        with self.lock:
            item = self.sessions.get(token)
            if item and item.expires_at > time.monotonic():
                return item
            self.sessions.pop(token, None)
        return None


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _bounded_text(value: object, limit: int = 240) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _page(title: str, body: str) -> bytes:
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{_e(title)} · RunbookOS</title>"
        "<style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#182230}"
        "a{color:#175cd3}table{border-collapse:collapse;width:100%}td,th{padding:.55rem;border-bottom:1px solid #ddd;text-align:left}"
        "input,select,textarea,button{font:inherit;padding:.5rem;margin:.25rem 0}article{border:1px solid #ddd;padding:1rem;margin:1rem 0}"
        ".muted{color:#667085}.critical,.error{color:#b42318}</style><body>"
        f"<header><a href='/'>RunbookOS incidents</a></header><h1>{_e(title)}</h1>{body}</body></html>"
    ).encode()


class _Server(ThreadingHTTPServer):
    # Reuse a recently closed loopback listener, but never use SO_REUSEPORT or
    # take over an active listener. Non-daemon request threads are joined by
    # server_close; request sockets have a timeout so shutdown remains bounded.
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, address, handler):
        self.request_slots = threading.BoundedSemaphore(16)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        request.settimeout(10)
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()


def serve_dashboard(
    database: Path, auth_file: Path, host: str = "127.0.0.1", port: int = 8780
) -> None:
    if host != "127.0.0.1":
        raise ValueError("dashboard host is fixed to 127.0.0.1")
    auth = AuthConfig.load(auth_file)
    state = DashboardState(database, auth)

    class Handler(BaseHTTPRequestHandler):
        server_version = "RunbookOS-Dashboard"
        sys_version = ""

        def log_message(self, _format: str, *args: object) -> None:
            # URLs and request bodies may contain untrusted input; keep access logs quiet.
            return

        def send_page(
            self, status: int, title: str, body: str, headers: dict[str, str] | None = None
        ) -> None:
            payload = _page(title, body)
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
            )
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)

        def cookie(self) -> str | None:
            for part in self.headers.get("Cookie", "").split(";"):
                name, sep, value = part.strip().partition("=")
                if sep and name == "runbookos_session":
                    return value
            return None

        def require_session(self) -> Session | None:
            return state.session(self.cookie())

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/login":
                self.send_page(
                    200,
                    "Operator login",
                    "<form method='post' action='/login'><label>Password <input type='password' name='password' required autocomplete='current-password'></label><button>Sign in</button></form>",
                )
                return
            session = self.require_session()
            if session is None:
                self.send_page(
                    303,
                    "Authentication required",
                    "<p>Sign in to view operational records.</p>",
                    {"Location": "/login"},
                )
                return
            if parsed.path == "/":
                query = parse_qs(parsed.query)
                status = query.get("status", [""])[0] or None
                severity = query.get("severity", [""])[0]
                target = query.get("target", [""])[0]
                try:
                    rows = state.incidents.list(status=status, limit=1000)
                except ValueError:
                    rows = state.incidents.list(limit=1000)
                if severity:
                    rows = [row for row in rows if row["severity"] == severity]
                if target:
                    rows = [row for row in rows if row["target_alias"] == target]
                valid, count = state.incidents.store.verify_audit_chain()
                audit = f"VALID · {count} events" if valid else f"INVALID · verified prefix {count}"
                table = (
                    "".join(
                        "<tr>"
                        + "".join(
                            f"<td>{_e(row[key])}</td>"
                            for key in (
                                "severity",
                                "status",
                                "target_alias",
                                "service",
                                "updated_at",
                            )
                        )
                        + f"<td>{_e(row.get('source', 'unknown'))}</td>"
                        + f"<td>{_e(_bounded_text(row.get('summary', '')))}</td>"
                        + f"<td><a href='/incidents/{quote(row['incident_id'])}'>Open</a></td></tr>"
                        for row in rows
                    )
                    or "<tr><td colspan='8'>No matching incidents.</td></tr>"
                )
                filters = f"<form><select name='status'><option value=''>All states</option>{''.join(f'<option {_selected(status, item)}>{item}</option>' for item in ('NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'CLOSED'))}</select><select name='severity'><option value=''>All severity</option>{''.join(f'<option {_selected(severity, item)}>{item}</option>' for item in ('info', 'warning', 'error', 'critical'))}</select><input name='target' value='{_e(target)}' placeholder='Target alias'><button>Filter</button></form>"
                body = f"<p>Audit chain: <strong>{_e(audit)}</strong></p>{filters}<table><thead><tr><th>Severity</th><th>Status</th><th>Target</th><th>Service</th><th>Updated</th><th>Source</th><th>Summary</th><th></th></tr></thead><tbody>{table}</tbody></table><form method='post' action='/logout'><input type='hidden' name='csrf' value='{_e(session.csrf)}'><button>Sign out</button></form>"
                self.send_page(200, "Incident queue", body)
                return
            if parsed.path.startswith("/incidents/"):
                incident_id = unquote(parsed.path.removeprefix("/incidents/"))
                try:
                    detail = state.incidents.show(incident_id)
                except ConfigurationError:
                    self.send_page(
                        404, "Incident not found", "<p>No incident with that identifier.</p>"
                    )
                    return
                links = "".join(
                    f"<li>{_e(alert['source'])} · {_e(alert['alert_id'])} · {_e(alert['event_timestamp'])}<br><span class='muted'>{_e(alert['correlation_reason'])}</span></li>"
                    for alert in detail["alerts"]
                )
                event_rows = []
                for event in detail["events"]:
                    try:
                        event_details = json.loads(event["details_json"])
                    except (json.JSONDecodeError, TypeError):
                        event_details = {}
                    if not isinstance(event_details, dict):
                        event_details = {}
                    from_status = event_details.get("from_status", event.get("from_status") or "—")
                    to_status = event_details.get("to_status", event.get("to_status") or "—")
                    event_rows.append(
                        f"<tr><td>{_e(event['created_at'])}</td><td>{_e(event['event_type'])}</td>"
                        f"<td>{_e(event['actor'])}</td><td>{_e(event['reason'])}</td>"
                        f"<td>{_e(event_details.get('evidence_status', '—'))}</td>"
                        f"<td>{_e(from_status)} → {_e(to_status)}</td></tr>"
                    )
                events = "".join(event_rows)
                investigations = []
                for item in detail["investigations"]:
                    investigations.append(
                        f"<li>Investigation {_e(item['investigation_id'])}; executions: {_e(', '.join(item['execution_ids']) or 'none')}; evidence refs: {_e(', '.join(item['evidence_refs']) or 'none')} <span class='muted'>(verified references only; evidence payload omitted)</span></li>"
                    )
                remediation_rows = []
                for item in detail["remediation_plans"]:
                    executions = (
                        ", ".join(
                            f"{run['execution_id']} · {run['outcome'] or run['status']} · "
                            f"{run['finished_at'] or run['started_at']}"
                            for run in item["executions"]
                        )
                        or "none"
                    )
                    warning = (
                        "<strong>UNKNOWN outcome: inspect target independently before considering another action.</strong>"
                        if item["unknown_outcome_warning"]
                        else ""
                    )
                    if item["plan_integrity"] != "valid":
                        warning += " <strong>Stored plan integrity mismatch.</strong>"
                    preflight = (
                        ", ".join(
                            f"{check['step_id']} ({check['action_id']}, {check['assertion_count']} assertions)"
                            for check in item["preflight"]
                        )
                        or "none"
                    )
                    postflight = (
                        ", ".join(
                            f"{check['step_id']} ({check['action_id']}, {check['assertion_count']} assertions)"
                            for check in item["postflight"]
                        )
                        or "none"
                    )
                    remediation_rows.append(
                        "<li>"
                        f"Plan {_e(item['plan_id'])} · hash {_e(item['plan_hash'])} · integrity {_e(item['plan_integrity'])}<br>"
                        f"Target/action: {_e(item['target'])} / {_e(item['action_id'])}; associated by {_e(item['actor'])} at {_e(item['associated_at'])}<br>"
                        f"Approval: {_e(item['approval']['state'])}; last execution: {_e(item['last_execution_at'] or 'none')}<br>"
                        f"Preflight: {_e(preflight)}; postflight: {_e(postflight)}<br>"
                        f"Executions: {_e(executions)} {warning}</li>"
                    )
                controls = _controls(detail, session.csrf)
                valid, count = state.incidents.store.verify_audit_chain()
                audit = f"VALID · {count} events" if valid else f"INVALID · verified prefix {count}"
                body = (
                    f"<article><p><strong>{_e(detail['severity'].upper())}</strong> · {_e(detail['status'])}</p><p>{_e(detail['summary'])}</p>"
                    f"<dl><dt>Target / service</dt><dd>{_e(detail['target_alias'])} / {_e(detail['service'])}</dd><dt>Category</dt><dd>{_e(detail['category'])}</dd><dt>Created / updated</dt><dd>{_e(detail['created_at'])} / {_e(detail['updated_at'])}</dd><dt>Audit chain</dt><dd>{_e(audit)}</dd></dl></article>"
                    f"<h2>Alert correlation</h2><ul>{links}</ul><h2>Linked investigations</h2><ul>{''.join(investigations) or '<li>None</li>'}</ul>"
                    f"<h2>Remediation review (read-only)</h2><ul>{''.join(remediation_rows) or '<li>No remediation plans associated.</li>'}</ul>"
                    f"<h2>Incident timeline</h2><table><tr><th>Time</th><th>Event</th><th>Actor</th><th>Reason</th><th>Evidence status</th><th>Status transition</th></tr>{events}</table>{controls}"
                )
                self.send_page(200, f"Incident {incident_id}", body)
                return
            self.send_page(404, "Not found", "<p>Unknown page.</p>")

        def do_POST(self) -> None:  # noqa: N802
            length_text = self.headers.get("Content-Length", "0")
            if not length_text.isdecimal() or int(length_text) > 4096:
                self.send_page(413, "Request rejected", "<p>Request too large.</p>")
                return
            try:
                form = parse_qs(
                    self.rfile.read(int(length_text)).decode("utf-8"), strict_parsing=True
                )
            except (UnicodeError, ValueError):
                self.send_page(400, "Request rejected", "<p>Malformed form.</p>")
                return
            parsed = urlparse(self.path)
            if parsed.path == "/login":
                token = state.authenticate(self.client_address[0], form.get("password", [""])[0])
                if token is None:
                    self.send_page(
                        401,
                        "Login failed",
                        "<p>Authentication failed or temporarily rate limited.</p>",
                    )
                    return
                self.send_page(
                    303,
                    "Signed in",
                    "<p>Authenticated.</p>",
                    {
                        "Location": "/",
                        "Set-Cookie": f"runbookos_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={_SESSION_TTL}",
                    },
                )
                return
            session = self.require_session()
            if session is None:
                self.send_page(401, "Authentication required", "<p>Sign in first.</p>")
                return
            if not hmac.compare_digest(form.get("csrf", [""])[0], session.csrf):
                self.send_page(403, "Request rejected", "<p>CSRF validation failed.</p>")
                return
            if parsed.path == "/logout":
                with state.lock:
                    state.sessions.pop(self.cookie() or "", None)
                self.send_page(
                    303,
                    "Signed out",
                    "<p>Signed out.</p>",
                    {
                        "Location": "/login",
                        "Set-Cookie": "runbookos_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
                    },
                )
                return
            parts = parsed.path.strip("/").split("/")
            if len(parts) != 3 or parts[0] != "incidents":
                self.send_page(404, "Not found", "<p>Unknown action.</p>")
                return
            incident_id, action = unquote(parts[1]), parts[2]
            reason = form.get("reason", [""])[0]
            try:
                if action == "acknowledge":
                    state.incidents.transition(
                        incident_id, "ACKNOWLEDGED", session.operator_id, reason
                    )
                elif action == "resolve":
                    state.incidents.transition(
                        incident_id,
                        "RESOLVED",
                        session.operator_id,
                        reason,
                        evidence_status=form.get("evidence_status", [""])[0],
                    )
                elif action == "close":
                    state.incidents.transition(incident_id, "CLOSED", session.operator_id, reason)
                else:
                    self.send_page(404, "Not found", "<p>Unknown lifecycle action.</p>")
                    return
            except (ValueError, PolicyDenied, ConfigurationError) as exc:
                self.send_page(409, "Transition rejected", f"<p>{_e(exc)}</p>")
                return
            self.send_page(
                303,
                "Incident updated",
                "<p>Lifecycle transition recorded.</p>",
                {"Location": f"/incidents/{quote(incident_id)}"},
            )

    server = _Server((host, port), Handler)
    try:
        print(
            f"RunbookOS dashboard listening on http://{host}:{server.server_port}; Ctrl-C stops it."
        )
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()


def _selected(current: str | None, value: str) -> str:
    return "selected" if current == value else ""


def _controls(incident: dict[str, object], csrf: str) -> str:
    incident_id = quote(str(incident["incident_id"]))
    status = str(incident["status"])
    form_prefix = f"<input type='hidden' name='csrf' value='{_e(csrf)}'><label>Reason <input name='reason' maxlength='500' required></label>"
    if status == "NEW":
        return f"<h2>Operator action</h2><form method='post' action='/incidents/{incident_id}/acknowledge'>{form_prefix}<button>Acknowledge</button></form>"
    if status == "ACKNOWLEDGED":
        return "<p>Investigation execution is available through the existing CLI after explicit review: <code>runbookos incidents investigate</code>.</p>"
    if status == "INVESTIGATING":
        return (
            f"<h2>Resolve incident</h2><form method='post' action='/incidents/{incident_id}/resolve'>{form_prefix}"
            "<label>Evidence status <select name='evidence_status' required><option>verified</option><option>not_available</option><option>inconclusive</option></select></label><button>Resolve</button></form>"
        )
    if status == "RESOLVED":
        return f"<h2>Close incident</h2><form method='post' action='/incidents/{incident_id}/close'>{form_prefix}<button>Close</button></form>"
    return "<p>Incident is closed.</p>"
