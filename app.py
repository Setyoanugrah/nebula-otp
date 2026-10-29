#!/usr/bin/env python3
"""Nebula OTP — OTP delivery service with a web console.

Public surface:
  GET  /                      landing
  GET  /register  POST /register
  GET  /login     POST /login     POST /logout
  GET  /app                   console: keys, usage
  POST /app/keys              create a key (shown once)
  POST /app/keys/{id}/revoke
  GET  /v1/health
  POST /v1/otp/send           X-API-Key: opnbla...
  POST /v1/otp/verify

Design notes:
  - API keys are stored as SHA-256 hashes; the raw value is shown once.
  - Passwords use scrypt with a per-user salt (stdlib, no extra deps).
  - Sessions are random tokens, stored hashed, sent as an HttpOnly cookie.
  - Codes are stored as SHA-256(salt + code), one active code per destination.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import string
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from typing import Any

from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("OTP_DB", "/var/lib/otpsvc/otp.db")
CODE_TTL = int(os.environ.get("OTP_TTL", "300"))
COOLDOWN = int(os.environ.get("OTP_COOLDOWN", "60"))
MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))
DAILY_QUOTA = int(os.environ.get("OTP_DAILY_QUOTA", "200"))
SESSION_DAYS = int(os.environ.get("OTP_SESSION_DAYS", "14"))
KEY_PREFIX = "opnbla"
KEY_BODY_LEN = 32
ALNUM = string.ascii_letters + string.digits

app = FastAPI(title="Nebula OTP", version="2.0")


# --------------------------------------------------------------------------- db
def db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def migrate() -> None:
    with db() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY,
                email      TEXT NOT NULL UNIQUE,
                pass_hash  TEXT NOT NULL,
                salt       TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS keys (
                id         INTEGER PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                name       TEXT NOT NULL,
                prefix     TEXT NOT NULL,
                key_hash   TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                last_used  INTEGER,
                revoked    INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_keys_user ON keys(user_id);
            CREATE TABLE IF NOT EXISTS codes (
                id          INTEGER PRIMARY KEY,
                key_id      INTEGER NOT NULL,
                channel     TEXT NOT NULL,
                destination TEXT NOT NULL,
                code_hash   TEXT NOT NULL,
                salt        TEXT NOT NULL,
                attempts    INTEGER NOT NULL DEFAULT 0,
                created_at  INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL,
                consumed_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_codes_dest ON codes(key_id, destination);
            CREATE TABLE IF NOT EXISTS sends (
                id          INTEGER PRIMARY KEY,
                key_id      INTEGER NOT NULL,
                channel     TEXT NOT NULL,
                destination TEXT NOT NULL,
                ok          INTEGER NOT NULL,
                error       TEXT,
                created_at  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sends_key ON sends(key_id, created_at);
            CREATE TABLE IF NOT EXISTS admin_sessions (
                token_hash TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS uptime_targets (
                id         INTEGER PRIMARY KEY,
                label      TEXT NOT NULL,
                url        TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS uptime_results (
                id         INTEGER PRIMARY KEY,
                target_id  INTEGER NOT NULL,
                ok         INTEGER NOT NULL,
                status     INTEGER,
                ms         INTEGER,
                error      TEXT,
                checked_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_uptime_t ON uptime_results(target_id, checked_at);
            """
        )

        # v1 used project_id on codes/sends; v2 keys them by key_id. Rebuild the
        # two affected tables rather than leaving a half-migrated schema that
        # fails every console query.
        for table, sql in (
            ("codes",
             """CREATE TABLE codes_new (
                    id          INTEGER PRIMARY KEY,
                    key_id      INTEGER NOT NULL,
                    channel     TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    code_hash   TEXT NOT NULL,
                    salt        TEXT NOT NULL,
                    attempts    INTEGER NOT NULL DEFAULT 0,
                    created_at  INTEGER NOT NULL,
                    expires_at  INTEGER NOT NULL,
                    consumed_at INTEGER
                )"""),
            ("sends",
             """CREATE TABLE sends_new (
                    id          INTEGER PRIMARY KEY,
                    key_id      INTEGER NOT NULL,
                    channel     TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    ok          INTEGER NOT NULL,
                    error       TEXT,
                    created_at  INTEGER NOT NULL
                )"""),
        ):
            cols = [r[1] for r in con.execute(f"PRAGMA table_info({table})")]
            if "project_id" in cols:
                con.execute(f"DROP TABLE IF EXISTS {table}_new")
                con.execute(sql)
                con.execute(f"DROP TABLE {table}")
                con.execute(f"ALTER TABLE {table}_new RENAME TO {table}")
                con.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_{table}_key ON {table}(key_id, created_at)"
                )
        # old projects table is unused by v2
        con.execute("DROP TABLE IF EXISTS projects")

        # admin keys can bypass quota and cooldown
        kcols = [r[1] for r in con.execute("PRAGMA table_info(keys)")]
        if "unlimited" not in kcols:
            con.execute("ALTER TABLE keys ADD COLUMN unlimited INTEGER NOT NULL DEFAULT 0")


migrate()


def now() -> int:
    return int(time.time())


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ------------------------------------------------------------------ passwords
def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=32)
    return dk.hex(), salt


def check_password(password: str, stored: str, salt: str) -> bool:
    dk = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=32)
    return hmac.compare_digest(dk.hex(), stored)


# ------------------------------------------------------------------- sessions
def make_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    exp = now() + SESSION_DAYS * 86400
    with db() as con:
        con.execute(
            "INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
            (sha(token), user_id, now(), exp),
        )
    return token


def current_user(request: Request) -> sqlite3.Row | None:
    token = request.cookies.get("nebula_session")
    if not token:
        return None
    with db() as con:
        row = con.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id"
            " WHERE s.token_hash=? AND s.expires_at>?",
            (sha(token), now()),
        ).fetchone()
    return row


def require_user(request: Request) -> sqlite3.Row:
    user = current_user(request)
    if not user:
        raise HTTPException(401, "login required")
    return user


# ------------------------------------------------------------------- admin auth
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "icarusvospie@gmail.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Jenkijen9901")
ADMIN_PATH = os.environ.get("ADMIN_PATH", "administrator")


def admin_session(request: Request) -> bool:
    token = request.cookies.get("nebula_admin")
    if not token:
        return False
    with db() as con:
        row = con.execute(
            "SELECT 1 FROM admin_sessions WHERE token_hash=? AND expires_at>?",
            (sha(token), now()),
        ).fetchone()
    return row is not None


def require_admin(request: Request) -> None:
    if not admin_session(request):
        raise HTTPException(401, "admin login required")


# ---------------------------------------------------------------------- keys
def new_key() -> str:
    body = "".join(secrets.choice(ALNUM) for _ in range(KEY_BODY_LEN))
    return KEY_PREFIX + body


def key_owner(key: str | None) -> sqlite3.Row:
    if not key:
        raise HTTPException(401, "missing API key")
    with db() as con:
        row = con.execute(
            "SELECT * FROM keys WHERE key_hash=? AND revoked=0", (sha(key),)
        ).fetchone()
    if not row:
        raise HTTPException(401, "invalid API key")
    with db() as con:
        con.execute("UPDATE keys SET last_used=? WHERE id=?", (now(), row["id"]))
    return row


# ------------------------------------------------------------------ channels
PHONE_RE = re.compile(r"^\+?[1-9]\d{6,15}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


def normalise(channel: str, destination: str) -> str:
    d = destination.strip()
    if channel == "email":
        d = d.lower()
        if not EMAIL_RE.match(d):
            raise HTTPException(422, "destination is not a valid email")
        return d
    if channel in ("sms", "whatsapp"):
        d = d.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
        if d.startswith("0"):
            d = "+62" + d[1:]
        elif not d.startswith("+"):
            d = "+" + d
        if not PHONE_RE.match(d):
            raise HTTPException(422, "destination is not a valid phone number")
        return d
    raise HTTPException(422, "channel must be email, sms or whatsapp")


def send_email(dest: str, code: str, ttl: int) -> None:
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    pwd = os.environ.get("SMTP_PASS", "")
    sender = os.environ.get("SMTP_FROM", user)
    use_tls = os.environ.get("SMTP_TLS", "1") == "1"

    msg = EmailMessage()
    msg["Subject"] = f"Kode verifikasi: {code}"
    msg["From"] = sender
    msg["To"] = dest
    msg.set_content(
        f"Kode verifikasi kamu: {code}\n\n"
        f"Berlaku {max(ttl // 60, 1)} menit. Jangan bagikan kode ini ke siapa pun.\n"
    )
    ctx = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=20) as s:
            if user:
                s.login(user, pwd)
            s.send_message(msg)
    elif use_tls:
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.starttls(context=ctx)
            if user:
                s.login(user, pwd)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=20) as s:
            if user:
                s.login(user, pwd)
            s.send_message(msg)


def send_gateway(dest: str, code: str, ttl: int, channel: str) -> None:
    url = os.environ.get("SMS_GATEWAY_URL") if channel == "sms" else os.environ.get("WA_URL")
    token = os.environ.get("SMS_GATEWAY_TOKEN") if channel == "sms" else os.environ.get("WA_TOKEN")
    if not url:
        raise RuntimeError(f"{channel} gateway not configured")
    body = json.dumps({
        "to": dest,
        "message": f"Kode verifikasi kamu: {code}. Berlaku {max(ttl // 60, 1)} menit.",
    }).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            if r.status >= 300:
                raise RuntimeError(f"gateway returned {r.status}")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"gateway HTTP {e.code}") from e


def deliver(channel: str, dest: str, code: str, ttl: int) -> None:
    if channel == "email":
        send_email(dest, code, ttl)
    elif channel in ("sms", "whatsapp"):
        send_gateway(dest, code, ttl, channel)
    else:
        raise RuntimeError("unknown channel")


# ------------------------------------------------------------------- API models
class SendIn(BaseModel):
    channel: str = Field(default="email")
    destination: str


class VerifyIn(BaseModel):
    channel: str = Field(default="email")
    destination: str
    code: str


# ------------------------------------------------------------------- API routes
@app.get("/v1/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": "nebula-otp",
        "channels": {
            "email": bool(os.environ.get("SMTP_HOST")),
            "sms": bool(os.environ.get("SMS_GATEWAY_URL")),
            "whatsapp": bool(os.environ.get("WA_URL")),
        },
        "ttl": CODE_TTL,
        "cooldown": COOLDOWN,
    }


@app.post("/v1/otp/send")
def otp_send(body: SendIn, x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    owner = key_owner(x_api_key)
    dest = normalise(body.channel, body.destination)

    start = now() - 86400
    with db() as con:
        used = con.execute(
            "SELECT COUNT(*) c FROM sends WHERE key_id=? AND created_at>?",
            (owner["id"], start),
        ).fetchone()["c"]
        last = con.execute(
            "SELECT MAX(created_at) t FROM codes WHERE key_id=? AND destination=?",
            (owner["id"], dest),
        ).fetchone()["t"] or 0

    unlimited = bool(owner["unlimited"]) if "unlimited" in owner.keys() else False
    if not unlimited:
        if used >= DAILY_QUOTA:
            raise HTTPException(429, "daily quota reached for this key")
        elapsed = now() - int(last)
        if elapsed < COOLDOWN:
            raise HTTPException(429, f"wait {COOLDOWN - elapsed}s before resending")

    code = f"{secrets.randbelow(1_000_000):06d}"
    salt = secrets.token_hex(16)
    expires = now() + CODE_TTL

    try:
        deliver(body.channel, dest, code, CODE_TTL)
    except Exception as exc:  # noqa: BLE001
        with db() as con:
            con.execute(
                "INSERT INTO sends(key_id,channel,destination,ok,error,created_at)"
                " VALUES(?,?,?,0,?,?)",
                (owner["id"], body.channel, dest, str(exc)[:200], now()),
            )
        raise HTTPException(502, f"delivery failed: {exc}") from exc

    with db() as con:
        con.execute(
            "DELETE FROM codes WHERE key_id=? AND destination=? AND consumed_at IS NULL",
            (owner["id"], dest),
        )
        con.execute(
            "INSERT INTO codes(key_id,channel,destination,code_hash,salt,created_at,expires_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (owner["id"], body.channel, dest, sha(salt + code), salt, now(), expires),
        )
        con.execute(
            "INSERT INTO sends(key_id,channel,destination,ok,error,created_at)"
            " VALUES(?,?,?,1,NULL,?)",
            (owner["id"], body.channel, dest, now()),
        )

    out: dict[str, Any] = {
        "ok": True, "channel": body.channel, "destination": dest, "expires_in": CODE_TTL,
    }
    if os.environ.get("OTP_DEV_MODE") == "1":
        out["dev_code"] = code
    return out


@app.post("/v1/otp/verify")
def otp_verify(body: VerifyIn, x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    owner = key_owner(x_api_key)
    dest = normalise(body.channel, body.destination)
    code = body.code.strip()

    with db() as con:
        row = con.execute(
            "SELECT * FROM codes WHERE key_id=? AND destination=? AND consumed_at IS NULL"
            " ORDER BY id DESC LIMIT 1",
            (owner["id"], dest),
        ).fetchone()
        if not row:
            raise HTTPException(404, "no active code for this destination")
        if row["expires_at"] < now():
            con.execute("UPDATE codes SET consumed_at=? WHERE id=?", (now(), row["id"]))
            raise HTTPException(410, "code expired")
        if row["attempts"] >= MAX_ATTEMPTS:
            con.execute("UPDATE codes SET consumed_at=? WHERE id=?", (now(), row["id"]))
            raise HTTPException(429, "too many attempts")
        if not hmac.compare_digest(row["code_hash"], sha(row["salt"] + code)):
            con.execute("UPDATE codes SET attempts=attempts+1 WHERE id=?", (row["id"],))
            left = MAX_ATTEMPTS - (row["attempts"] + 1)
            raise HTTPException(401, f"wrong code, {max(left, 0)} attempts left")
        con.execute("UPDATE codes SET consumed_at=? WHERE id=?", (now(), row["id"]))

    return {"ok": True, "verified": True, "destination": dest}


# ----------------------------------------------------------------- admin routes
UPTIME_TIMEOUT = int(os.environ.get("UPTIME_TIMEOUT", "10"))


def check_url(url: str) -> dict[str, Any]:
    """Fetch a URL and report status and latency. Never raises."""
    t0 = time.time()
    try:
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": "NebulaUptime/1.0"})
        with urllib.request.urlopen(req, timeout=UPTIME_TIMEOUT) as r:
            body = r.read(2048)
            ms = int((time.time() - t0) * 1000)
            return {"ok": 200 <= r.status < 400, "status": r.status, "ms": ms,
                    "error": None, "bytes": len(body)}
    except urllib.error.HTTPError as e:
        ms = int((time.time() - t0) * 1000)
        return {"ok": False, "status": e.code, "ms": ms, "error": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        ms = int((time.time() - t0) * 1000)
        return {"ok": False, "status": None, "ms": ms, "error": type(e).__name__}


@app.get("/" + ADMIN_PATH, response_class=HTMLResponse)
def admin_login_page(request: Request, err: str = "") -> HTMLResponse:
    if admin_session(request):
        return RedirectResponse("/" + ADMIN_PATH + "/panel", status_code=303)
    e = f'<div class="err">{err}</div>' if err else ""
    body = f"""<div class="center">
<h1>Administrator</h1><p class="sub">Panel internal Nebula OTP.</p>{e}
<div class="card"><form method="post" action="/{ADMIN_PATH}">
  <label>Email</label><input name="email" type="email" required autofocus>
  <label>Password</label><input name="password" type="password" required>
  <div style="margin-top:18px"><button type="submit">Masuk</button></div>
</form></div></div>"""
    return HTMLResponse(shell("Admin", body))


@app.post("/" + ADMIN_PATH)
def admin_login(email: str = Form(...), password: str = Form(...)) -> RedirectResponse:
    ok_email = hmac.compare_digest(email.strip().lower(), ADMIN_EMAIL.lower())
    ok_pass = hmac.compare_digest(password, ADMIN_PASSWORD)
    if not (ok_email and ok_pass):
        return RedirectResponse(f"/{ADMIN_PATH}?err=Kredensial+salah", status_code=303)
    token = secrets.token_urlsafe(32)
    with db() as con:
        con.execute(
            "INSERT INTO admin_sessions(token_hash,created_at,expires_at) VALUES(?,?,?)",
            (sha(token), now(), now() + 7 * 86400),
        )
    resp = RedirectResponse(f"/{ADMIN_PATH}/panel", status_code=303)
    resp.set_cookie("nebula_admin", token, httponly=True, samesite="lax",
                    max_age=7 * 86400, path="/")
    return resp


@app.post("/" + ADMIN_PATH + "/logout")
def admin_logout(request: Request) -> RedirectResponse:
    token = request.cookies.get("nebula_admin")
    if token:
        with db() as con:
            con.execute("DELETE FROM admin_sessions WHERE token_hash=?", (sha(token),))
    resp = RedirectResponse("/" + ADMIN_PATH, status_code=303)
    resp.delete_cookie("nebula_admin", path="/")
    return resp


@app.get("/" + ADMIN_PATH + "/panel", response_class=HTMLResponse)
def admin_panel(request: Request, new: str = "", added: str = "") -> HTMLResponse:
    if not admin_session(request):
        return RedirectResponse("/" + ADMIN_PATH, status_code=303)

    # check every target on each panel load, keeping only the last 40 results
    with db() as con:
        _targets = con.execute("SELECT * FROM uptime_targets").fetchall()
    for _t in _targets:
        _r = check_url(_t["url"])
        with db() as con:
            con.execute(
                "INSERT INTO uptime_results(target_id,ok,status,ms,error,checked_at)"
                " VALUES(?,?,?,?,?,?)",
                (_t["id"], 1 if _r["ok"] else 0, _r["status"], _r["ms"], _r["error"], now()),
            )
            con.execute(
                "DELETE FROM uptime_results WHERE target_id=? AND id NOT IN"
                " (SELECT id FROM uptime_results WHERE target_id=? ORDER BY id DESC LIMIT 40)",
                (_t["id"], _t["id"]),
            )

    with db() as con:
        keys = con.execute(
            "SELECT k.*, u.email FROM keys k LEFT JOIN users u ON u.id=k.user_id"
            " ORDER BY k.id DESC LIMIT 200"
        ).fetchall()
        targets = con.execute("SELECT * FROM uptime_targets ORDER BY id").fetchall()
        totals = {
            "keys": con.execute("SELECT COUNT(*) c FROM keys WHERE revoked=0").fetchone()["c"],
            "users": con.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
            "sends24": con.execute(
                "SELECT COUNT(*) c FROM sends WHERE created_at>?", (now() - 86400,)
            ).fetchone()["c"],
            "sends": con.execute("SELECT COUNT(*) c FROM sends").fetchone()["c"],
            "codes": con.execute(
                "SELECT COUNT(*) c FROM codes WHERE consumed_at IS NULL AND expires_at>?",
                (now(),),
            ).fetchone()["c"],
        }

    banner = ""
    if new:
        banner = f"""<div class="newkey">
  <div style="font-weight:600;margin-bottom:4px">API key dibuat</div>
  <div class="val">{new}</div>
  <p class="warn">Simpan sekarang — tidak bisa ditampilkan lagi.</p>
</div>"""

    # uptime rows
    up_rows = ""
    for t in targets:
        with db() as con:
            last = con.execute(
                "SELECT * FROM uptime_results WHERE target_id=? ORDER BY id DESC LIMIT 1",
                (t["id"],),
            ).fetchone()
            hist = con.execute(
                "SELECT ok FROM uptime_results WHERE target_id=? ORDER BY id DESC LIMIT 40",
                (t["id"],),
            ).fetchall()
        if last:
            dot = "#34d399" if last["ok"] else "#f87171"
            state = "UP" if last["ok"] else "DOWN"
            detail = f'{last["status"] or "-"} · {last["ms"]}ms'
            if last["error"]:
                detail += f' · {last["error"]}'
        else:
            dot, state, detail = "#8b98a8", "—", "belum dicek"
        bars = "".join(
            f'<span style="display:inline-block;width:6px;height:16px;margin-right:2px;'
            f'border-radius:2px;background:{"#34d399" if h["ok"] else "#f87171"}"></span>'
            for h in reversed(hist)
        )
        up_rows += (f'<tr><td><b>{t["label"]}</b><br><span class="muted">{t["url"]}</span></td>'
                    f'<td><span style="color:{dot};font-weight:700">{state}</span></td>'
                    f'<td class="muted">{detail}</td><td>{bars or "—"}</td>'
                    f'<td><form method="post" action="/{ADMIN_PATH}/uptime/{t["id"]}/delete" style="margin:0">'
                    f'<button class="danger" type="submit">Hapus</button></form></td></tr>')
    if not up_rows:
        up_rows = '<tr><td colspan="5" class="muted" style="padding:20px 10px">Belum ada target.</td></tr>'

    # key rows
    key_rows = ""
    for k in keys:
        state = ('<span style="color:#f87171">dicabut</span>' if k["revoked"]
                 else '<span style="color:#34d399">aktif</span>')
        unl = ('<span style="color:#fbbf24;font-weight:700">∞ unlimited</span>'
               if k["unlimited"] else '<span class="muted">terbatas</span>')
        used = time.strftime("%d %b %H:%M", time.localtime(k["last_used"])) if k["last_used"] else "—"
        act = ""
        if not k["revoked"]:
            act = (f'<form method="post" action="/{ADMIN_PATH}/keys/{k["id"]}/revoke" style="margin:0">'
                   f'<button class="danger" type="submit">Cabut</button></form>')
        key_rows += (f'<tr><td><b>{k["name"]}</b><br><span class="muted">{k["email"] or "-"}</span></td>'
                     f'<td><code>{k["prefix"]}…</code></td><td>{state}</td><td>{unl}</td>'
                     f'<td class="muted">{used}</td><td>{act}</td></tr>')
    if not key_rows:
        key_rows = '<tr><td colspan="6" class="muted" style="padding:20px 10px">Belum ada key.</td></tr>'

    body = f"""<h1>Panel Administrator</h1>
<p class="sub">{ADMIN_EMAIL}</p>
{banner}
<div class="card">
  <table>
    <tr><td class="muted">API key aktif</td><td><b>{totals["keys"]}</b></td></tr>
    <tr><td class="muted">User terdaftar</td><td><b>{totals["users"]}</b></td></tr>
    <tr><td class="muted">Kirim 24 jam</td><td><b>{totals["sends24"]}</b></td></tr>
    <tr><td class="muted">Total kirim</td><td><b>{totals["sends"]}</b></td></tr>
    <tr><td class="muted">Kode aktif</td><td><b>{totals["codes"]}</b></td></tr>
  </table>
</div>

<div class="card">
  <h2>Buat API key</h2>
  <form method="post" action="/{ADMIN_PATH}/keys" style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
    <div style="flex:1;min-width:180px">
      <label style="margin-top:0">Nama key</label>
      <input name="name" placeholder="internal-bot" required>
    </div>
    <div style="min-width:160px">
      <label style="margin-top:0">Pemilik (opsional)</label>
      <input name="owner" placeholder="email user">
    </div>
    <label style="display:flex;align-items:center;gap:8px;margin:0 0 11px;text-transform:none;
           font-size:14px;letter-spacing:0;color:var(--ink)">
      <input type="checkbox" name="unlimited" value="1" style="width:auto">
      Unlimited usage
    </label>
    <button type="submit">Generate</button>
  </form>
</div>

<div class="card">
  <h2>Uptime website</h2>
  <table>
    <tr><th>Target</th><th>Status</th><th>Detail</th><th>40 cek terakhir</th><th></th></tr>
    {up_rows}
  </table>
  <form method="post" action="/{ADMIN_PATH}/uptime" style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;margin-top:18px">
    <div style="flex:1;min-width:160px">
      <label style="margin-top:0">Label</label>
      <input name="label" placeholder="Nebula Drive" required>
    </div>
    <div style="flex:2;min-width:220px">
      <label style="margin-top:0">URL</label>
      <input name="url" placeholder="https://drive.rikuzetsi.my.id/api/health" required>
    </div>
    <button type="submit">Tambah</button>
  </form>
  <p class="muted" style="margin:14px 0 0">Cek dijalankan tiap kali halaman ini dibuka.</p>
</div>

<div class="card">
  <h2>Semua API key</h2>
  <table>
    <tr><th>Nama</th><th>Key</th><th>Status</th><th>Kuota</th><th>Terakhir</th><th></th></tr>
    {key_rows}
  </table>
</div>
<form method="post" action="/{ADMIN_PATH}/logout"><button class="ghost" type="submit">Keluar</button></form>"""
    return HTMLResponse(shell("Admin", body))


@app.post("/" + ADMIN_PATH + "/keys")
def admin_create_key(request: Request, name: str = Form(...), owner: str = Form(""),
                     unlimited: str = Form("")) -> RedirectResponse:
    if not admin_session(request):
        return RedirectResponse("/" + ADMIN_PATH, status_code=303)
    uid = None
    if owner.strip():
        with db() as con:
            row = con.execute("SELECT id FROM users WHERE email=?",
                              (owner.strip().lower(),)).fetchone()
            uid = row["id"] if row else None
    raw = new_key()
    with db() as con:
        con.execute(
            "INSERT INTO keys(user_id,name,prefix,key_hash,created_at,unlimited)"
            " VALUES(?,?,?,?,?,?)",
            (uid or 0, name.strip()[:60] or "admin", raw[:12], sha(raw), now(),
             1 if unlimited == "1" else 0),
        )
    return RedirectResponse(f"/{ADMIN_PATH}/panel?new={raw}", status_code=303)


@app.post("/" + ADMIN_PATH + "/keys/{kid}/revoke")
def admin_revoke_key(request: Request, kid: int) -> RedirectResponse:
    if not admin_session(request):
        return RedirectResponse("/" + ADMIN_PATH, status_code=303)
    with db() as con:
        con.execute("UPDATE keys SET revoked=1 WHERE id=?", (kid,))
    return RedirectResponse(f"/{ADMIN_PATH}/panel", status_code=303)


@app.post("/" + ADMIN_PATH + "/uptime")
def admin_add_uptime(request: Request, label: str = Form(...), url: str = Form(...)) -> RedirectResponse:
    if not admin_session(request):
        return RedirectResponse("/" + ADMIN_PATH, status_code=303)
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    with db() as con:
        con.execute("INSERT INTO uptime_targets(label,url,created_at) VALUES(?,?,?)",
                    (label.strip()[:60], url, now()))
    return RedirectResponse(f"/{ADMIN_PATH}/panel", status_code=303)


@app.post("/" + ADMIN_PATH + "/uptime/{tid}/delete")
def admin_del_uptime(request: Request, tid: int) -> RedirectResponse:
    if not admin_session(request):
        return RedirectResponse("/" + ADMIN_PATH, status_code=303)
    with db() as con:
        con.execute("DELETE FROM uptime_targets WHERE id=?", (tid,))
        con.execute("DELETE FROM uptime_results WHERE target_id=?", (tid,))
    return RedirectResponse(f"/{ADMIN_PATH}/panel", status_code=303)


@app.post("/" + ADMIN_PATH + "/uptime/check")
def admin_check_uptime(request: Request) -> JSONResponse:
    if not admin_session(request):
        raise HTTPException(401, "admin login required")
    with db() as con:
        targets = con.execute("SELECT * FROM uptime_targets").fetchall()
    out = []
    for t in targets:
        res = check_url(t["url"])
        with db() as con:
            con.execute(
                "INSERT INTO uptime_results(target_id,ok,status,ms,error,checked_at)"
                " VALUES(?,?,?,?,?,?)",
                (t["id"], 1 if res["ok"] else 0, res["status"], res["ms"],
                 res["error"], now()),
            )
        out.append({"label": t["label"], **res})
    return JSONResponse({"ok": True, "checked": len(out), "results": out})


# ---------------------------------------------------------------------- styles
CSS = """
:root{--bg:#080a0d;--card:#11151b;--line:#1f2731;--ink:#e8edf3;--dim:#8b98a8;
--accent:#3b82f6;--accent2:#60a5fa;--ok:#34d399;--bad:#f87171}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--accent2);text-decoration:none}a:hover{text-decoration:underline}
.top{border-bottom:1px solid var(--line);padding:16px 0;background:rgba(8,10,13,.9)}
.wrap{max-width:960px;margin:0 auto;padding:0 22px}
.top .wrap{display:flex;align-items:center;justify-content:space-between;gap:14px}
.brand{font-weight:700;font-size:16px}.brand span{color:var(--accent2)}
.top .right{display:flex;align-items:center;gap:16px;font-size:14px;color:var(--dim)}
.main{padding:44px 0 70px}
h1{font-size:26px;margin:0 0 6px;letter-spacing:-.4px}
h2{font-size:17px;margin:0 0 14px}
.sub{color:var(--dim);font-size:14.5px;margin:0 0 28px}
.card{background:var(--card);border:1px solid var(--line);border-radius:13px;padding:22px;margin-bottom:18px}
label{display:block;font-size:11.5px;letter-spacing:.7px;text-transform:uppercase;color:var(--dim);margin:14px 0 6px;font-weight:600}
input{width:100%;background:#0b0f14;border:1px solid #2a333d;color:var(--ink);
padding:11px 13px;border-radius:8px;font:14px ui-monospace,monospace}
input:focus{outline:none;border-color:var(--accent)}
button{background:var(--accent);color:#fff;border:0;padding:11px 22px;border-radius:8px;
font-weight:600;font-size:14.5px;cursor:pointer;font-family:inherit}
button:hover{background:#4a90ff}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--ink)}
button.ghost:hover{border-color:var(--accent);background:transparent}
button.danger{background:transparent;border:1px solid #4a2226;color:#f87171;padding:7px 14px;font-size:13px}
button.danger:hover{background:#2a1416}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--dim);font-size:11.5px;letter-spacing:.7px;text-transform:uppercase;
padding:0 10px 10px;font-weight:600}
td{padding:12px 10px;border-top:1px solid var(--line);vertical-align:middle}
code{font:13px ui-monospace,monospace;color:#c9d6e4;background:#0b0f14;padding:3px 7px;border-radius:5px}
.newkey{background:#0d1a12;border:1px solid #1c3d2a;border-radius:10px;padding:18px;margin-bottom:18px}
.newkey .val{font:15px ui-monospace,monospace;color:var(--ok);word-break:break-all;
background:#08120c;padding:12px;border-radius:7px;margin:10px 0}
.warn{color:#fbbf24;font-size:13.5px;margin:0}
.err{background:#1f1214;border:1px solid #4a2226;color:#fca5a5;padding:11px 14px;
border-radius:8px;font-size:14px;margin-bottom:16px}
.muted{color:var(--dim);font-size:13.5px}
.center{max-width:400px;margin:0 auto}
"""


def shell(title: str, body: str, user: sqlite3.Row | None = None) -> str:
    right = ""
    if user:
        right = (f'<span>{user["email"]}</span>'
                 f'<form method="post" action="/logout" style="margin:0">'
                 f'<button class="ghost" type="submit">Keluar</button></form>')
    else:
        right = '<a href="/login">Masuk</a><a href="/register">Daftar</a>'
    return f"""<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Nebula OTP</title><style>{CSS}</style></head><body>
<div class="top"><div class="wrap">
  <div class="brand">Nebula<span>OTP</span></div>
  <div class="right">{right}</div>
</div></div>
<div class="main"><div class="wrap">{body}</div></div>
</body></html>"""


# ------------------------------------------------------------------------ pages
@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    user = current_user(request)
    if user:
        return RedirectResponse("/app", status_code=303)
    body = """
<h1>Kode verifikasi untuk aplikasi kamu</h1>
<p class="sub">Kirim OTP lewat email, SMS, atau WhatsApp. Satu API, harga rupiah.</p>
<div class="card">
  <h2>Mulai</h2>
  <p class="muted" style="margin:0 0 18px">Buat akun, lalu generate API key pertama kamu.
     100 kode email gratis.</p>
  <a href="/register"><button>Daftar gratis</button></a>
  <a href="/login"><button class="ghost" style="margin-left:8px">Masuk</button></a>
</div>
<div class="card">
  <h2>Endpoint</h2>
  <p class="muted" style="margin:0 0 10px">Dua request, tidak ada SDK.</p>
  <code>POST /v1/otp/send</code> &nbsp; <code>POST /v1/otp/verify</code>
</div>
"""
    return HTMLResponse(shell("Beranda", body))


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, err: str = "") -> HTMLResponse:
    if current_user(request):
        return RedirectResponse("/app", status_code=303)
    e = f'<div class="err">{err}</div>' if err else ""
    body = f"""<div class="center">
<h1>Daftar</h1><p class="sub">Gratis 100 kode email.</p>{e}
<div class="card"><form method="post" action="/register">
  <label>Email</label><input name="email" type="email" required autofocus>
  <label>Password</label><input name="password" type="password" required minlength="8">
  <p class="muted" style="margin:10px 0 0">Minimal 8 karakter.</p>
  <div style="margin-top:18px"><button type="submit">Buat akun</button></div>
</form></div>
<p class="muted">Sudah punya akun? <a href="/login">Masuk</a></p>
</div>"""
    return HTMLResponse(shell("Daftar", body))


@app.post("/register")
def register(email: str = Form(...), password: str = Form(...)) -> RedirectResponse:
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        return RedirectResponse("/register?err=Email+tidak+valid", status_code=303)
    if len(password) < 8:
        return RedirectResponse("/register?err=Password+minimal+8+karakter", status_code=303)
    pw, salt = hash_password(password)
    try:
        with db() as con:
            cur = con.execute(
                "INSERT INTO users(email,pass_hash,salt,created_at) VALUES(?,?,?,?)",
                (email, pw, salt, now()),
            )
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        return RedirectResponse("/register?err=Email+sudah+terdaftar", status_code=303)

    token = make_session(uid)
    resp = RedirectResponse("/app", status_code=303)
    resp.set_cookie("nebula_session", token, httponly=True, samesite="lax",
                    max_age=SESSION_DAYS * 86400, path="/")
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, err: str = "") -> HTMLResponse:
    if current_user(request):
        return RedirectResponse("/app", status_code=303)
    e = f'<div class="err">{err}</div>' if err else ""
    body = f"""<div class="center">
<h1>Masuk</h1><p class="sub">Konsol Nebula OTP.</p>{e}
<div class="card"><form method="post" action="/login">
  <label>Email</label><input name="email" type="email" required autofocus>
  <label>Password</label><input name="password" type="password" required>
  <div style="margin-top:18px"><button type="submit">Masuk</button></div>
</form></div>
<p class="muted">Belum punya akun? <a href="/register">Daftar</a></p>
</div>"""
    return HTMLResponse(shell("Masuk", body))


@app.post("/login")
def login(email: str = Form(...), password: str = Form(...)) -> RedirectResponse:
    email = email.strip().lower()
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not check_password(password, user["pass_hash"], user["salt"]):
        return RedirectResponse("/login?err=Email+atau+password+salah", status_code=303)
    token = make_session(user["id"])
    resp = RedirectResponse("/app", status_code=303)
    resp.set_cookie("nebula_session", token, httponly=True, samesite="lax",
                    max_age=SESSION_DAYS * 86400, path="/")
    return resp


@app.post("/logout")
def logout(request: Request) -> RedirectResponse:
    token = request.cookies.get("nebula_session")
    if token:
        with db() as con:
            con.execute("DELETE FROM sessions WHERE token_hash=?", (sha(token),))
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie("nebula_session", path="/")
    return resp


@app.get("/app", response_class=HTMLResponse)
def console(request: Request, new: str = "", name: str = "") -> HTMLResponse:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    with db() as con:
        keys = con.execute(
            "SELECT * FROM keys WHERE user_id=? ORDER BY id DESC", (user["id"],)
        ).fetchall()
        kcount = len(keys)
        start = now() - 86400
        stats = con.execute(
            "SELECT COUNT(*) n FROM sends s JOIN keys k ON k.id=s.key_id"
            " WHERE k.user_id=? AND s.created_at>?", (user["id"], start)
        ).fetchone()["n"]
        total = con.execute(
            "SELECT COUNT(*) n FROM sends s JOIN keys k ON k.id=s.key_id"
            " WHERE k.user_id=?", (user["id"],)
        ).fetchone()["n"]

    banner = ""
    if new:
        banner = f"""<div class="newkey">
  <div style="font-weight:600;margin-bottom:4px">API key baru dibuat</div>
  <div class="val">{new}</div>
  <p class="warn">Simpan sekarang — key ini tidak bisa ditampilkan lagi.</p>
</div>"""

    rows = ""
    if keys:
        for k in keys:
            state = ('<span style="color:#f87171">dicabut</span>' if k["revoked"]
                     else '<span style="color:#34d399">aktif</span>')
            used = time.strftime("%d %b %H:%M", time.localtime(k["last_used"])) if k["last_used"] else "—"
            action = ("" if k["revoked"] else
                      f'<form method="post" action="/app/keys/{k["id"]}/revoke" style="margin:0">'
                      f'<button class="danger" type="submit">Cabut</button></form>')
            rows += (f'<tr><td><b>{k["name"]}</b></td><td><code>{k["prefix"]}…</code></td>'
                     f'<td>{state}</td><td class="muted">{used}</td><td>{action}</td></tr>')
    else:
        rows = '<tr><td colspan="5" class="muted" style="padding:22px 10px">Belum ada API key.</td></tr>'

    body = f"""<h1>Konsol</h1>
<p class="sub">{user["email"]}</p>
{banner}
<div class="card">
  <table>
    <tr><th>Nama</th><th>Key</th><th>Status</th><th>Terakhir dipakai</th><th></th></tr>
    {rows}
  </table>
</div>
<div class="card">
  <h2>Buat API key</h2>
  <form method="post" action="/app/keys" style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
    <div style="flex:1;min-width:200px">
      <label style="margin-top:0">Nama key</label>
      <input name="name" placeholder="website-produksi" required>
    </div>
    <button type="submit">Generate</button>
  </form>
</div>
<div class="card">
  <h2>Pemakaian</h2>
  <table>
    <tr><td class="muted">API key aktif</td><td><b>{kcount}</b></td></tr>
    <tr><td class="muted">Kirim 24 jam terakhir</td><td><b>{stats}</b> / {DAILY_QUOTA} per key</td></tr>
    <tr><td class="muted">Total kirim</td><td><b>{total}</b></td></tr>
  </table>
</div>
<div class="card">
  <h2>Cara pakai</h2>
  <p class="muted" style="margin:0 0 8px">Kirim kode:</p>
  <code>curl -X POST https://otp.rikuzetsi.my.id/v1/otp/send -H "X-API-Key: opnbla..." -H "Content-Type: application/json" -d '{{"channel":"email","destination":"user@mail.com"}}'</code>
  <p class="muted" style="margin:16px 0 8px">Verifikasi:</p>
  <code>curl -X POST https://otp.rikuzetsi.my.id/v1/otp/verify -H "X-API-Key: opnbla..." -H "Content-Type: application/json" -d '{{"channel":"email","destination":"user@mail.com","code":"123456"}}'</code>
</div>"""
    return HTMLResponse(shell("Konsol", body, user))


@app.post("/app/keys")
def create_key(request: Request, name: str = Form(...)) -> RedirectResponse:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    raw = new_key()
    with db() as con:
        con.execute(
            "INSERT INTO keys(user_id,name,prefix,key_hash,created_at) VALUES(?,?,?,?,?)",
            (user["id"], name.strip()[:60] or "default", raw[:12], sha(raw), now()),
        )
    return RedirectResponse(f"/app?new={raw}", status_code=303)


@app.post("/app/keys/{kid}/revoke")
def revoke_key(request: Request, kid: int) -> RedirectResponse:
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db() as con:
        con.execute("UPDATE keys SET revoked=1 WHERE id=? AND user_id=?", (kid, user["id"]))
    return RedirectResponse("/app", status_code=303)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8099")))
