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
