#!/usr/bin/env python3
"""Nebula OTP — an OTP delivery service for app developers.

Websites and bots call POST /v1/otp/send with a destination, then
POST /v1/otp/verify with the code the user received. Delivery is pluggable:
email over SMTP, SMS over an HTTP gateway (Android phone or an aggregator), or
WhatsApp over an HTTP gateway.

Design choices that matter for a public OTP service:
  - codes are stored as SHA-256(salt + code), never in plaintext
  - one active code per destination; resending replaces it
  - per-destination cooldown and per-key daily quota stop SMS bombing
  - fixed attempt counter, consumed on success, so brute force is bounded
  - constant-time compare on verify
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
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("OTP_DB", "/var/lib/otpsvc/otp.db")
CODE_TTL = int(os.environ.get("OTP_TTL", "300"))            # seconds a code lives
COOLDOWN = int(os.environ.get("OTP_COOLDOWN", "60"))        # per destination
MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))
DAILY_QUOTA = int(os.environ.get("OTP_DAILY_QUOTA", "200"))  # per api key
ADMIN_TOKEN = os.environ.get("OTP_ADMIN_TOKEN", "")

app = FastAPI(title="Nebula OTP", version="1.0")


# --------------------------------------------------------------------------- db
def db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def migrate() -> None:
    with db() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id         INTEGER PRIMARY KEY,
                name       TEXT NOT NULL,
                key_hash   TEXT NOT NULL UNIQUE,
                key_prefix TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                revoked    INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS codes (
                id          INTEGER PRIMARY KEY,
                project_id  INTEGER NOT NULL,
                channel     TEXT NOT NULL,
                destination TEXT NOT NULL,
                code_hash   TEXT NOT NULL,
                salt        TEXT NOT NULL,
                attempts    INTEGER NOT NULL DEFAULT 0,
                created_at  INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL,
                consumed_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_codes_dest
                ON codes(project_id, destination, channel);
            CREATE TABLE IF NOT EXISTS sends (
                id          INTEGER PRIMARY KEY,
                project_id  INTEGER NOT NULL,
                channel     TEXT NOT NULL,
                destination TEXT NOT NULL,
                ok          INTEGER NOT NULL,
                error       TEXT,
                created_at  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sends_key ON sends(project_id, created_at);
            """
        )


migrate()


def now() -> int:
    return int(time.time())


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ---------------------------------------------------------------------- helpers
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
        if d.startswith("0"):          # Indonesian local form
            d = "+62" + d[1:]
        elif not d.startswith("+"):
            d = "+" + d
        if not PHONE_RE.match(d):
            raise HTTPException(422, "destination is not a valid phone number")
        return d
    raise HTTPException(422, "channel must be email, sms or whatsapp")


def project_from_key(key: str | None) -> sqlite3.Row:
    if not key:
        raise HTTPException(401, "missing API key")
    kh = sha(key)
    with db() as con:
        row = con.execute(
            "SELECT * FROM projects WHERE key_hash=? AND revoked=0", (kh,)
        ).fetchone()
    if not row:
        raise HTTPException(401, "invalid API key")
    return row


def daily_count(project_id: int) -> int:
    start = now() - 86400
    with db() as con:
        n = con.execute(
            "SELECT COUNT(*) c FROM sends WHERE project_id=? AND created_at>?",
            (project_id, start),
        ).fetchone()["c"]
    return int(n)


def last_send_at(project_id: int, destination: str) -> int:
    with db() as con:
        row = con.execute(
            "SELECT MAX(created_at) t FROM codes WHERE project_id=? AND destination=?",
            (project_id, destination),
        ).fetchone()
    return int(row["t"] or 0)


def record_send(project_id: int, channel: str, dest: str, ok: bool, err: str | None) -> None:
    with db() as con:
        con.execute(
            "INSERT INTO sends(project_id,channel,destination,ok,error,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (project_id, channel, dest, 1 if ok else 0, err, now()),
        )


# --------------------------------------------------------------------- channels
def send_email(dest: str, code: str, ttl: int) -> None:
    host = os.environ["SMTP_HOST"]
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "")
    pwd = os.environ.get("SMTP_PASS", "")
    sender = os.environ.get("SMTP_FROM", user)

    msg = EmailMessage()
    msg["Subject"] = f"Kode verifikasi: {code}"
    msg["From"] = sender
    msg["To"] = dest
    msg.set_content(
        f"Kode verifikasi kamu: {code}\n\n"
        f"Berlaku {ttl // 60} menit. Jangan bagikan kode ini ke siapa pun.\n"
    )
    use_tls = os.environ.get("SMTP_TLS", "1") == "1"
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
        # plain SMTP: local sinks and trusted relays that do not offer STARTTLS
        with smtplib.SMTP(host, port, timeout=20) as s:
            if user:
                s.login(user, pwd)
            s.send_message(msg)


def send_http_gateway(dest: str, code: str, ttl: int, channel: str) -> None:
    """POST to a gateway that turns the request into a real SMS or WA message.

    Works with an Android SMS-gateway app on a phone with a SIM, or with an
    aggregator that exposes an HTTP API. The gateway URL and token come from the
    environment, and the payload shape is the one those gateways expect.
    """
    url = os.environ.get("SMS_GATEWAY_URL") if channel == "sms" else os.environ.get("WA_URL")
    token = os.environ.get("SMS_GATEWAY_TOKEN") if channel == "sms" else os.environ.get("WA_TOKEN")
    if not url:
        raise RuntimeError(f"{channel} gateway not configured")

    body = json.dumps({
        "to": dest,
        "message": f"Kode verifikasi kamu: {code}. Berlaku {ttl // 60} menit. Jangan bagikan.",
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
        send_http_gateway(dest, code, ttl, channel)
    else:
        raise RuntimeError("unknown channel")


# ------------------------------------------------------------------------ models
class SendIn(BaseModel):
    channel: str = Field(default="email", description="email | sms | whatsapp")
    destination: str
    purpose: str | None = None


class VerifyIn(BaseModel):
    channel: str = Field(default="email")
    destination: str
    code: str


# ------------------------------------------------------------------------ routes
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
    proj = project_from_key(x_api_key)
    dest = normalise(body.channel, body.destination)

    if daily_count(proj["id"]) >= DAILY_QUOTA:
        raise HTTPException(429, "daily quota reached for this key")

    elapsed = now() - last_send_at(proj["id"], dest)
    if elapsed < COOLDOWN:
        raise HTTPException(429, f"wait {COOLDOWN - elapsed}s before resending")

    code = f"{secrets.randbelow(1_000_000):06d}"
    salt = secrets.token_hex(16)
    expires = now() + CODE_TTL

    try:
        deliver(body.channel, dest, code, CODE_TTL)
    except Exception as exc:  # noqa: BLE001
        record_send(proj["id"], body.channel, dest, False, str(exc)[:200])
        raise HTTPException(502, f"delivery failed: {exc}") from exc

    with db() as con:
        con.execute(
            "DELETE FROM codes WHERE project_id=? AND destination=? AND consumed_at IS NULL",
            (proj["id"], dest),
        )
        con.execute(
            "INSERT INTO codes(project_id,channel,destination,code_hash,salt,created_at,expires_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (proj["id"], body.channel, dest, sha(salt + code), salt, now(), expires),
        )
    record_send(proj["id"], body.channel, dest, True, None)

    out: dict[str, Any] = {
        "ok": True,
        "channel": body.channel,
        "destination": dest,
        "expires_in": CODE_TTL,
    }
    if os.environ.get("OTP_DEV_MODE") == "1":
        out["dev_code"] = code      # only for local testing
    return out


@app.post("/v1/otp/verify")
def otp_verify(body: VerifyIn, x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    proj = project_from_key(x_api_key)
    dest = normalise(body.channel, body.destination)
    code = body.code.strip()

    with db() as con:
        row = con.execute(
            "SELECT * FROM codes WHERE project_id=? AND destination=?"
            " AND consumed_at IS NULL ORDER BY id DESC LIMIT 1",
            (proj["id"], dest),
        ).fetchone()

        if not row:
            raise HTTPException(404, "no active code for this destination")
        if row["expires_at"] < now():
            con.execute("UPDATE codes SET consumed_at=? WHERE id=?", (now(), row["id"]))
            raise HTTPException(410, "code expired")
        if row["attempts"] >= MAX_ATTEMPTS:
            con.execute("UPDATE codes SET consumed_at=? WHERE id=?", (now(), row["id"]))
            raise HTTPException(429, "too many attempts")

        good = hmac.compare_digest(row["code_hash"], sha(row["salt"] + code))
        if not good:
            con.execute("UPDATE codes SET attempts=attempts+1 WHERE id=?", (row["id"],))
            left = MAX_ATTEMPTS - (row["attempts"] + 1)
            raise HTTPException(401, f"wrong code, {max(left, 0)} attempts left")

        con.execute("UPDATE codes SET consumed_at=? WHERE id=?", (now(), row["id"]))

    return {"ok": True, "verified": True, "destination": dest}


# --------------------------------------------------------------------- dashboard
@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return """<!doctype html><meta charset=utf-8><title>Nebula OTP</title>
<style>
 body{background:#0b0d10;color:#e6e6e6;font:15px/1.6 ui-sans-serif,system-ui;margin:0;padding:40px}
 .wrap{max-width:760px;margin:auto}
 h1{font-size:22px;letter-spacing:.5px;margin:0 0 4px}
 .sub{color:#7d8590;font-size:13px;margin-bottom:28px}
 .card{background:#12161b;border:1px solid #222a33;border-radius:10px;padding:20px;margin-bottom:16px}
 label{display:block;font-size:12px;color:#8b949e;margin:12px 0 6px;text-transform:uppercase;letter-spacing:.6px}
 input,select{width:100%;background:#0b0f14;border:1px solid #2a333d;color:#e6e6e6;
   padding:10px 12px;border-radius:7px;font:14px ui-monospace,monospace;box-sizing:border-box}
 button{background:#2f81f7;color:#fff;border:0;padding:11px 20px;border-radius:7px;
   font-weight:600;cursor:pointer;margin-top:16px}
 button:hover{background:#4a94ff}
 pre{background:#0b0f14;border:1px solid #222a33;padding:14px;border-radius:7px;
   overflow:auto;font-size:12.5px;color:#9fe8b0;margin-top:16px}
 .row{display:flex;gap:12px}.row>*{flex:1}
</style>
<div class=wrap>
 <h1>Nebula OTP</h1>
 <div class=sub>Layanan pengiriman kode verifikasi untuk website &amp; bot</div>

 <div class=card>
  <label>API key</label>
  <input id=key placeholder="otp_...">
  <div class=row>
   <div><label>Channel</label>
    <select id=ch><option>email</option><option>sms</option><option>whatsapp</option></select></div>
   <div><label>Tujuan</label><input id=dest placeholder="user@mail.com / 0812..."></div>
  </div>
  <button onclick=sendCode()>Kirim kode</button>
  <label>Kode yang diterima</label>
  <input id=code placeholder="6 digit">
  <button onclick=verifyCode()>Verifikasi</button>
  <pre id=out>siap.</pre>
 </div>
</div>
<script>
const out=document.getElementById('out');
const show=o=>out.textContent=JSON.stringify(o,null,2);
async function sendCode(){
  const r=await fetch('/v1/otp/send',{method:'POST',
    headers:{'Content-Type':'application/json','X-API-Key':key.value},
    body:JSON.stringify({channel:ch.value,destination:dest.value})});
  show(await r.json());
}
async function verifyCode(){
  const r=await fetch('/v1/otp/verify',{method:'POST',
    headers:{'Content-Type':'application/json','X-API-Key':key.value},
    body:JSON.stringify({channel:ch.value,destination:dest.value,code:code.value})});
  show(await r.json());
}
</script>"""


# ------------------------------------------------------------------- admin keys
@app.post("/v1/admin/projects")
def create_project(name: str, request: Request) -> JSONResponse:
    if not ADMIN_TOKEN or request.headers.get("x-admin-token") != ADMIN_TOKEN:
        raise HTTPException(403, "admin token required")
    raw = "otp_" + secrets.token_urlsafe(24)
    with db() as con:
        con.execute(
            "INSERT INTO projects(name,key_hash,key_prefix,created_at) VALUES(?,?,?,?)",
            (name, sha(raw), raw[:12], now()),
        )
    return JSONResponse({"ok": True, "name": name, "api_key": raw},
                        headers={"Cache-Control": "no-store"})


@app.get("/v1/admin/stats")
def stats(request: Request) -> dict[str, Any]:
    if not ADMIN_TOKEN or request.headers.get("x-admin-token") != ADMIN_TOKEN:
        raise HTTPException(403, "admin token required")
    with db() as con:
        p = con.execute("SELECT COUNT(*) c FROM projects WHERE revoked=0").fetchone()["c"]
        s = con.execute("SELECT COUNT(*) c FROM sends").fetchone()["c"]
        ok = con.execute("SELECT COUNT(*) c FROM sends WHERE ok=1").fetchone()["c"]
    return {"projects": p, "sends": s, "delivered": ok}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8099")))
