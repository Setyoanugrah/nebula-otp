# Nebula OTP

Layanan pengiriman kode verifikasi (OTP) untuk website, bot, atau aplikasi.
Kirim kode lewat email / SMS / WhatsApp, verifikasi lewat satu endpoint.

## Isi paket

```
app.py              service (FastAPI + SQLite)
requirements.txt    dependensi
sink.py             SMTP sink lokal buat tes tanpa kredensial
clients/
  otp_client.py     client Python
  otp_client.js     client JS (Node / browser)
  express_proxy.js  contoh backend Express (API key aman di server)
  fastapi_example.py contoh route FastAPI
  API.md            cheat sheet curl + daftar status code
```

## Jalankan

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
export SMTP_HOST=smtp.gmail.com SMTP_PORT=465 SMTP_USER=you@gmail.com \
       SMTP_PASS=app_password SMTP_FROM=you@gmail.com \
       OTP_ADMIN_TOKEN=rahasia OTP_DB=./otp.db PORT=8099
.venv/bin/python app.py
```

Buka `http://127.0.0.1:8099/` untuk dashboard, atau `GET /v1/health`.

## Bikin API key

```bash
curl -X POST "http://127.0.0.1:8099/v1/admin/projects?name=websiteku" \
     -H "x-admin-token: rahasia"
# -> {"api_key":"otp_...", ...}  simpan, hanya muncul sekali
```

## Pakai dari aplikasi

```python
from otp_client import OTPClient

otp = OTPClient()                      # baca OTP_API_KEY / OTP_BASE_URL dari env
otp.send("user@mail.com")              # kirim kode
ok = otp.verify("user@mail.com", "123456")   # True / False
```

## Kanal

| channel | transport | syarat |
|---|---|---|
| `email` | SMTP | host/user/pass (Gmail butuh App Password, bukan password akun) |
| `sms` | HTTP gateway | `SMS_GATEWAY_URL` + token — agregator atau app SMS gateway di HP |
| `whatsapp` | HTTP gateway | `WA_URL` + token |

VPS tidak punya modem GSM, jadi SMS tidak bisa dikirim langsung dari server.
Isi `SMS_GATEWAY_URL` dengan API agregator, atau jalankan app gateway di HP ber-SIM.

## Keamanan yang sudah terpasang

- Kode disimpan `sha256(salt + code)`, bukan plaintext
- Satu kode aktif per tujuan; kirim ulang membatalkan yang lama
- Cooldown 60 detik per tujuan (anti SMS-bombing)
- Kuota 200 kirim/hari per API key
- Maksimal 5 percobaan verifikasi, lalu kode dibakar
- Perbandingan constant-time (`hmac.compare_digest`)
- API key disimpan sebagai hash, prefix terlihat untuk identifikasi di log
- `OTP_DEV_MODE=1` membocorkan kode di response — jangan pernah di produksi

## Status code

| code | arti |
|---|---|
| 200 | berhasil |
| 401 | API key salah, atau kode salah |
| 404 | belum ada kode aktif untuk tujuan itu |
| 410 | kode kedaluwarsa |
| 422 | tujuan tidak valid |
| 429 | cooldown / kuota habis / terlalu banyak percobaan |
| 502 | provider menolak mengirim |

## Konfigurasi

| env | default | keterangan |
|---|---|---|
| `OTP_DB` | `/var/lib/otpsvc/otp.db` | lokasi SQLite |
| `OTP_TTL` | `300` | umur kode (detik) |
| `OTP_COOLDOWN` | `60` | jeda kirim ulang per tujuan |
| `OTP_MAX_ATTEMPTS` | `5` | percobaan verifikasi |
| `OTP_DAILY_QUOTA` | `200` | kirim per key per hari |
| `OTP_ADMIN_TOKEN` | — | wajib untuk endpoint admin |
| `OTP_DEV_MODE` | `0` | `1` = kode ikut di response |
| `SMTP_TLS` | `1` | `0` untuk sink lokal / relay tanpa STARTTLS |
