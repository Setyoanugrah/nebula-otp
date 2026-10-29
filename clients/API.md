# Nebula OTP — API cheat sheet

BASE=http://127.0.0.1:8099
KEY=otp_xxxxxxxxxxxxxxxxxxxxxxxx

# 1. health (no auth)
curl -s $BASE/v1/health

# 2. kirim kode
curl -s -X POST $BASE/v1/otp/send \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{"channel":"email","destination":"user@mail.com"}'

# 3. verifikasi
curl -s -X POST $BASE/v1/otp/verify \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{"channel":"email","destination":"user@mail.com","code":"123456"}'

# 4. SMS (butuh gateway dikonfigurasi)
curl -s -X POST $BASE/v1/otp/send \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{"channel":"sms","destination":"08123456789"}'

# 5. bikin project/key baru (admin)
curl -s -X POST "$BASE/v1/admin/projects?name=myapp" -H "x-admin-token: $ADMIN"

# 6. statistik (admin)
curl -s $BASE/v1/admin/stats -H "x-admin-token: $ADMIN"

# Status code
#  200 ok          401 key salah / kode salah      404 belum ada kode
#  410 kedaluwarsa 422 tujuan tidak valid          429 cooldown / kuota / terlalu banyak percobaan
#  502 provider menolak kirim
