# Materi jualan Nebula OTP

## Target pembeli

Yang paling mungkin butuh dan paling cepat closing:

1. **Developer indie / freelancer** yang bikin website klien dan butuh verifikasi email.
   Mereka benci daftar Twilio/Firebase (kartu kredit, harga dolar).
2. **Pemilik toko online kecil** yang mau verifikasi nomor pembeli sebelum COD.
3. **Admin grup / komunitas** yang punya bot Telegram atau WhatsApp dan mau verifikasi member.
4. **Agency / studio kecil** yang handle banyak project dan butuh satu vendor OTP saja.
5. **Mahasiswa / tugas akhir** yang butuh OTP untuk demo, tidak mau bayar SaaS asing.

## Kalimat pembuka (DM)

> Halo, saya bikin layanan OTP — kirim kode verifikasi lewat email/SMS/WhatsApp
> buat website atau bot. Bedanya sama Twilio/Firebase: harga rupiah, bayar per kode,
> nggak perlu kartu kredit, dan integrasinya cuma 2 endpoint.
>
> Kalau kamu atau klien kamu ada project yang butuh verifikasi email/nomor,
> saya kasih 100 kode gratis buat coba. Minat?

## Kalimat untuk grup developer

> **[Jasa] OTP service lokal — bayar per kode**
>
> Buat yang lagi bikin project dan butuh verifikasi email/HP tapi males setup
> SMTP sendiri atau daftar Twilio:
>
> - Kirim OTP lewat email / SMS / WhatsApp
> - API 2 endpoint, integrasi 5 menit
> - Kode disimpan sebagai hash, ada cooldown anti-spam, kuota harian
> - Harga: Rp75/1000 email, Rp450/SMS
> - Gratis 100 kode buat nyoba
>
> Contoh integrasi & dokumentasi saya kirim kalau minat. Bisa custom kalau butuh
> branding sendiri (white-label).

## Jawaban kalau ditanya "kenapa nggak pakai Firebase/Twilio aja?"

> Boleh, kalau butuh ekosistem besar. Bedanya di sini:
> - **Harga**: Twilio ~$0.0075/SMS + markup, bayar dolar pakai kartu. Di sini rupiah, per kode.
> - **Setup**: Firebase Auth ngunci kamu ke ekosistem mereka. Di sini cukup 2 request HTTP.
> - **Kontrol**: kamu bisa minta kanal sendiri, template pesan sendiri, bahkan white-label.
> - **Lokal**: nomor Indonesia, harga Indonesia, support bisa bahasa Indonesia.
>
> Kalau project-nya kecil sampai menengah, ini lebih murah dan lebih simpel.

## Jawaban kalau ditanya "aman nggak?"

> Yang sudah terpasang di sistem:
> - Kode disimpan sebagai SHA-256 + salt, bukan teks biasa — bocor database pun kode tetap aman
> - Satu kode aktif per tujuan; kirim ulang membatalkan yang lama
> - Cooldown 60 detik per nomor (anti SMS bombing)
> - Maksimal 5 percobaan verifikasi, lalu kode dibakar
> - Kuota harian per API key
> - Perbandingan constant-time, tidak bisa ditebak lewat timing
>
> Semua ini sudah saya tes end-to-end, bukan cuma klaim.

## Paket harga (saran)

| paket | isi | harga |
|---|---|---|
| Coba | 100 kode email | gratis |
| Email | 1.000 kode email | Rp75.000 |
| Email Pro | 10.000 kode email | Rp600.000 |
| SMS | per kode SMS | Rp450 |
| White-label | domain & branding sendiri | nego |

Harga di atas sengaja murah untuk masuk pasar. Naikkan setelah ada 5-10 pelanggan tetap.

## Channel untuk nyari pembeli

- Grup Telegram/Discord developer Indonesia
- Grup Facebook: "Programmer Indonesia", "Web Developer Indonesia"
- Twitter/X dengan tagar #buildinpublic #indiehacker
- Forum Kaskus (Layanan Jasa)
- LinkedIn: tawarkan ke agency kecil
- WhatsApp: tawarkan ke kenalan yang punya toko online

## Yang perlu disiapkan sebelum jualan

1. **Hosting permanen** — box GitHub Actions cuma hidup 6 jam lalu restart, URL-nya berubah.
   Beli VPS Rp30-50rb/bulan (Contabo, Hetzner, atau lokal), copy folder ini, isi env yang sama.
2. **Domain** — misal `nebulaotp.id` (~Rp150rb/tahun). Ini yang bikin kelihatan serius.
3. **Cara terima pembayaran** — QRIS (paling gampang), atau Midtrans/Xendit kalau mau otomatis.
4. **Landing page** — sudah ada di `site/index.html`, tinggal ganti nomor kontak.
5. **Template pesan** — bikin 2-3 varian supaya pelanggan bisa pilih nada bicaranya.

## Catatan penting

- **Jangan jual SMS sebelum punya gateway.** Sistemnya sudah siap, tapi butuh
  `SMS_GATEWAY_URL` yang diisi API agregator (Telnyx, Vonage, atau lokal) — itu biaya per SMS.
  Mulai dari email dulu, itu sudah jalan penuh.
- **Gmail gratis ada batas ~500 email/hari.** Kalau pelanggan makin banyak, pindah ke
  Brevo (300/hari gratis) atau Resend, lalu ke SMTP berbayar.
- **Repo public, database private.** Sudah dipisah: kode di `nebula-otp` (public, unlimited
  runner), backup DB di `nebula-otp-backup` (private). Jangan pernah taruh data pelanggan di repo public.
