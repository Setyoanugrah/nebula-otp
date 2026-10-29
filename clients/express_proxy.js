// Backend proxy for a website. The API key stays here, never in the browser.
// npm i express express-rate-limit
import express from "express";
import rateLimit from "express-rate-limit";
import { OTPClient } from "./otp_client.js";

const app = express();
app.use(express.json());
const otp = new OTPClient({
  apiKey: process.env.OTP_API_KEY,
  baseUrl: process.env.OTP_BASE_URL,
});

// your own limiter in front of the service, per IP
const limiter = rateLimit({ windowMs: 60_000, max: 5 });

app.post("/api/otp/send", limiter, async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes("@")) {
    return res.status(422).json({ error: "email tidak valid" });
  }
  try {
    const out = await otp.send(email);
    res.json({ ok: true, expires_in: out.expires_in });
  } catch (e) {
    // 429 = cooldown or quota, 502 = provider refused
    res.status(e.status || 500).json({ error: e.message });
  }
});

app.post("/api/otp/verify", limiter, async (req, res) => {
  const { email, code } = req.body;
  try {
    const ok = await otp.verify(email, String(code));
    if (!ok) return res.status(401).json({ error: "kode salah atau kedaluwarsa" });
    // issue your own session/JWT here
    res.json({ ok: true });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

app.listen(3000, () => console.log("listening on :3000"));
