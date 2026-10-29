"""Wire the OTP client into an existing FastAPI app."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr

from otp_client import OTPClient, OTPError

app = FastAPI()
otp = OTPClient()          # reads OTP_API_KEY / OTP_BASE_URL from env


class SendIn(BaseModel):
    email: EmailStr


class VerifyIn(BaseModel):
    email: EmailStr
    code: str


@app.post("/api/otp/send")
def send_otp(body: SendIn):
    try:
        return otp.send(body.email)
    except OTPError as e:
        raise HTTPException(e.status, e.detail)


@app.post("/api/otp/verify")
def verify_otp(body: VerifyIn):
    if not otp.verify(body.email, body.code):
        raise HTTPException(401, "kode salah atau kedaluwarsa")
    return {"ok": True}
