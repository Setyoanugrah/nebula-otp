"""Nebula OTP client — drop this into any Python app."""
from __future__ import annotations

import os
from typing import Any

import requests


class OTPError(Exception):
    """Raised when the service refuses the request."""

    def __init__(self, status: int, detail: str):
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail


class OTPClient:
    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        self.api_key = api_key or os.environ["OTP_API_KEY"]
        self.base_url = (base_url or os.environ.get("OTP_BASE_URL", "http://127.0.0.1:8099")).rstrip("/")

    def _post(self, path: str, payload: dict) -> dict[str, Any]:
        r = requests.post(
            self.base_url + path,
            json=payload,
            headers={"X-API-Key": self.api_key},
            timeout=30,
        )
        data = r.json() if r.content else {}
        if r.status_code >= 400:
            raise OTPError(r.status_code, data.get("detail", r.text[:200]))
        return data

    def send(self, destination: str, channel: str = "email") -> dict[str, Any]:
        return self._post("/v1/otp/send", {"channel": channel, "destination": destination})

    def verify(self, destination: str, code: str, channel: str = "email") -> bool:
        try:
            return bool(self._post("/v1/otp/verify",
                                   {"channel": channel, "destination": destination,
                                    "code": code}).get("verified"))
        except OTPError as e:
            if e.status in (401, 404, 410, 429):
                return False
            raise

    def health(self) -> dict[str, Any]:
        return requests.get(self.base_url + "/v1/health", timeout=10).json()
