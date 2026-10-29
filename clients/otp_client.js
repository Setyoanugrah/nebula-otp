/**
 * Nebula OTP client — browser or Node.
 * In the browser, never ship the API key: proxy through your own backend.
 */
export class OTPClient {
  constructor({ apiKey, baseUrl = "http://127.0.0.1:8099" }) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  async #post(path, payload) {
    const res = await fetch(this.baseUrl + path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": this.apiKey },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.detail || res.statusText);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  send(destination, channel = "email") {
    return this.#post("/v1/otp/send", { channel, destination });
  }

  async verify(destination, code, channel = "email") {
    try {
      const r = await this.#post("/v1/otp/verify", { channel, destination, code });
      return r.verified === true;
    } catch (e) {
      if ([401, 404, 410, 429].includes(e.status)) return false;
      throw e;
    }
  }

  health() {
    return fetch(this.baseUrl + "/v1/health").then((r) => r.json());
  }
}
