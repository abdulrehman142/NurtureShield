import { API_ORIGIN, REQUEST_TIMEOUT_MS, MAX_URL_LENGTH } from "./config.js";

export class ShieldError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

export function validateUrl(value) {
  if (typeof value !== "string" || !value.trim()) throw new ShieldError("validation", "Paste a link to check.");
  const text = value.trim();
  if (text.length > MAX_URL_LENGTH || /[\s\u0000-\u001f\u007f\\]/u.test(text)) {
    throw new ShieldError("validation", "Enter a link of up to 8,192 characters without spaces or control characters.");
  }
  try {
    const parsed = new URL(text.includes("://") ? text : `https://${text}`);
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname ||
        (!parsed.hostname.includes(".") && !parsed.hostname.startsWith("["))) throw new Error();
  } catch { throw new ShieldError("validation", "Enter a valid HTTP(S) URL or domain name."); }
  // URL() is validation only. Preserve the original text for backend canonicalization.
  return text;
}

export function validateAssessment(data) {
  if (!data || typeof data.url !== "string" || data.url.length > MAX_URL_LENGTH ||
      !["malicious", "legitimate"].includes(data.prediction) ||
      !Number.isFinite(data.malicious_probability) || data.malicious_probability < 0 || data.malicious_probability > 1 ||
      !["low", "moderate", "elevated", "high"].includes(data.risk_level) ||
      !Array.isArray(data.observed_characteristics) || data.observed_characteristics.length > 50 ||
      data.observed_characteristics.some(item => typeof item !== "string" || item.length > 1000)) {
    throw new ShieldError("response", "NurtureNet returned an unexpected response. Please try again.");
  }
  return data;
}

export function createApiClient({ origin = API_ORIGIN, fetchImpl = globalThis.fetch, timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
  const trusted = new URL(origin);
  if (trusted.origin !== origin || trusted.username || trusted.password ||
      !(trusted.protocol === "https:" || (trusted.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(trusted.hostname)))) {
    throw new Error("Configure an exact HTTPS backend origin, or HTTP loopback for development.");
  }
  return async function analyze(value) {
    const url = validateUrl(value);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    async function request(path, options = {}) {
      // These are the only two network destinations this client can construct.
      if (path !== "/api/v1/nurtureshield/analyze") throw new Error("Invalid endpoint");
      const response = await fetchImpl(origin + path, {
        ...options, credentials: "include", cache: "no-store", redirect: "error", signal: controller.signal,
      });
      if (response.status === 403) throw new ShieldError("forbidden", "Access denied. Ask the administrator to allow this extension ID.");
      if (response.status === 422) throw new ShieldError("validation", "Enter a valid HTTP(S) URL or domain name.");
      if (response.status === 429) throw new ShieldError("rate", "Too many checks. Please wait and try again.");
      if (!response.ok) throw new ShieldError("service", "NurtureShield is temporarily unavailable. Please try again later.");
      try { return await response.json(); }
      catch { throw new ShieldError("response", "NurtureNet returned an unexpected response. Please try again."); }
    }
    try {
      return validateAssessment(await request("/api/v1/nurtureshield/analyze", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      }));
    } catch (error) {
      if (error instanceof ShieldError) throw error;
      throw new ShieldError(controller.signal.aborted ? "timeout" : "network",
        controller.signal.aborted ? "Analysis timed out. Please try again." : "Unable to reach NurtureNet. Check that the configured server is running.");
    } finally { clearTimeout(timer); }
  };
}
