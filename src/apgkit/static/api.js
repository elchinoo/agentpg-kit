// Fetch wrapper: same-origin cookies, a CSRF header on writes, readable errors. No credentials are kept in JS.
// The CSRF header name comes from <html data-csrf="X-App-CSRF">, so every app can use its own.

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function describe(detail, status) {
  if (typeof detail === "string" && detail) return detail;
  if (Array.isArray(detail)) return detail.map((d) => `${(d.loc || []).filter((x) => x !== "body").join(".")}: ${d.msg}`).join("; ");
  if (status === 502 || status === 503 || status === 504) return "The server is unavailable. It may be paused or waking up; wait a few seconds and try again.";
  return `Request failed (${status})`;
}

export async function api(path, { method = "GET", json, body, headers = {} } = {}) {
  const h = { ...headers };
  let payload = body;
  if (json !== undefined) {
    h["Content-Type"] = "application/json";
    payload = JSON.stringify(json);
  }
  if (method !== "GET") h[document.documentElement.dataset.csrf || "X-CSRF"] = "1";
  const r = await fetch(path, { method, headers: h, body: payload, credentials: "same-origin" });
  if (!r.ok) {
    let detail = "";
    try { detail = (await r.json()).detail; } catch { /* not JSON, e.g. a proxy error page */ }
    const err = new ApiError(r.status, describe(detail, r.status));
    if (r.status === 401 && !path.startsWith("/api/login") && !path.startsWith("/api/setup") && !path.startsWith("/login")) {
      window.dispatchEvent(new CustomEvent("apg-auth-lost"));
    }
    if (r.status === 423) window.dispatchEvent(new CustomEvent("apg-vault-locked"));
    throw err;
  }
  return r.json();
}
