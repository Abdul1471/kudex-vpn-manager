const API_VERSION = "1.1.0";

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });

function clientIP(request) {
  // Cloudflare overwrites this header at its edge. Never accept a client-supplied IP field.
  return request.headers.get("CF-Connecting-IP") || "";
}

function validIP(value) {
  if (typeof value !== "string" || value.length > 45) return false;
  if (value.includes(".")) {
    const parts = value.split(".");
    return parts.length === 4 && parts.every(p =>
      /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255
    );
  }
  // Accept IPv6 literals only; reject hostnames, zones, and bracketed values.
  return value.includes(":") &&
    /^[0-9a-f:]+$/i.test(value) &&
    value.split(":").length >= 3;
}

function safeEqual(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

function isAdmin(request, env) {
  const key = env.ADMIN_API_KEY;
  const header = request.headers.get("Authorization") || "";
  return Boolean(key && header.startsWith("Bearer ") &&
    safeEqual(header.slice(7), key));
}

async function getLicense(env, ip) {
  return env.DB.prepare(
    `SELECT ip_address, license_type, status, created_at, expires_at, updated_at
     FROM vps_licenses WHERE ip_address = ?`
  ).bind(ip).first();
}

function licenseResult(row, now) {
  if (!row) return { authenticated: false, reason: "no_license" };
  if (row.status !== "active") return { authenticated: false, reason: "revoked" };
  if (row.expires_at !== null && row.expires_at <= now) {
    return {
      authenticated: false,
      reason: "expired",
      license_type: row.license_type,
      expires_at: row.expires_at
    };
  }
  return {
    authenticated: true,
    reason: "valid",
    license_type: row.license_type,
    expires_at: row.expires_at
  };
}

async function readJSON(request) {
  if (!(request.headers.get("Content-Type") || "").toLowerCase().includes("application/json")) {
    throw new Error("Content-Type must be application/json");
  }
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > 4096) throw new Error("Request body too large");
  return request.json();
}

async function handle(request, env) {
  if (!env.DB || !env.ADMIN_API_KEY) {
    return json({ error: "API configuration incomplete" }, 503);
  }

  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const now = Math.floor(Date.now() / 1000);

  if (method === "GET" && path === "/") {
    return json({ service: "KudexTech License API", status: "online", version: API_VERSION });
  }

  if (method === "POST" && path === "/trialip") {
    const ip = clientIP(request);
    if (!validIP(ip)) return json({ registered: false, error: "Cloudflare client IP unavailable or invalid" }, 400);

    const expires = now + 86400;
    const result = await env.DB.prepare(
      `INSERT OR IGNORE INTO vps_licenses
       (ip_address, license_type, status, created_at, expires_at, updated_at)
       VALUES (?, 'trial', 'active', ?, ?, ?)`
    ).bind(ip, now, expires, now).run();

    if (result.meta.changes !== 1) {
      const existing = await getLicense(env, ip);
      return json({
        registered: false,
        message: "A license record already exists for this VPS IP.",
        ...licenseResult(existing, now)
      }, 409);
    }

    const row = await getLicense(env, ip);
    return json({
      registered: true,
      message: "24-hour trial registered.",
      ...licenseResult(row, now)
    }, 201);
  }

  if (method === "POST" && path === "/api/authenticate") {
    const ip = clientIP(request);
    if (!validIP(ip)) return json({ authenticated: false, reason: "ip_unavailable" }, 400);
    return json(licenseResult(await getLicense(env, ip), now));
  }

  if (path.startsWith("/api/admin/")) {
    if (!isAdmin(request, env)) return json({ error: "Unauthorized" }, 401);

    if (method === "GET" && path === "/api/admin/licenses") {
      const rows = await env.DB.prepare(
        `SELECT ip_address, license_type, status, created_at, expires_at, updated_at
         FROM vps_licenses ORDER BY created_at DESC LIMIT 100`
      ).all();
      return json({ licenses: rows.results || [] });
    }

    if (method === "GET" && path === "/api/admin/license") {
      const ip = url.searchParams.get("ip_address") || "";
      if (!validIP(ip)) return json({ error: "A valid ip_address query parameter is required" }, 400);
      const row = await getLicense(env, ip);
      return row ? json({ license: row }) : json({ error: "License not found" }, 404);
    }

    if (method === "POST" && path === "/api/admin/license/create") {
      let body;
      try { body = await readJSON(request); }
      catch (error) { return json({ error: error.message || "Invalid JSON" }, 400); }

      const ip = String(body.ip_address || "").trim();
      const type = String(body.license_type || "").trim();
      if (!validIP(ip)) return json({ error: "A valid IPv4 or IPv6 address is required" }, 400);
      if (!["30_days", "lifetime"].includes(type)) {
        return json({ error: "license_type must be 30_days or lifetime" }, 400);
      }

      const expires = type === "30_days" ? now + 30 * 86400 : null;
      await env.DB.prepare(
        `INSERT INTO vps_licenses
         (ip_address, license_type, status, created_at, expires_at, updated_at)
         VALUES (?, ?, 'active', ?, ?, ?)
         ON CONFLICT(ip_address) DO UPDATE SET
           license_type=excluded.license_type, status='active',
           created_at=excluded.created_at, expires_at=excluded.expires_at,
           updated_at=excluded.updated_at`
      ).bind(ip, type, now, expires, now).run();

      return json({ created: true, license: await getLicense(env, ip) }, 201);
    }

    if (method === "POST" && path === "/api/admin/license/revoke") {
      let body;
      try { body = await readJSON(request); }
      catch (error) { return json({ error: error.message || "Invalid JSON" }, 400); }

      const ip = String(body.ip_address || "").trim();
      if (!validIP(ip)) return json({ error: "A valid IPv4 or IPv6 address is required" }, 400);

      const result = await env.DB.prepare(
        "UPDATE vps_licenses SET status='revoked', updated_at=? WHERE ip_address=?"
      ).bind(now, ip).run();
      if (result.meta.changes !== 1) return json({ error: "License not found" }, 404);
      return json({ revoked: true, ip_address: ip });
    }

    return json({ error: "Admin endpoint not found" }, 404);
  }

  return json({ error: "Endpoint not found" }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch {
      // Do not return database details, SQL, or secrets to callers.
      return json({ error: "Internal server error" }, 500);
    }
  }
};
