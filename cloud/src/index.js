/** Cloud stores opted-in metadata only; never authorizes or executes agent tools. */
const DAY = 86400,
  now = () => Math.floor(Date.now() / 1000);
const OPS = new Set([
  "read_file",
  "write_file",
  "api_get",
  "api_post",
  "isolated_read",
  "isolated_write",
  "wasm_run",
  "unknown",
]);
const REASONS = new Set([
  "authorized",
  "denied",
  "approval_required",
  "policy_blocked",
  "expired",
  "invalid",
  "execution_failed",
  "unknown",
]);
const DECISIONS = new Set(["ALLOW", "DENY", "REQUIRE_APPROVAL"]);
const random = () => {
  const a = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...a))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
};
const digest = async (s) =>
  new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)),
  );
const hash = async (s) =>
  [...(await digest(s))].map((x) => x.toString(16).padStart(2, "0")).join("");
const fail = (status, code) => {
  throw Object.assign(new Error(code), { status, code, publicFailure: true });
};
const json = (v, status = 200, headers = {}) =>
  new Response(JSON.stringify(v), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      ...headers,
    },
  });
const exact = (o, keys) =>
  o &&
  typeof o === "object" &&
  !Array.isArray(o) &&
  Object.keys(o).sort().join(",") === [...keys].sort().join(",");
const dev = (env) =>
  env.DEV_MODE === "true" &&
  new URL(env.PUBLIC_ORIGIN).hostname === "127.0.0.1";
const sessionName = (env) =>
  dev(env) ? "sentinel_session" : "__Host-sentinel_session";
const oauthName = (env) =>
  dev(env) ? "sentinel_oauth" : "__Host-sentinel_oauth";
const cookie = (req, name) => {
  const a = (req.headers.get("Cookie") || "")
    .split(";")
    .map((x) => x.trim())
    .filter((x) => x.startsWith(name + "="));
  return a.length === 1 ? a[0].slice(name.length + 1) : "";
};
const setCookie = (env, name, value, age) =>
  `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${dev(env) ? "" : "; Secure"}`;
const stmt = (env, sql, ...args) => env.DB.prepare(sql).bind(...args);
const first = (env, sql, ...args) => stmt(env, sql, ...args).first();
const run = (env, sql, ...args) => stmt(env, sql, ...args).run();
async function body(req) {
  if (
    !/^application\/json(?:\s*;|$)/i.test(req.headers.get("Content-Type") || "")
  )
    fail(415, "json_required");
  const reader = req.body?.getReader();
  let size = 0,
    parts = [];
  if (reader)
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 32768) {
        await reader.cancel();
        fail(413, "body_too_large");
      }
      parts.push(value);
    }
  const bytes = new Uint8Array(size);
  let pos = 0;
  for (const p of parts) {
    bytes.set(p, pos);
    pos += p.length;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    fail(400, "invalid_json");
  }
}
async function rate(env, key, limit, seconds) {
  const time = now(),
    bucket = key + ":" + Math.floor(time / seconds);
  const result = await first(
    env,
    "INSERT INTO rates(bucket,count,expires_at) VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1 WHERE count<? RETURNING count",
    bucket,
    time + seconds,
    limit,
  );
  if (!result) fail(429, "rate_limited");
}
function origin(req, env) {
  if (req.headers.get("Origin") !== env.PUBLIC_ORIGIN)
    fail(403, "origin_rejected");
}
async function user(req, env, mutate = false) {
  const token = cookie(req, sessionName(env));
  if (!/^[\w-]{43}$/.test(token)) fail(401, "authentication_required");
  const row = await first(
    env,
    "SELECT s.*,u.login FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.hash=? AND s.expires_at>?",
    await hash(token),
    now(),
  );
  if (!row) fail(401, "authentication_required");
  if (mutate) {
    origin(req, env);
    if (req.headers.get("X-CSRF-Token") !== row.csrf)
      fail(403, "csrf_rejected");
  }
  return row;
}
async function device(req, env) {
  const value = req.headers.get("Authorization") || "";
  if (!/^Bearer [\w-]{43}$/.test(value))
    fail(401, "device_authentication_required");
  const row = await first(
    env,
    "SELECT d.*,u.sync_enabled FROM devices d JOIN users u ON u.id=d.user_id WHERE d.token_hash=? AND d.revoked_at IS NULL AND d.expires_at>?",
    await hash(value.slice(7)),
    now(),
  );
  if (!row) fail(401, "device_authentication_required");
  return row;
}
async function newSession(env, id, login, old = "") {
  const token = random(),
    csrf = random(),
    time = now();
  const batch = [
    stmt(
      env,
      "INSERT INTO users(id,login,created_at) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET login=excluded.login",
      id,
      login,
      time,
    ),
  ];
  batch.push(stmt(env, "DELETE FROM sessions WHERE user_id=? AND hash NOT IN (SELECT hash FROM sessions WHERE user_id=? ORDER BY authenticated_at DESC LIMIT 4)", id, id));
  if (old)
    batch.push(stmt(env, "DELETE FROM sessions WHERE hash=?", await hash(old)));
  batch.push(
    stmt(
      env,
      "INSERT INTO sessions(hash,user_id,csrf,expires_at,authenticated_at) VALUES(?,?,?,?,?)",
      await hash(token),
      id,
      csrf,
      time + 3600,
      time,
    ),
  );
  await env.DB.batch(batch);
  return { token, csrf };
}
export function validateEvent(e) {
  return !!(
    exact(e, [
      "event_id",
      "timestamp",
      "operation",
      "decision",
      "executed",
      "reason_code",
    ]) &&
    typeof e.event_id === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      e.event_id,
    ) &&
    Number.isSafeInteger(e.timestamp) &&
    e.timestamp >= now() - 30 * DAY &&
    e.timestamp <= now() + 300 &&
    OPS.has(e.operation) &&
    DECISIONS.has(e.decision) &&
    typeof e.executed === "boolean" &&
    (!e.executed || e.decision === "ALLOW") &&
    REASONS.has(e.reason_code)
  );
}
export async function cleanup(env) {
  const time = now();
  await env.DB.batch([
    stmt(env, "DELETE FROM events WHERE received_at<?", time - 30 * DAY),
    stmt(env, "DELETE FROM sessions WHERE expires_at<=?", time),
    stmt(env, "DELETE FROM oauth_states WHERE expires_at<=?", time),
    stmt(env, "DELETE FROM pairing WHERE expires_at<=?", time),
    stmt(env, "DELETE FROM rates WHERE expires_at<=?", time),
  ]);
}
async function route(req, env) {
  const url = new URL(req.url),
    path = url.pathname,
    method = req.method;
  if (!path.startsWith("/api/"))
    return env.ASSETS
      ? env.ASSETS.fetch(req)
      : json({ error: "not_found" }, 404);
  let publicURL;
  try {
    publicURL = new URL(env.PUBLIC_ORIGIN);
  } catch {
    fail(503, "service_not_configured");
  }
  if (publicURL.origin !== env.PUBLIC_ORIGIN || !["http:", "https:"].includes(publicURL.protocol)) fail(503, "service_not_configured");
  if (url.origin !== publicURL.origin) fail(403, "host_rejected");
  if (!env.DB) fail(503, "service_not_configured");
  if (env.DEV_MODE === "true" && !dev(env))
    fail(503, "unsafe_dev_configuration");
  if (
    !dev(env) &&
    (env.PRODUCTION_ENABLED !== "true" ||
      publicURL.protocol !== "https:" ||
      !env.GITHUB_CLIENT_ID ||
      !env.GITHUB_CLIENT_SECRET)
  )
    fail(503, "production_not_enabled");
  if (method === "POST" && path === "/api/dev/login") {
    if (!dev(env) || !env.DEV_AUTH_KEY || env.DEV_AUTH_KEY.length < 32)
      fail(404, "not_found");
    origin(req, env);
    await rate(env, "dev-login", 10, 60);
    const b = await body(req);
    if (
      !exact(b, ["key", "identity"]) ||
      !["alice", "bob"].includes(b.identity) ||
      typeof b.key !== "string" ||
      (await hash(b.key)) !== (await hash(env.DEV_AUTH_KEY))
    )
      fail(401, "authentication_failed");
    const s = await newSession(
      env,
      "dev:" + b.identity,
      b.identity,
      cookie(req, sessionName(env)),
    );
    return json(
      {
        user: { id: "dev:" + b.identity, login: b.identity },
        csrf_token: s.csrf,
      },
      200,
      { "Set-Cookie": setCookie(env, sessionName(env), s.token, 3600) },
    );
  }
  if (method === "GET" && path === "/api/auth/github") {
    if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET)
      fail(503, "oauth_not_configured");
    await rate(
      env,
      "oauth-start:" + (req.headers.get("CF-Connecting-IP") || "local"),
      20,
      60,
    );
    await rate(env, "oauth-global", 100, 3600);
    const state = random(),
      verifier = random();
    await run(
      env,
      "INSERT INTO oauth_states(hash,verifier,expires_at) VALUES(?,?,?)",
      await hash(state),
      verifier,
      now() + 600,
    );
    const challenge = btoa(String.fromCharCode(...(await digest(verifier))))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    const target = new URL("https://github.com/login/oauth/authorize");
    for (const [k, v] of Object.entries({
      client_id: env.GITHUB_CLIENT_ID,
      redirect_uri: env.PUBLIC_ORIGIN + "/api/auth/github/callback",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    }))
      target.searchParams.set(k, v);
    return new Response(null, {
      status: 302,
      headers: {
        Location: target.href,
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "Set-Cookie": setCookie(env, oauthName(env), state, 600),
      },
    });
  }
  if (method === "GET" && path === "/api/auth/github/callback") {
    const state = url.searchParams.get("state"),
      code = url.searchParams.get("code");
    if (
      !state ||
      !code ||
      state !== cookie(req, oauthName(env)) ||
      code.length > 512
    )
      fail(400, "oauth_state_invalid");
    const record = await first(
      env,
      "DELETE FROM oauth_states WHERE hash=? AND expires_at>? RETURNING verifier",
      await hash(state),
      now(),
    );
    if (!record) fail(400, "oauth_state_invalid");
    const fetcher = env.OAUTH_FETCH || fetch;
    const response = await fetcher(
      "https://github.com/login/oauth/access_token",
      {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(10000),
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          code_verifier: record.verifier,
          redirect_uri: env.PUBLIC_ORIGIN + "/api/auth/github/callback",
        }),
      },
    );
    if (!response.ok) fail(502, "oauth_exchange_failed");
    const token = await response.json();
    if (
      typeof token.access_token !== "string" ||
      token.access_token.length > 4096
    )
      fail(502, "oauth_exchange_failed");
    const identity = await fetcher("https://api.github.com/user", {
      redirect: "error",
      signal: AbortSignal.timeout(10000),
      headers: {
        Authorization: "Bearer " + token.access_token,
        Accept: "application/vnd.github+json",
        "User-Agent": "Sentinel-AI",
      },
    });
    if (!identity.ok) fail(502, "oauth_identity_failed");
    const who = await identity.json();
    if (
      !Number.isSafeInteger(who.id) ||
      typeof who.login !== "string" ||
      !who.login.match(/^[\w-]{1,100}$/)
    )
      fail(502, "oauth_identity_failed");
    const s = await newSession(
      env,
      "github:" + who.id,
      who.login,
      cookie(req, sessionName(env)),
    );
    return new Response(null, {
      status: 302,
      headers: {
        Location: env.PUBLIC_ORIGIN + "/dashboard.html",
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "Set-Cookie": setCookie(env, sessionName(env), s.token, 3600),
      },
    });
  }
  if (method === "POST" && path === "/api/device/pair") {
    await rate(
      env,
      "pair:" + (req.headers.get("CF-Connecting-IP") || "local"),
      20,
      60,
    );
    const b = await body(req);
    if (
      !exact(b, ["pairing_code"]) ||
      typeof b.pairing_code !== "string" ||
      !/^[\w-]{43}$/.test(b.pairing_code)
    )
      fail(400, "invalid_pairing_code");
    await rate(env, "pair-global", 100, 3600);
    // Atomic consumption fails closed if the subsequent device insert fails.
    const p = await first(
      env,
      "DELETE FROM pairing WHERE hash=? AND expires_at>? RETURNING *",
      await hash(b.pairing_code),
      now(),
    );
    if (!p) fail(401, "invalid_pairing_code");
    const token = random(),
      id = crypto.randomUUID();
    const inserted = await first(
      env,
      "INSERT INTO devices(id,user_id,name,token_hash,created_at,expires_at) SELECT ?,?,?,?,?,? WHERE (SELECT count(*) FROM devices WHERE user_id=?)<100 RETURNING id",
      id,
      p.user_id,
      p.name,
      await hash(token),
      now(),
      now() + 30 * DAY,
      p.user_id,
    );
    if (!inserted) fail(429, "device_limit");
    return json({ device_id: id, device_token: token });
  }
  if (path.startsWith("/api/device/") || path === "/api/telemetry") {
    const d = await device(req, env);
    if (method === "POST" && path === "/api/device/revoke") {
      await run(env, "UPDATE devices SET revoked_at=? WHERE id=?", now(), d.id);
      return json({ revoked: true });
    }
    if (method === "POST" && path === "/api/device/rotate") {
      const token = random();
      const changed = await first(
        env,
        "UPDATE devices SET token_hash=?,expires_at=? WHERE id=? AND token_hash=? AND revoked_at IS NULL RETURNING id",
        await hash(token),
        now() + 30 * DAY,
        d.id,
        d.token_hash,
      );
      if (!changed) fail(401, "device_authentication_required");
      return json({ device_token: token });
    }
    if (method === "POST" && path === "/api/telemetry") {
      if (!d.sync_enabled) fail(403, "sync_disabled");
      const b = await body(req);
      if (
        !exact(b, ["events"]) ||
        !Array.isArray(b.events) ||
        b.events.length < 1 ||
        b.events.length > 25 ||
        !b.events.every(validateEvent)
      )
        fail(400, "invalid_telemetry");
      await rate(env, "ingest:" + d.id, 20, 60);
      await rate(env, "daily:" + d.user_id, 20, DAY);
      await rate(env, "global-ingest", 200, DAY);
      await env.DB.batch(
        b.events.map((e) =>
          stmt(
            env,
            "INSERT OR IGNORE INTO events(event_id,user_id,device_id,timestamp,operation,decision,executed,reason_code,received_at) SELECT ?,?,?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM devices d JOIN users u ON d.user_id=u.id WHERE d.id=? AND d.revoked_at IS NULL AND d.expires_at>? AND d.token_hash=? AND u.sync_enabled=1)",
            e.event_id,
            d.user_id,
            d.id,
            e.timestamp,
            e.operation,
            e.decision,
            Number(e.executed),
            e.reason_code,
            now(),
            d.id,
            now(),
            d.token_hash,
          ),
        ),
      );
      const active = await first(
        env,
        "SELECT d.id FROM devices d JOIN users u ON d.user_id=u.id WHERE d.id=? AND d.revoked_at IS NULL AND d.expires_at>? AND d.token_hash=? AND u.sync_enabled=1",
        d.id,
        now(),
        d.token_hash,
      );
      if (!active) fail(403, "sync_unavailable");
      await run(
        env,
        "UPDATE devices SET last_seen_at=? WHERE id=?",
        now(),
        d.id,
      );
      return json({ accepted: b.events.map((e) => e.event_id) });
    }
    fail(404, "not_found");
  }
  const u = await user(req, env, !["GET", "HEAD"].includes(method));
  await rate(env, "account-api:" + u.user_id, 120, 60);
  if (method === "GET" && path === "/api/session")
    return json({
      user: { id: u.user_id, login: u.login },
      csrf_token: u.csrf,
    });
  if (method === "POST" && path === "/api/logout") {
    await run(env, "DELETE FROM sessions WHERE hash=?", u.hash);
    return json({ logged_out: true }, 200, {
      "Set-Cookie": setCookie(env, sessionName(env), "", 0),
    });
  }
  if (path === "/api/settings") {
    if (method === "PATCH") {
      const b = await body(req);
      if (!exact(b, ["sync_enabled"]) || typeof b.sync_enabled !== "boolean")
        fail(400, "invalid_settings");
      await run(
        env,
        "UPDATE users SET sync_enabled=? WHERE id=?",
        Number(b.sync_enabled),
        u.user_id,
      );
    } else if (method !== "GET") fail(405, "method_not_allowed");
    const settings = await first(
      env,
      "SELECT sync_enabled FROM users WHERE id=?",
      u.user_id,
    );
    return json({ sync_enabled: !!settings.sync_enabled, retention_days: 30 });
  }
  if (method === "POST" && path === "/api/devices/pair") {
    await rate(env, "pair-create:" + u.user_id, 10, 3600);
    const b = await body(req);
    if (
      !exact(b, ["name"]) ||
      typeof b.name !== "string" ||
      !/^[a-zA-Z0-9 _.-]{1,50}$/.test(b.name)
    )
      fail(400, "invalid_device_name");
    const code = random(),
      expires = now() + 300;
    await run(
      env,
      "INSERT INTO pairing(hash,user_id,name,expires_at) VALUES(?,?,?,?)",
      await hash(code),
      u.user_id,
      b.name,
      expires,
    );
    return json({ pairing_code: code, expires_at: expires });
  }
  if (method === "GET" && path === "/api/devices") {
    const rows = await stmt(
      env,
      "SELECT id,name,created_at,expires_at,revoked_at,last_seen_at FROM devices WHERE user_id=? ORDER BY created_at DESC LIMIT 100",
      u.user_id,
    ).all();
    return json({ devices: rows.results });
  }
  if (method === "POST" && /^\/api\/devices\/[^/]+\/revoke$/.test(path)) {
    const row = await first(
      env,
      "UPDATE devices SET revoked_at=? WHERE id=? AND user_id=? RETURNING id",
      now(),
      path.split("/")[3],
      u.user_id,
    );
    if (!row) fail(404, "not_found");
    return json({ revoked: true });
  }
  if (method === "GET" && path === "/api/events") {
    const limit = Number(url.searchParams.get("limit") || 50),
      cursor = Number(
        url.searchParams.get("cursor") || Number.MAX_SAFE_INTEGER,
      ),
      decision = url.searchParams.get("decision");
    if (
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 100 ||
      !Number.isSafeInteger(cursor) ||
      cursor < 1 ||
      (decision && !DECISIONS.has(decision))
    )
      fail(400, "invalid_query");
    const rows = await stmt(
      env,
      "SELECT seq,event_id,device_id,timestamp,operation,decision,executed,reason_code FROM events WHERE user_id=? AND seq<? AND received_at>=?" +
        (decision ? " AND decision=?" : "") +
        " ORDER BY seq DESC LIMIT ?",
      u.user_id,
      cursor,
      now() - 30 * DAY,
      ...(decision ? [decision] : []),
      limit + 1,
    ).all();
    const more = rows.results.length > limit,
      events = rows.results.slice(0, limit);
    return json({
      events: events.map((e) => ({ ...e, executed: !!e.executed })),
      next_cursor: more ? String(events.at(-1).seq) : null,
    });
  }
  if (method === "GET" && path === "/api/summary") {
    const s = await first(
      env,
      "SELECT count(*) total,COALESCE(sum(decision='ALLOW'),0) allow,COALESCE(sum(decision='DENY'),0) deny,COALESCE(sum(decision='REQUIRE_APPROVAL'),0) require_approval,COALESCE(sum(executed),0) executed FROM events WHERE user_id=? AND received_at>=?",
      u.user_id,
      now() - 30 * DAY,
    );
    const d = await first(
      env,
      "SELECT count(*) n FROM devices WHERE user_id=? AND revoked_at IS NULL",
      u.user_id,
    );
    return json({ ...s, devices: d.n });
  }
  if (method === "DELETE" && path === "/api/events") {
    await run(env, "DELETE FROM events WHERE user_id=?", u.user_id);
    return json({ deleted: true });
  }
  if (method === "DELETE" && path === "/api/account") {
    if (u.authenticated_at < now() - 300)
      fail(401, "fresh_authentication_required");
    await run(env, "DELETE FROM users WHERE id=?", u.user_id);
    return json({ deleted: true }, 200, {
      "Set-Cookie": setCookie(env, sessionName(env), "", 0),
    });
  }
  fail(404, "not_found");
}
export default {
  async fetch(req, env) {
    try {
      return await route(req, env);
    } catch (e) {
      return json({ error: e.publicFailure ? e.code : "service_unavailable" }, e.publicFailure ? e.status : 503);
    }
  },
  async scheduled(_event, env) {
    await cleanup(env);
  },
};
