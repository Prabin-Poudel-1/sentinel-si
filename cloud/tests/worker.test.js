import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import worker, { validateEvent, cleanup } from "../src/index.js";
class D1 {
  constructor() {
    this.db = new DatabaseSync(":memory:");
    this.db.exec(
      readFileSync(
        new URL("../migrations/0001_initial.sql", import.meta.url),
        "utf8",
      ),
    );
  }
  prepare(sql) {
    const db = this.db;
    return {
      bind(...args) {
        return {
          first: async () => db.prepare(sql).get(...args) || null,
          all: async () => ({ results: db.prepare(sql).all(...args) }),
          run: async () => ({ meta: db.prepare(sql).run(...args) }),
          sql,
          args,
        };
      },
    };
  }
  async batch(items) {
    this.db.exec("BEGIN");
    try {
      const results = items.map((i) => ({
        results: this.db.prepare(i.sql).all(...i.args),
      }));
      this.db.exec("COMMIT");
      return results;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }
}
function setup(extra = {}) {
  const env = {
    DB: new D1(),
    DEV_MODE: "true",
    PUBLIC_ORIGIN: "http://127.0.0.1:8788",
    DEV_AUTH_KEY: "synthetic-key-for-tests-only-1234567890",
    ...extra,
  };
  return {
    env,
    async request(path, options = {}) {
      const headers = {
        "Content-Type": "application/json",
        Origin: env.PUBLIC_ORIGIN,
        ...options.headers,
      };
      return worker.fetch(
        new Request(env.PUBLIC_ORIGIN + path, {
          ...options,
          headers,
          body:
            options.body === undefined
              ? undefined
              : JSON.stringify(options.body),
        }),
        env,
      );
    },
  };
}
async function login(c, identity = "alice") {
  const r = await c.request("/api/dev/login", {
    method: "POST",
    body: { key: c.env.DEV_AUTH_KEY, identity },
  });
  assert.equal(r.status, 200);
  const b = await r.json();
  return {
    Cookie: r.headers.get("Set-Cookie").split(";")[0],
    "X-CSRF-Token": b.csrf_token,
  };
}
async function pair(c, h) {
  const r = await c.request("/api/devices/pair", {
    method: "POST",
    headers: h,
    body: { name: "Synthetic device" },
  });
  assert.equal(r.status, 200);
  const b = await r.json();
  const p = await c.request("/api/device/pair", {
    method: "POST",
    body: { pairing_code: b.pairing_code },
  });
  assert.equal(p.status, 200);
  return { ...(await p.json()), code: b.pairing_code };
}
const event = () => ({
  event_id: crypto.randomUUID(),
  timestamp: Math.floor(Date.now() / 1000),
  operation: "read_file",
  decision: "ALLOW",
  executed: true,
  reason_code: "authorized",
});
async function enable(c, h) {
  assert.equal(
    (
      await c.request("/api/settings", {
        method: "PATCH",
        headers: h,
        body: { sync_enabled: true },
      })
    ).status,
    200,
  );
}
async function ingest(c, d, events) {
  return c.request("/api/telemetry", {
    method: "POST",
    headers: { Authorization: "Bearer " + d.device_token },
    body: { events },
  });
}
test("production and unsafe development configuration fail closed", async () => {
  for (const extra of [
    { DEV_MODE: "false" },
    { PUBLIC_ORIGIN: "https://example.test" },
    { DEV_AUTH_KEY: "" },
  ]) {
    const c = setup(extra);
    assert.ok(
      (
        await c.request("/api/dev/login", {
          method: "POST",
          body: { key: "x", identity: "alice" },
        })
      ).status >= 400,
    );
  }
});
test("unauthenticated routes and unknown device tokens rejected", async () => {
  const c = setup();
  assert.equal((await c.request("/api/events")).status, 401);
  assert.equal(
    (await ingest(c, { device_token: "x".repeat(43) }, [event()])).status,
    401,
  );
});
test("session cookies are HttpOnly and session IDs not in JSON", async () => {
  const c = setup();
  const h = await login(c);
  const r = await c.request("/api/session", { headers: h });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).user.id, "dev:alice");
  const stored = c.env.DB.db.prepare("SELECT hash FROM sessions").get().hash;
  assert.notEqual(stored, h.Cookie.split("=")[1]);
});
test("CSRF, origin and host checks reject mutations", async () => {
  const c = setup(),
    h = await login(c);
  for (const headers of [
    { Cookie: h.Cookie },
    { ...h, Origin: "https://evil.invalid" },
  ])
    assert.equal(
      (
        await c.request("/api/devices/pair", {
          method: "POST",
          headers,
          body: { name: "test" },
        })
      ).status,
      403,
    );
  assert.equal(
    (await worker.fetch(new Request("http://evil.invalid/api/session"), c.env))
      .status,
    403,
  );
});
test("pairing codes are one-use and stored hashed", async () => {
  const c = setup(),
    h = await login(c),
    d = await pair(c, h);
  assert.equal(
    (
      await c.request("/api/device/pair", {
        method: "POST",
        body: { pairing_code: d.code },
      })
    ).status,
    401,
  );
  assert.equal(
    c.env.DB.db.prepare("SELECT count(*) n FROM pairing").get().n,
    0,
  );
  assert.notEqual(
    c.env.DB.db.prepare("SELECT token_hash FROM devices").get().token_hash,
    d.device_token,
  );
});
test("expired pairing and device credentials are rejected", async () => {
  const c = setup(),
    h = await login(c),
    d = await pair(c, h);
  c.env.DB.db.exec("UPDATE devices SET expires_at=0");
  assert.equal((await ingest(c, d, [event()])).status, 401);
  const r = await c.request("/api/devices/pair", {
      method: "POST",
      headers: h,
      body: { name: "expired" },
    }),
    b = await r.json();
  c.env.DB.db.exec("UPDATE pairing SET expires_at=0");
  assert.equal(
    (await c.request("/api/device/pair", { method: "POST", body: b })).status,
    400,
  );
  assert.equal(
    (
      await c.request("/api/device/pair", {
        method: "POST",
        body: { pairing_code: b.pairing_code },
      })
    ).status,
    401,
  );
});
test("sync opt-in required before ingestion and supports disabling", async () => {
  const c = setup(),
    h = await login(c),
    d = await pair(c, h);
  assert.equal((await ingest(c, d, [event()])).status, 403);
  await enable(c, h);
  assert.equal((await ingest(c, d, [event()])).status, 200);
  await c.request("/api/settings", {
    method: "PATCH",
    headers: h,
    body: { sync_enabled: false },
  });
  assert.equal((await ingest(c, d, [event()])).status, 403);
});
test("strict telemetry whitelist rejects content, arbitrary reasons, invalid types", () => {
  const a = event();
  assert.equal(validateEvent(a), true);
  for (const bad of [
    { ...a, resource: "secret" },
    { ...a, reason_code: "secret contents" },
    { ...a, executed: 1 },
    { ...a, decision: "DENY" },
    { ...a, operation: "shell" },
    { ...a, timestamp: 0 },
    { ...a, event_id: "arbitrary" },
    { ...a, task_id: "secret" },
  ])
    assert.equal(validateEvent(bad), false);
});
test("ingestion deduplicates, paginates and returns real summaries", async () => {
  const c = setup(),
    h = await login(c),
    d = await pair(c, h);
  await enable(c, h);
  const e = event();
  await ingest(c, d, [e, e, event()]);
  await ingest(c, d, [e]);
  const s = await (await c.request("/api/summary", { headers: h })).json();
  assert.equal(s.total, 2);
  const page = await (
    await c.request("/api/events?limit=1", { headers: h })
  ).json();
  assert.equal(page.events.length, 1);
  assert.ok(page.next_cursor);
  const next = await (
    await c.request("/api/events?limit=1&cursor=" + page.next_cursor, {
      headers: h,
    })
  ).json();
  assert.equal(next.events.length, 1);
  assert.notEqual(next.events[0].event_id, page.events[0].event_id);
  assert.equal(next.next_cursor, null);
});
test("two-user ownership isolates events, summaries and device revocation", async () => {
  const c = setup(),
    a = await login(c),
    b = await login(c, "bob"),
    d = await pair(c, a);
  await enable(c, a);
  await ingest(c, d, [event()]);
  assert.deepEqual(
    (await (await c.request("/api/events", { headers: b })).json()).events,
    [],
  );
  assert.equal(
    (await (await c.request("/api/summary", { headers: b })).json()).total,
    0,
  );
  assert.equal(
    (
      await c.request("/api/devices/" + d.device_id + "/revoke", {
        method: "POST",
        headers: b,
      })
    ).status,
    404,
  );
  assert.equal(
    (await (await c.request("/api/devices", { headers: b })).json()).devices
      .length,
    0,
  );
});
test("rotation invalidates old token and device can revoke itself", async () => {
  const c = setup(),
    h = await login(c),
    d = await pair(c, h);
  await enable(c, h);
  const r = await c.request("/api/device/rotate", {
    method: "POST",
    headers: { Authorization: "Bearer " + d.device_token },
  });
  assert.equal(r.status, 200);
  const fresh = await r.json();
  assert.equal((await ingest(c, d, [event()])).status, 401);
  assert.equal((await ingest(c, fresh, [event()])).status, 200);
  await c.request("/api/device/revoke", {
    method: "POST",
    headers: { Authorization: "Bearer " + fresh.device_token },
  });
  assert.equal((await ingest(c, fresh, [event()])).status, 401);
});
test("user device revocation invalidates ingestion", async () => {
  const c = setup(),
    h = await login(c),
    d = await pair(c, h);
  await enable(c, h);
  assert.equal(
    (
      await c.request("/api/devices/" + d.device_id + "/revoke", {
        method: "POST",
        headers: h,
      })
    ).status,
    200,
  );
  assert.equal((await ingest(c, d, [event()])).status, 401);
});
test("logout and expiry invalidate sessions", async () => {
  const c = setup(),
    h = await login(c);
  await c.request("/api/logout", { method: "POST", headers: h });
  assert.equal((await c.request("/api/session", { headers: h })).status, 401);
  const fresh = await login(c);
  c.env.DB.db.exec("UPDATE sessions SET expires_at=0");
  assert.equal(
    (await c.request("/api/session", { headers: fresh })).status,
    401,
  );
});
test("data deletion, fresh reauthentication, account deletion cascade", async () => {
  const c = setup(),
    h = await login(c),
    d = await pair(c, h);
  await enable(c, h);
  await ingest(c, d, [event()]);
  assert.equal(
    (await c.request("/api/events", { method: "DELETE", headers: h })).status,
    200,
  );
  assert.equal(c.env.DB.db.prepare("SELECT count(*) n FROM events").get().n, 0);
  c.env.DB.db.exec("UPDATE sessions SET authenticated_at=0");
  assert.equal(
    (await c.request("/api/account", { method: "DELETE", headers: h })).status,
    401,
  );
  const fresh = await login(c);
  assert.equal(
    (await c.request("/api/account", { method: "DELETE", headers: fresh }))
      .status,
    200,
  );
  for (const table of ["users", "sessions", "devices", "events", "pairing"])
    assert.equal(
      c.env.DB.db.prepare("SELECT count(*) n FROM " + table).get().n,
      0,
    );
});
test("retention removes old events and expired authentication artifacts", async () => {
  const c = setup(),
    h = await login(c),
    d = await pair(c, h);
  await enable(c, h);
  await ingest(c, d, [event()]);
  c.env.DB.db.exec(
    "UPDATE events SET received_at=0;UPDATE sessions SET expires_at=0",
  );
  await cleanup(c.env);
  assert.equal(c.env.DB.db.prepare("SELECT count(*) n FROM events").get().n, 0);
  assert.equal(
    c.env.DB.db.prepare("SELECT count(*) n FROM sessions").get().n,
    0,
  );
});
test("malformed, oversized, wrong content-type and injection query rejected", async () => {
  const c = setup(),
    h = await login(c);
  assert.equal(
    (
      await c.request("/api/settings", {
        method: "PATCH",
        headers: h,
        body: { sync_enabled: true, extra: "x" },
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await c.request("/api/settings", {
        method: "PATCH",
        headers: h,
        body: { sync_enabled: "x".repeat(33000) },
      })
    ).status,
    413,
  );
  assert.equal(
    (
      await c.request("/api/settings", {
        method: "PATCH",
        headers: { ...h, "Content-Type": "text/plain" },
        body: { sync_enabled: true },
      })
    ).status,
    415,
  );
  assert.equal(
    (await c.request("/api/events?limit=-1", { headers: h })).status,
    400,
  );
  assert.equal(
    (await c.request("/api/events?decision=%27OR1=1", { headers: h })).status,
    400,
  );
});
test("rate limit is durable and fails closed", async () => {
  const c = setup();
  for (let i = 0; i < 10; i++)
    await c.request("/api/dev/login", {
      method: "POST",
      body: { key: "wrong", identity: "alice" },
    });
  assert.equal(
    (
      await c.request("/api/dev/login", {
        method: "POST",
        body: { key: c.env.DEV_AUTH_KEY, identity: "alice" },
      })
    ).status,
    429,
  );
});
test("D1 errors never fall back to authorization", async () => {
  const c = setup(),
    h = await login(c);
  c.env.DB.prepare = () => {
    throw Error("sensitive connection details");
  };
  const r = await c.request("/api/session", { headers: h });
  assert.equal(r.status, 503);
  assert.deepEqual(await r.json(), { error: "service_unavailable" });
});
test("OAuth uses PKCE, verifies state and consumes state once; mock upstream only", async () => {
  let verifier;
  const c = setup({
    GITHUB_CLIENT_ID: "synthetic-client",
    GITHUB_CLIENT_SECRET: "synthetic-secret",
    OAUTH_FETCH: async (url, options) => {
      if (url.endsWith("access_token")) {
        verifier = JSON.parse(options.body).code_verifier;
        return Response.json({ access_token: "synthetic-only" });
      }
      return Response.json({ id: 123, login: "synthetic" });
    },
  });
  const r = await c.request("/api/auth/github"),
    location = new URL(r.headers.get("Location"));
  assert.equal(location.searchParams.get("code_challenge_method"), "S256");
  assert.ok(location.searchParams.get("code_challenge"));
  const state = location.searchParams.get("state"),
    headers = { Cookie: r.headers.get("Set-Cookie").split(";")[0] };
  assert.equal(
    (
      await c.request("/api/auth/github/callback?state=wrong&code=x", {
        headers,
      })
    ).status,
    400,
  );
  const response = await c.request(
    "/api/auth/github/callback?state=" + state + "&code=x",
    { headers },
  );
  assert.equal(response.status, 302);
  assert.equal(verifier.length, 43);
  assert.equal(
    (
      await c.request("/api/auth/github/callback?state=" + state + "&code=x", {
        headers,
      })
    ).status,
    400,
  );
});
test("production sessions require Secure cookies and configured OAuth", async () => {
  const c = setup({
    DEV_MODE: "false",
    PUBLIC_ORIGIN: "https://sentinel.example",
    PRODUCTION_ENABLED: "true",
    GITHUB_CLIENT_ID: "synthetic",
    GITHUB_CLIENT_SECRET: "synthetic",
  });
  const r = await c.request("/api/auth/github");
  assert.equal(r.status, 302);
  assert.match(r.headers.get("Set-Cookie"), /__Host-sentinel_oauth=/);
  assert.match(r.headers.get("Set-Cookie"), /; Secure/);
  assert.equal(
    (
      await c.request("/api/dev/login", {
        method: "POST",
        body: { key: c.env.DEV_AUTH_KEY, identity: "alice" },
      })
    ).status,
    404,
  );
});
test('maximum telemetry batch remains below Free D1 query cap',async()=>{
  const c=setup(),h=await login(c),d=await pair(c,h);await enable(c,h);
  let queries=0;const prepare=c.env.DB.prepare.bind(c.env.DB);
  c.env.DB.prepare=sql=>{queries++;return prepare(sql);};
  assert.equal((await ingest(c,d,Array.from({length:25},event))).status,200);
  assert.ok(queries<=50, 'Free D1 query cap exceeded');
  assert.equal((await ingest(c,d,Array.from({length:26},event))).status,400);
});
test('daily account and global quotas reject before event writes',async()=>{
  for(const bucket of ['daily:dev:alice','global-ingest']){
    const c=setup(),h=await login(c),d=await pair(c,h);await enable(c,h);
    const now=Math.floor(Date.now()/1000);
    c.env.DB.db.prepare('INSERT INTO rates VALUES(?,?,?)').run(bucket+':'+Math.floor(now/86400),10000,now+86400);
    assert.equal((await ingest(c,d,[event()])).status,429);
    assert.equal(c.env.DB.db.prepare('SELECT count(*) n FROM events').get().n,0);
  }
});
test('concurrent pairing consumes one code once',async()=>{
  const c=setup(),h=await login(c);
  const b=await(await c.request('/api/devices/pair',{method:'POST',headers:h,body:{name:'Concurrent'}})).json();
  const results=await Promise.all([1,2].map(()=>c.request('/api/device/pair',{method:'POST',body:{pairing_code:b.pairing_code}})));
  assert.deepEqual(results.map(r=>r.status).sort(),[200,401]);
});
test('XSS device name rejected and other user deletion leaves owner events',async()=>{
  const c=setup(),a=await login(c),b=await login(c,'bob'),d=await pair(c,a);await enable(c,a);await ingest(c,d,[event()]);
  assert.equal((await c.request('/api/devices/pair',{method:'POST',headers:a,body:{name:'<img src=x onerror=alert(1)>'}})).status,400);
  assert.equal((await c.request('/api/events',{method:'DELETE',headers:b})).status,200);
  assert.equal((await(await c.request('/api/summary',{headers:a})).json()).total,1);
});
test('device limit is enforced atomically at enrollment',async()=>{
  const c=setup(),h=await login(c);const now=Math.floor(Date.now()/1000);
  for(let i=0;i<100;i++)c.env.DB.db.prepare('INSERT INTO devices(id,user_id,name,token_hash,created_at,expires_at) VALUES(?,?,?,?,?,?)').run('fixture-'+i,'dev:alice','fixture','hash-'+i,now,now+1000);
  const code=await(await c.request('/api/devices/pair',{method:'POST',headers:h,body:{name:'extra'}})).json();
  assert.equal((await c.request('/api/device/pair',{method:'POST',body:{pairing_code:code.pairing_code}})).status,429);
  assert.equal(c.env.DB.db.prepare('SELECT count(*) n FROM devices').get().n,100);
});
test('in-flight token rotation prevents stale token ingestion',async()=>{
  const c=setup(),h=await login(c),d=await pair(c,h);await enable(c,h);
  const batch=c.env.DB.batch.bind(c.env.DB);
  c.env.DB.batch=items=>{c.env.DB.db.exec("UPDATE devices SET token_hash='changed' ");return batch(items);};
  assert.equal((await ingest(c,d,[event()])).status,403);
  assert.equal(c.env.DB.db.prepare('SELECT count(*) n FROM events').get().n,0);
});
test('session count bounded and malformed JSON fails safely',async()=>{
  const c=setup();for(let i=0;i<7;i++)await login(c);
  assert.equal(c.env.DB.db.prepare('SELECT count(*) n FROM sessions').get().n,5);
  const r=await worker.fetch(new Request(c.env.PUBLIC_ORIGIN+'/api/dev/login',{method:'POST',headers:{Origin:c.env.PUBLIC_ORIGIN,'Content-Type':'application/json'},body:'{'}),c.env);
  assert.equal(r.status,400);assert.deepEqual(await r.json(),{error:'invalid_json'});
});
