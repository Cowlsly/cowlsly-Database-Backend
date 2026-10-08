// Regression tests for the Worker's Hono routing, middleware and security-sensitive responses.
// Runs on Node (node --test) against in-memory fakes of the D1 (`DB`) and KV (`KV`) bindings.
// No network, no Cloudflare account, no deployment.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import bcrypt from 'bcryptjs';

import app from '../src/index.js';

class FakeKV {
  constructor() {
    this.store = new Map();
    this.puts = [];
  }
  async get(key) {
    return this.store.has(key) ? this.store.get(key) : null;
  }
  async put(key, value, options) {
    this.store.set(key, value);
    this.puts.push({ key, value, options });
  }
  async delete(key) {
    this.store.delete(key);
  }
}

// `respond(sql, args, method)` decides what each prepared statement returns.
class FakeD1 {
  constructor(respond = () => null) {
    this.respond = respond;
    this.queries = [];
  }
  prepare(sql) {
    const db = this;
    const stmt = {
      sql,
      args: [],
      bind(...args) {
        stmt.args = args;
        return stmt;
      },
      async first() {
        db.queries.push({ sql, args: stmt.args, method: 'first' });
        return db.respond(sql, stmt.args, 'first') ?? null;
      },
      async all() {
        db.queries.push({ sql, args: stmt.args, method: 'all' });
        return db.respond(sql, stmt.args, 'all') ?? { results: [] };
      },
      async run() {
        db.queries.push({ sql, args: stmt.args, method: 'run' });
        return db.respond(sql, stmt.args, 'run') ?? { success: true };
      },
    };
    return stmt;
  }
}

function makeEnv(respond) {
  return { DB: new FakeD1(respond), KV: new FakeKV() };
}

async function signFor(env) {
  const res = await app.request('/get-sign', {}, env);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.success, true);
  return body.sign;
}

function post(path, sign, body) {
  const url = sign ? `${path}?sign=${encodeURIComponent(sign)}` : path;
  return [url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }];
}

test('/get-sign issues a sign stored in KV with a 48h TTL', async () => {
  const env = makeEnv();
  const sign = await signFor(env);
  assert.match(sign, /^[0-9a-f-]{36}$/);
  assert.equal(await env.KV.get(sign), 'valid');
  assert.equal(env.KV.puts[0].options.expirationTtl, 172800);
});

test('sign middleware refuses missing and unknown signs before any database access', async () => {
  const env = makeEnv();
  for (const url of ['/getTeam', '/getTeam?sign=not-a-real-sign']) {
    const res = await app.request(...post(url, null, { teamNum: 1 }), env);
    assert.equal(res.status, 403, url);
    assert.deepEqual(await res.json(), { success: false, error: 'Invalid sign' });
  }
  assert.equal(env.DB.queries.length, 0);
});

test('a valid sign reaches the route and parameters are bound, not interpolated', async () => {
  const env = makeEnv((sql) => (sql.includes('FROM Teams') ? { Number: 5940, Name: 'Team' } : null));
  const sign = await signFor(env);
  const res = await app.request(...post('/getTeam', sign, { teamNum: 5940 }), env);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { success: true, team: { Number: 5940, Name: 'Team' }, unNamed: false });
  assert.deepEqual(env.DB.queries[0].args, [5940]);
  assert.ok(!env.DB.queries[0].sql.includes('5940'));
});

test('unknown routes with a valid sign return 404', async () => {
  const env = makeEnv();
  const sign = await signFor(env);
  const res = await app.request(`/no-such-route?sign=${sign}`, {}, env);
  assert.equal(res.status, 404);
});

test('CORS: responses carry the CORS header and preflight succeeds without a sign', async () => {
  const env = makeEnv();
  const res = await app.request('/get-sign', { headers: { Origin: 'https://example.org' } }, env);
  assert.equal(res.headers.get('access-control-allow-origin'), '*');
  const pre = await app.request(
    '/getTeam',
    {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://example.org',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type',
      },
    },
    env,
  );
  assert.equal(pre.status, 204);
  assert.match(pre.headers.get('access-control-allow-methods') || '', /POST/);
});

// These two routes are registered in src/index.js; clients call them at "/<name>".
for (const [path, body, respond] of [
  [
    '/getAllMembersOfTeamThatAreScoutersAndCaptains',
    { teamCode: 1 },
    () => ({ results: [{ Name: 'A', Email: 'a@example.org', Role: 'Scouter' }] }),
  ],
  ['/updateMemberTimeTable', { Time: '10:00', Date: '2026-10-08', Team: 1, member: 'A' }, () => ({ success: true })],
]) {
  test(`route ${path} is reachable with a valid sign`, async () => {
    const env = makeEnv(respond);
    const sign = await signFor(env);
    const res = await app.request(...post(path, sign, body), env);
    assert.equal(res.status, 200, `${path} returned ${res.status}`);
    assert.equal((await res.json()).success, true);
  });
}

test('/getUser never returns the stored password hash (wrong password or success)', async () => {
  const hash = await bcrypt.hash('correct horse', 4);
  const row = { Email: 'a@example.org', Name: 'A', 'Team Code': 1, Password: hash, Role: 'Scouter', 'Time Table': null };
  const env = makeEnv((sql) => (sql.includes('FROM Users') ? row : null));
  const sign = await signFor(env);

  const bad = await app.request(...post('/getUser', sign, { email: row.Email, Password: 'wrong' }), env);
  assert.equal(bad.status, 401);
  const badText = await bad.text();
  assert.ok(!badText.includes(hash), 'wrong-password response leaks the bcrypt hash');
  assert.ok(!badText.includes('$2'), 'wrong-password response contains a bcrypt-looking string');

  const ok = await app.request(...post('/getUser', sign, { email: row.Email, Password: 'correct horse' }), env);
  assert.equal(ok.status, 200);
  const okText = await ok.text();
  assert.ok(!okText.includes(hash), 'login response leaks the bcrypt hash');
  const data = JSON.parse(okText).data;
  assert.equal(data.Email, row.Email);
  assert.equal(data.Role, 'Scouter');
  assert.ok(!('Password' in data), 'login response includes a Password field');
});

test('/addUser stores a bcrypt hash, never the plaintext password', async () => {
  const env = makeEnv((sql) => (sql.includes('FROM Teams') ? { 'Team Code': 1 } : null));
  const sign = await signFor(env);
  const res = await app.request(
    ...post('/addUser', sign, { email: 'b@example.org', name: 'B', teamCode: 1, Password: 'plain-secret', Role: 'Scouter' }),
    env,
  );
  // The handler issues a PUT route; POST must not reach it.
  assert.equal(res.status, 404);
  const put = await app.request(
    `/addUser?sign=${sign}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'b@example.org', name: 'B', teamCode: 1, Password: 'plain-secret', Role: 'Scouter' }),
    },
    env,
  );
  assert.equal(put.status, 200);
  const insert = env.DB.queries.find((q) => q.sql.startsWith('INSERT INTO Users'));
  assert.ok(insert);
  assert.ok(!insert.args.includes('plain-secret'));
  assert.ok(await bcrypt.compare('plain-secret', insert.args[3]));
});

test('/addReport builds SQL only from the fixed DataSet column names', async () => {
  const env = makeEnv(() => null);
  const sign = await signFor(env);
  const body = {
    TeamNumber: 42,
    One: ['text', 'fast'],
    Two: ['number', 3],
    'Three"; DROP TABLE Users; --': ['text', 'x'],
    Eleven: ['text', 'ignored'],
    FinalNotes: 'ok',
  };
  const res = await app.request(...post('/addReport', sign, body), env);
  assert.equal(res.status, 200);
  for (const q of env.DB.queries) {
    assert.ok(!/DROP|--|Eleven/.test(q.sql), `unexpected SQL: ${q.sql}`);
    const cols = q.sql.match(/DataSet[A-Za-z]+/g) || [];
    for (const col of cols) assert.match(col, /^DataSet(One|Two|Three|Four|Five|Six|Seven|Eight|Nine|Ten)$/);
  }
  const insert = env.DB.queries.find((q) => q.sql.startsWith('INSERT INTO "UnNamed"'));
  assert.deepEqual(insert.args.slice(0, 3), [42, 'fast', 3]);
});
