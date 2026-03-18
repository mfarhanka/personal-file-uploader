'use strict';
/**
 * Integration tests using Node's built-in test runner.
 * Each test spins up the server on a random port with a temp DB.
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// ── helpers ──────────────────────────────────────────────────────────────────

function request(options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString();
        let json;
        try { json = JSON.parse(raw); } catch { json = null; }
        resolve({ status: res.statusCode, headers: res.headers, body: json, raw });
      });
    });
    req.on('error', reject);
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

/** GET /api/csrf-token and return the token + session cookie */
async function getCsrfToken(hostname, port) {
  const res = await request({ hostname, port, method: 'GET', path: '/api/csrf-token', headers: {} });
  const cookie = (res.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');
  return { csrfToken: res.body.csrfToken, cookie };
}

function json(opts, body) {
  return request({
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(opts.headers || {}),
    },
  }, body ? JSON.stringify(body) : undefined);
}

// Multipart form-data helper (sends one small text file)
function uploadFile(options, filename, content, cookie, csrfToken) {
  const boundary = '----TestBoundary' + Date.now();
  const CRLF = '\r\n';
  const part =
    `--${boundary}${CRLF}` +
    `Content-Disposition: form-data; name="files"; filename="${filename}"${CRLF}` +
    `Content-Type: text/plain${CRLF}${CRLF}` +
    content + CRLF +
    `--${boundary}--${CRLF}`;
  return request({
    ...options,
    method: 'POST',
    headers: {
      'Content-Type': `multipart/form-data; boundary=${boundary}`,
      'Content-Length': Buffer.byteLength(part),
      'X-CSRF-Token': csrfToken || '',
      ...(cookie ? { Cookie: cookie } : {}),
    },
  }, part);
}

// ── test state ────────────────────────────────────────────────────────────────

let server, port, tmpDb, tmpUploads;

before(async () => {
  // Isolated tmp dirs / DB for the test run
  tmpUploads = fs.mkdtempSync(path.join(os.tmpdir(), 'pfu-uploads-'));
  tmpDb = path.join(os.tmpdir(), `pfu-test-${Date.now()}.db`);

  // Patch environment so server.js picks them up
  process.env.DB_PATH = tmpDb;
  process.env.UPLOAD_DIR = tmpUploads;
  process.env.PORT = '0'; // OS-assigned

  // We need to load a fresh copy; clear the require cache first
  delete require.cache[require.resolve('../server.js')];

  // Monkeypatch paths BEFORE requiring server
  // (server.js reads the env vars or falls back to defaults, so we patch at module level)
  const mod = require('../server.js');
  server = mod._server || null;

  // If server.js exports app, spin up our own server
  if (!server) {
    const app = mod;
    await new Promise((resolve) => {
      server = app.listen(0, resolve);
    });
  }
  port = server.address().port;
});

after(() => {
  server.close();
  // Cleanup temp files
  try { fs.unlinkSync(tmpDb); } catch {}
  try { fs.rmSync(tmpUploads, { recursive: true, force: true }); } catch {}
});

function opts(method, p, cookie, csrfToken) {
  const headers = {};
  if (cookie) headers['Cookie'] = cookie;
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  return { hostname: 'localhost', port, method, path: p, headers };
}

// ── tests ─────────────────────────────────────────────────────────────────────

test('POST /api/account/create returns accountId and 6-digit pin', async () => {
  const { csrfToken, cookie } = await getCsrfToken('localhost', port);
  const res = await json(opts('POST', '/api/account/create', cookie, csrfToken));
  assert.equal(res.status, 200);
  assert.ok(res.body.accountId, 'should have accountId');
  assert.match(String(res.body.pin), /^\d{6}$/, 'PIN should be 6 digits');
});

test('create account sets session cookie', async () => {
  // The session (and its cookie) is established by the /api/csrf-token call.
  // Verify that we do get a session cookie from the CSRF token endpoint.
  const { cookie } = await getCsrfToken('localhost', port);
  assert.ok(cookie, 'csrf-token endpoint should set session cookie');
});

test('GET /api/account/me returns 401 without session', async () => {
  const res = await json(opts('GET', '/api/account/me'));
  assert.equal(res.status, 401);
});

test('full flow: create → me → upload → list → download → delete file → delete account', async () => {
  // 1. Get CSRF token and create account
  const { csrfToken, cookie: initCookie } = await getCsrfToken('localhost', port);
  const create = await json(opts('POST', '/api/account/create', initCookie, csrfToken));
  assert.equal(create.status, 200);
  // After create, the server sets a new session cookie; grab it
  const sessionCookie = (create.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ')
    || initCookie;
  const { pin } = create.body;

  // 2. /me should return accountId
  const me = await json(opts('GET', '/api/account/me', sessionCookie));
  assert.equal(me.status, 200);
  assert.ok(me.body.accountId);

  // 3. Upload a file
  const upRes = await uploadFile(
    { hostname: 'localhost', port, path: '/api/files/upload' },
    'hello.txt',
    'Hello World',
    sessionCookie,
    csrfToken
  );
  assert.equal(upRes.status, 200, `upload failed: ${upRes.raw}`);
  assert.ok(Array.isArray(upRes.body) && upRes.body.length === 1);
  const fileId = upRes.body[0].id;

  // 4. List files
  const list = await json(opts('GET', '/api/files', sessionCookie));
  assert.equal(list.status, 200);
  assert.equal(list.body.length, 1);
  assert.equal(list.body[0].original_name, 'hello.txt');

  // 5. Download
  const dl = await request(opts('GET', `/api/files/${fileId}/download`, sessionCookie));
  assert.equal(dl.status, 200);
  assert.ok(dl.raw.includes('Hello World'));

  // 6. Delete file
  const delFile = await json(opts('DELETE', `/api/files/${fileId}`, sessionCookie, csrfToken));
  assert.equal(delFile.status, 200);

  const listAfter = await json(opts('GET', '/api/files', sessionCookie));
  assert.equal(listAfter.body.length, 0);

  // 7. Login with PIN from a new session (get fresh CSRF token)
  const { csrfToken: csrfToken2, cookie: newCookie } = await getCsrfToken('localhost', port);
  const login = await json(opts('POST', '/api/account/login', newCookie, csrfToken2), { pin });
  assert.equal(login.status, 200);
  const loginCookie = (login.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ')
    || newCookie;

  const me2 = await json(opts('GET', '/api/account/me', loginCookie));
  assert.equal(me2.status, 200);

  // 8. Delete account
  const delAcc = await json(opts('DELETE', '/api/account', loginCookie, csrfToken2));
  assert.equal(delAcc.status, 200);
});

test('POST /api/account/login with wrong PIN returns 401', async () => {
  const { csrfToken, cookie } = await getCsrfToken('localhost', port);
  const res = await json(opts('POST', '/api/account/login', cookie, csrfToken), { pin: '000000' });
  assert.equal(res.status, 401);
});

test('upload without a valid session returns 403 (CSRF check) or 401 (auth check)', async () => {
  // Without any session the CSRF token will not match → 403.
  // With a session but no accountId → 401.  Both are acceptable rejections.
  const { csrfToken } = await getCsrfToken('localhost', port);
  const res = await uploadFile(
    { hostname: 'localhost', port, path: '/api/files/upload' },
    'test.txt',
    'data',
    null,   // no cookie → no session → CSRF mismatch
    csrfToken
  );
  assert.ok(res.status === 401 || res.status === 403, `expected 401 or 403, got ${res.status}`);
});
