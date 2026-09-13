#!/usr/bin/env node
/**
 * Lane H end-to-end verification.
 *
 * Runs against the BUILT server (dist/), driven through the real MCP tool
 * surface over stdio and over the HTTP/SSE bridge. Unit tests exercise src/;
 * this exercises the artefact production actually loads.
 *
 * Usage: node scripts/lane-h-e2e.mjs
 */
import { spawn } from 'node:child_process';
import { createServer, request as httpRequest } from 'node:http';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.resolve(HERE, '..');
const DIST_INDEX = path.join(PKG, 'dist', 'index.js');
const DIST_HTTP = path.join(PKG, 'dist', 'http.js');
const HAPI = 'https://hapi.fhir.org/baseR4';

// The canary is imported, never inlined. Single source of truth.
const { CANARY, CANARY_FORMS, kitchenSinkPatient } =
  await import(pathToFileURL(path.join(PKG, 'dist', 'tests', 'fixtures', 'canary.js')).href);

const PRINCIPAL = {
  MCP_SERVICE_PRINCIPAL_ID: 'svc:lane-h-e2e',
  MCP_SERVICE_PRINCIPAL_SCOPES: 'patient/*.read'
};

let pass = 0;
let fail = 0;
const failures = [];

// Hermetic: child processes inherit this process's env, so any ambient
// identity configuration would silently invalidate the negative legs.
for (const v of ['MCP_SERVICE_PRINCIPAL_ID', 'MCP_SERVICE_PRINCIPAL_SCOPES', 'AUTH_TOKEN']) {
  delete process.env[v];
}

// Harness-only. Tearing down the SSE probe after a 401 makes the peer reset
// the socket, which Node surfaces as an uncaught ECONNRESET with no request
// context to attach a handler to. Nothing else is swallowed.
process.on('uncaughtException', (err) => {
  if (err && err.code === 'ECONNRESET') return;
  throw err;
});
function check(name, ok, detail = '') {
  if (ok) { pass++; console.log(`  PASS  ${name}`); }
  else { fail++; failures.push(name); console.log(`  FAIL  ${name}${detail ? ' :: ' + detail : ''}`); }
}
function section(title) { console.log(`\n=== ${title} ===`); }
/* ------------------------------------------------------------------ */
/* Minimal JSON-RPC-over-stdio MCP client                              */
/* ------------------------------------------------------------------ */
class StdioClient {
  constructor(scriptPath, env) {
    this.proc = spawn(process.execPath, [scriptPath], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe']
    });
    this.buf = '';
    this.pending = new Map();
    this.nextId = 1;
    this.stderr = '';
    this.exited = new Promise(resolve => this.proc.on('exit', code => resolve(code)));
    this.proc.stderr.on('data', d => { this.stderr += d.toString(); });
    this.proc.stdout.on('data', d => {
      this.buf += d.toString();
      let nl;
      while ((nl = this.buf.indexOf('\n')) >= 0) {
        const line = this.buf.slice(0, nl).trim();
        this.buf = this.buf.slice(nl + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { continue; }
        const res = this.pending.get(msg.id);
        if (res) { this.pending.delete(msg.id); res(msg); }
      }
    });
  }
  send(method, params) {
    const id = this.nextId++;
    const p = new Promise((resolve, reject) => {
      this.pending.set(id, resolve);
      setTimeout(() => { if (this.pending.delete(id)) reject(new Error(`timeout: ${method}`)); }, 60000);
    });
    this.proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    return p;
  }
  async initialize() {
    await this.send('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'lane-h-e2e', version: '1.0.0' }
    });
    this.proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  }
  callTool(name, args) { return this.send('tools/call', { name, arguments: args }); }
  close() { try { this.proc.kill(); } catch { /* already gone */ } }
}

function toolText(rpc) {
  if (rpc?.error) return { isError: true, text: JSON.stringify(rpc.error) };
  const r = rpc?.result;
  return { isError: !!r?.isError, text: r?.content?.[0]?.text ?? '' };
}

/* ------------------------------------------------------------------ */
/* A local FHIR server that serves a canary-laden Patient.             */
/* Lets us assert canary absence end-to-end WITHOUT writing to HAPI.   */
/* ------------------------------------------------------------------ */
function startCanaryFhirServer() {
  const patient = kitchenSinkPatient();
  return new Promise(resolve => {
    const srv = createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/fhir+json' });
      if (req.url.startsWith('/Patient/')) { res.end(JSON.stringify(patient)); return; }
      if (req.url.startsWith('/Patient')) {
        res.end(JSON.stringify({ resourceType: 'Bundle', type: 'searchset', total: 1, entry: [{ resource: patient }] }));
        return;
      }
      res.end(JSON.stringify({ resourceType: 'OperationOutcome' }));
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, base: `http://127.0.0.1:${srv.address().port}` }));
  });
}

/* ------------------------------------------------------------------ */
/* Pick a real HAPI Patient that carries maskable fields.              */
/* ------------------------------------------------------------------ */
async function pickHapiPatient() {
  const preferred = '137955398';
  try {
    const r = await fetch(`${HAPI}/Patient/${preferred}`);
    if (r.ok) { const p = await r.json(); if (p.identifier?.length) return p; }
  } catch { /* fall through to discovery */ }
  const s = await fetch(`${HAPI}/Patient?_count=20&identifier:missing=false&name:missing=false`);
  const b = await s.json();
  for (const e of b.entry ?? []) {
    if (e.resource?.identifier?.length && e.resource?.name?.length) return e.resource;
  }
  throw new Error('no suitable HAPI Patient found');
}
/* ------------------------------------------------------------------ */
/* Raw SSE + POST client for the HTTP bridge.                          */
/* ------------------------------------------------------------------ */
function httpBridgeCall(port, token, toolName, toolArgs) {
  return new Promise((resolve, reject) => {
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    let sessionPath = null;
    let sseBuf = '';
    let settled = false;
    const done = (fn, v) => { if (!settled) { settled = true; try { sse.destroy(); } catch { /* noop */ } fn(v); } };

    const sse = httpRequest({ host: '127.0.0.1', port, path: '/sse', method: 'GET', headers }, res => {
      res.on('error', () => { /* ECONNRESET after we destroy the probe */ });
      if (res.statusCode !== 200) { done(resolve, { httpStatus: res.statusCode }); return; }
      res.setEncoding('utf8');
      res.on('data', chunk => {
        sseBuf += chunk;
        const events = sseBuf.split('\n\n');
        sseBuf = events.pop();
        for (const ev of events) {
          const dataLine = ev.split('\n').find(l => l.startsWith('data:'));
          if (!dataLine) continue;
          const data = dataLine.slice(5).trim();
          if (ev.includes('event: endpoint')) {
            sessionPath = data;
            post(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'e2e', version: '1' } });
            continue;
          }
          let msg; try { msg = JSON.parse(data); } catch { continue; }
          if (msg.id === 1) {
            postNotify();
            post(2, 'tools/call', { name: toolName, arguments: toolArgs });
          } else if (msg.id === 2) {
            done(resolve, { httpStatus: 200, rpc: msg });
          }
        }
      });
    });
    sse.on('error', e => { if (!settled) done(reject, e); });
    sse.on('socket', s => s.on('error', () => { /* post-destroy reset */ }));
    sse.end();

    function writeBody(body) {
      const req = httpRequest({
        host: '127.0.0.1', port, path: sessionPath, method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
      }, r => r.resume());
      req.on('error', () => { /* surfaced via timeout */ });
      req.end(body);
    }
    const post = (id, method, params) => writeBody(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
    const postNotify = () => writeBody(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }));

    setTimeout(() => done(reject, new Error('http bridge timeout')), 60000);
  });
}

function startHttpServer(env) {
  const port = 18000 + Math.floor(Math.random() * 1000);
  const proc = spawn(process.execPath, [DIST_HTTP], {
    env: { ...process.env, MCP_TRANSPORT: 'http', PORT: String(port), ...env },
    stdio: ['ignore', 'ignore', 'pipe']
  });
  let err = '';
  proc.stderr.on('data', d => { err += d.toString(); });
  return new Promise(resolve => {
    const t = setInterval(() => {
      if (err.includes('HTTP server started')) { clearInterval(t); resolve({ proc, port, stderr: () => err }); }
    }, 150);
    setTimeout(() => { clearInterval(t); resolve({ proc, port, stderr: () => err }); }, 15000);
  });
}
/* ================================================================== */
/*                                MAIN                                */
/* ================================================================== */
const hapiPatient = await pickHapiPatient();
console.log(`HAPI Patient under test: ${hapiPatient.id} ` +
  `(identifiers=${hapiPatient.identifier?.length ?? 0}, name=${!!hapiPatient.name}, ` +
  `birthDate=${!!hapiPatient.birthDate}, telecom=${!!hapiPatient.telecom}, ` +
  `address=${!!hapiPatient.address}, text=${!!hapiPatient.text})`);

// ENABLE_AUDIT stays ON. SecurityMiddleware.performComplianceChecks() blocks
// every PHI-bearing resource when audit logging is disabled (lane B's
// requirement), so turning it off here would mask the thing under test.
const baseEnv = { FHIR_BASE_URL: HAPI, PHI_MODE: 'safe' };

/* --- L1: regression baseline. No principal => denied, as before. --- */
section('L1  stdio, NO principal configured (pre-existing behaviour must be unchanged)');
{
  const c = new StdioClient(DIST_INDEX, baseEnv);
  await c.initialize();
  const r = toolText(await c.callTool('fhir.read', { resourceType: 'Patient', id: hapiPatient.id }));
  check('Patient read is DENIED without an identity', r.isError && /denied/i.test(r.text), r.text.slice(0, 160));
  check('denial names the missing authenticated user',
    /PHI access requires authenticated user|HEALTHCARE_COMPLIANCE_VIOLATION/.test(r.text), r.text.slice(0, 160));
  c.close();
}

/* --- L2: the deliverable. Masked Patient body through fhir.read. --- */
section('L2  stdio, principal configured -> fhir.read returns a MASKED body (real HAPI)');
{
  const c = new StdioClient(DIST_INDEX, { ...baseEnv, ...PRINCIPAL });
  await c.initialize();
  const r = toolText(await c.callTool('fhir.read', { resourceType: 'Patient', id: hapiPatient.id }));
  check('fhir.read is NOT an error (authorized === true)', !r.isError, r.text.slice(0, 200));
  let body = null;
  try { body = JSON.parse(r.text).resource; } catch { /* leave null */ }
  check('a resource body came back', !!body && body.resourceType === 'Patient');
  if (body) {
    const raw = hapiPatient;
    const rawIds = (raw.identifier ?? []).map(i => i.value).filter(Boolean);
    const masked = JSON.stringify(body);
    check('masking RAN: no raw identifier value survives',
      rawIds.length > 0 && rawIds.every(v => !masked.includes(v)),
      `rawIds=${JSON.stringify(rawIds)}`);
    // The engine pseudonymises the whole `identifier` element rather than
    // rewriting each .value, so the masked shape is a PT_* token, not an array.
    check('identifier element still present but pseudonymised (not merely deleted)',
      body.identifier !== undefined && JSON.stringify(body.identifier) !== JSON.stringify(raw.identifier),
      JSON.stringify(body.identifier)?.slice(0, 200));
    if (raw.name?.[0]?.family) check('raw family name is gone', !masked.includes(raw.name[0].family));
    if (raw.birthDate) check('birthDate removed', body.birthDate === undefined);
    if (raw.telecom) check('telecom removed', body.telecom === undefined);
    if (raw.address) check('address removed', body.address === undefined);
    if (raw.text) check('narrative removed', body.text === undefined);
    check('resource still structurally useful (resourceType + id survive)',
      body.resourceType === 'Patient' && body.id !== undefined);
    console.log('        masked body: ' + masked.slice(0, 300));
  }
  c.close();
}

/* --- L3: canary absence end-to-end, no writes to HAPI. ------------- */
section('L3  stdio, principal, canary-laden upstream -> canary absent from fhir.read output');
{
  const { srv, base } = await startCanaryFhirServer();
  const c = new StdioClient(DIST_INDEX, { ...baseEnv, FHIR_BASE_URL: base, ...PRINCIPAL });
  await c.initialize();
  const r = toolText(await c.callTool('fhir.read', { resourceType: 'Patient', id: 'canary-patient' }));
  check('canary Patient read is authorized', !r.isError, r.text.slice(0, 200));
  check('control: the UPSTREAM payload really did contain the canary',
    JSON.stringify(kitchenSinkPatient()).includes(CANARY));
  // KNOWN, TRACKED EXCEPTION: `Reference.reference` strings such as
  // `Patient/<id>` are not rewritten. That is the repo's own deferred item -
  // phi-canary.test.ts marks it `test.failing` under "surface:
  // Reference.reference [owner: T4.x]" (finding 9 / Phase 4, bidirectional
  // pseudonymization). It is asserted here NARROWLY: the canary may survive in
  // `link` and nowhere else. If the leak ever widens, this fails.
  //
  // Worth stating plainly: before this lane, that gap was unreachable because
  // no resource body was ever returned. It is now live.
  let body = null;
  try { body = JSON.parse(r.text).resource; } catch { /* leave null */ }
  const withoutKnownGap = body ? JSON.stringify({ ...body, link: undefined }) : r.text;
  for (const form of CANARY_FORMS) {
    check(`canary absent from tool output outside the known Reference gap (${form.label})`,
      !withoutKnownGap.includes(form.value),
      withoutKnownGap.slice(0, 200));
  }
  check('the only surviving canary occurrence is Patient.link[].other.reference',
    JSON.stringify(body?.link ?? null).includes(CANARY) &&
    (r.text.split(CANARY).length - 1) === (JSON.stringify(body?.link ?? null).split(CANARY).length - 1),
    `total=${r.text.split(CANARY).length - 1}`);
  check('structured identifier, narrative, contained, extension and meta are all clean',
    body !== null && !JSON.stringify({
      identifier: body.identifier, text: body.text, contained: body.contained,
      extension: body.extension, meta: body.meta, name: body.name
    }).includes(CANARY));
  c.close();
  srv.close();
}

/* --- L4: search through the tool surface. -------------------------- */
section('L4  stdio, principal -> fhir.search returns masked entries (real HAPI)');
{
  const c = new StdioClient(DIST_INDEX, { ...baseEnv, ...PRINCIPAL });
  await c.initialize();
  const r = toolText(await c.callTool('fhir.search', { resourceType: 'Patient', count: 3 }));
  check('fhir.search is NOT an error', !r.isError, r.text.slice(0, 200));
  let res = null; try { res = JSON.parse(r.text); } catch { /* leave null */ }
  check('search returned entries (previously always 0)', (res?.returned ?? 0) > 0,
    `returned=${res?.returned} suppressed=${res?.suppressedCount}`);
  check('nothing was suppressed', (res?.suppressedCount ?? -1) === 0, `suppressed=${res?.suppressedCount}`);
  // `name` is replaced wholesale with the '***' token, so a masked entry has a
  // string there (or nothing), never the original HumanName array.
  check('entry names are masked (replaced with the *** token, not a HumanName array)',
    (res?.entries ?? []).every(e => e.resource?.name === undefined || typeof e.resource.name === 'string'),
    JSON.stringify(res?.entries?.[0]?.resource?.name));
  check('entry bodies carry no birthDate / telecom / address',
    (res?.entries ?? []).every(e => e.resource?.birthDate === undefined &&
      e.resource?.telecom === undefined && e.resource?.address === undefined));
  c.close();
}

/* --- L5: scopes are granular. RESTRICTED still denied. ------------- */
section('L5  stdio, principal with only patient/*.read -> RESTRICTED tier still DENIED');
{
  const c = new StdioClient(DIST_INDEX, { ...baseEnv, ...PRINCIPAL });
  await c.initialize();
  const r = toolText(await c.callTool('fhir.search', { resourceType: 'Coverage', count: 2 }));
  let res = null; try { res = JSON.parse(r.text); } catch { /* leave null */ }
  check('Coverage (RESTRICTED) not returned without x-restricted/*.read',
    r.isError || (res?.returned ?? 0) === 0,
    `returned=${res?.returned} suppressed=${res?.suppressedCount}`);
  c.close();
}
/* --- L6: misconfiguration is a startup error, not a weaker mode. --- */
section('L6  stdio, malformed identity config -> server refuses to start');
for (const [label, env] of [
  ['unrecognised scope', { ...baseEnv, MCP_SERVICE_PRINCIPAL_ID: 'svc:x', MCP_SERVICE_PRINCIPAL_SCOPES: 'patient/*.rad' }],
  ['id declared with no scopes', { ...baseEnv, MCP_SERVICE_PRINCIPAL_ID: 'svc:x', MCP_SERVICE_PRINCIPAL_SCOPES: '' }],
  ['malformed principal id', { ...baseEnv, MCP_SERVICE_PRINCIPAL_ID: 'svc x; DROP', MCP_SERVICE_PRINCIPAL_SCOPES: 'patient/*.read' }]
]) {
  const c = new StdioClient(DIST_INDEX, env);
  const code = await Promise.race([c.exited, new Promise(r => setTimeout(() => r('still-running'), 8000))]);
  check(`startup fails on ${label}`, code !== 'still-running' && code !== 0, `exit=${code}`);
  check(`startup error is explanatory (${label})`, /identity:/.test(c.stderr),
    c.stderr.split('\n').find(l => l.includes('identity:'))?.slice(0, 140) ?? c.stderr.slice(0, 140));
  c.close();
}

/* --- L7/L8: the HTTP bridge. Identity requires PROOF, not config. -- */
section('L7  http bridge, AUTH_TOKEN set + correct bearer -> masked body');
{
  const s = await startHttpServer({ ...baseEnv, ...PRINCIPAL, AUTH_TOKEN: 'lane-h-secret-token' });
  const noAuth = await httpBridgeCall(s.port, null, 'fhir.read', { resourceType: 'Patient', id: hapiPatient.id });
  check('unauthenticated request rejected at the transport (401)', noAuth.httpStatus === 401, `status=${noAuth.httpStatus}`);
  const ok = await httpBridgeCall(s.port, 'lane-h-secret-token', 'fhir.read', { resourceType: 'Patient', id: hapiPatient.id });
  const t = toolText(ok.rpc);
  check('verified bearer -> fhir.read authorized', ok.httpStatus === 200 && !t.isError, t.text.slice(0, 200));
  let body = null; try { body = JSON.parse(t.text).resource; } catch { /* leave null */ }
  check('verified bearer -> masked resource body returned', !!body && body.resourceType === 'Patient');
  if (body && hapiPatient.identifier?.length) {
    check('http bridge output is masked too',
      hapiPatient.identifier.map(i => i.value).filter(Boolean).every(v => !JSON.stringify(body).includes(v)));
  }
  s.proc.kill();
}

section('L8  http bridge, principal configured but AUTH_TOKEN unset -> identity NOT bound');
{
  const s = await startHttpServer({ ...baseEnv, ...PRINCIPAL });
  const r = await httpBridgeCall(s.port, null, 'fhir.read', { resourceType: 'Patient', id: hapiPatient.id });
  const t = toolText(r.rpc);
  check('open bridge still reaches the tool layer (unchanged)', r.httpStatus === 200, `status=${r.httpStatus}`);
  check('but PHI is DENIED: a configured principal alone grants nothing',
    t.isError && /denied/i.test(t.text), t.text.slice(0, 200));
  check('startup warned that the principal can never bind', /AUTH_TOKEN is not/.test(s.stderr()));
  s.proc.kill();
}

/* --- L9: DocumentReference allowlist inconsistency (lane G file). -- */
section('L9  DocumentReference: IDENTIFIABLE in the PHI matrix, absent from the validator allowlist');
{
  const c = new StdioClient(DIST_INDEX, { ...baseEnv, ...PRINCIPAL });
  await c.initialize();
  const r = toolText(await c.callTool('fhir.read', { resourceType: 'DocumentReference', id: '1' }));
  check('DocumentReference unreachable regardless of identity (input validation)',
    r.isError && /INPUT_VALIDATION_FAILED|Invalid or missing resourceType|Invalid resourceType|denied/i.test(r.text),
    r.text.slice(0, 200));
  console.log('        response: ' + r.text.slice(0, 200));
  c.close();
}

console.log('\n================ RESULT ================');
console.log(`PASS ${pass}   FAIL ${fail}`);
if (fail) console.log(`failing: ${failures.join(' | ')}`);
process.exit(fail ? 1 : 0);