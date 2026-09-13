/**
 * LANE G RUNTIME LEAK PROBE
 *
 * Not a unit test. The three leaks this lane closes were found by starting the
 * server and reading what it printed, and `dist/` is gitignored while jest runs
 * against `src/`, so a green suite says nothing about the artifact that is
 * actually deployed. This drives the BUILT server over JSON-RPC on stdio,
 * captures stdout and stderr separately, and greps both for a canary planted in
 * the request.
 *
 * The canary is IMPORTED, never inlined: it lives in exactly one module
 * (src/tests/fixtures/canary.ts -> dist/tests/fixtures/canary.js) so that a
 * grep for the literal across the tree returns one hit.
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { CANARY } from '../dist/tests/fixtures/canary.js';

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = join(here, '..');

const CANARY_FAMILY = 'Cohen';
const CANARY_GIVEN = 'Tamar';

function send(child, msg) {
  child.stdin.write(JSON.stringify(msg) + '\n');
}

async function driveServer({ auditSink }) {
  const env = { ...process.env, ENABLE_AUDIT: 'true', PHI_MODE: 'safe' };
  if (auditSink) env.AUDIT_SINK = auditSink;
  else delete env.AUDIT_SINK;

  const child = spawn(process.execPath, [join(pkgRoot, 'dist', 'index.js')], {
    cwd: pkgRoot,
    env,
    stdio: ['pipe', 'pipe', 'pipe']
  });

  let out = '';
  let err = '';
  child.stdout.on('data', (d) => { out += d.toString(); });
  child.stderr.on('data', (d) => { err += d.toString(); });

  await new Promise((r) => setTimeout(r, 1200));

  send(child, {
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'lane-g-probe', version: '0' } }
  });
  await new Promise((r) => setTimeout(r, 600));
  send(child, { jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
  await new Promise((r) => setTimeout(r, 300));

  // PROBE 1 -- leak 1. A Patient search whose params carry the canary and two
  // name components, made to FAIL validation (count > 1000) so the
  // security.input_validation_failed record is emitted. This is the
  // unauthenticated path reachable through the real tool surface.
  send(child, {
    jsonrpc: '2.0', id: 2, method: 'tools/call',
    params: {
      name: 'fhir.search',
      arguments: {
        resourceType: 'Patient',
        params: { identifier: CANARY, given: CANARY_GIVEN, family: CANARY_FAMILY, birthdate: '1980-01-01' },
        count: 99999
      }
    }
  });
  await new Promise((r) => setTimeout(r, 1500));

  // PROBE 2 -- audit completeness. A Patient read with no authenticated user is
  // denied by the healthcare-compliance branch, which used to return with no
  // audit record at all. The id IS the canary.
  send(child, {
    jsonrpc: '2.0', id: 3, method: 'tools/call',
    params: { name: 'fhir.read', arguments: { resourceType: 'Patient', id: CANARY } }
  });
  await new Promise((r) => setTimeout(r, 2500));

  // PROBE 3 -- leak 3 / success path. A VALID Patient search with the canary as
  // a search parameter. fhir-tools logs `params: input.params` on the success
  // path, so the raw parameters reach the audit sink even when nothing is
  // rejected.
  send(child, {
    jsonrpc: '2.0', id: 4, method: 'tools/call',
    params: { name: 'fhir.search', arguments: { resourceType: 'Patient', params: { identifier: CANARY } } }
  });
  await new Promise((r) => setTimeout(r, 6000));

  child.stdin.end();
  child.kill();
  await new Promise((r) => setTimeout(r, 400));

  return { out, err };
}

function report(label, { out, err }) {
  const auditLines = (out + '\n' + err)
    .split('\n')
    .filter((l) => l.trim().startsWith('{') && /"operation"/.test(l));

  const findings = [];
  const scan = (name, text) => {
    if (text.includes(CANARY)) findings.push(`${name} CONTAINS CANARY`);
    if (text.includes(CANARY_FAMILY)) findings.push(`${name} CONTAINS FAMILY NAME`);
    if (text.includes(CANARY_GIVEN)) findings.push(`${name} CONTAINS GIVEN NAME`);
    if (/"resourceId"/.test(text)) findings.push(`${name} CONTAINS RAW "resourceId" KEY`);
    if (/"originalInput"/.test(text)) findings.push(`${name} CONTAINS originalInput`);
  };
  scan('stdout', out);
  scan('stderr', err);

  // Channel check: on a stdio MCP server, stdout is the JSON-RPC channel.
  const stdoutAuditLines = out.split('\n').filter((l) => l.trim().startsWith('{') && /"operation"/.test(l) && /"traceId"/.test(l));

  console.log('==== ' + label + ' ====');
  console.log('audit records seen: ' + auditLines.length);
  console.log('audit records ON STDOUT (protocol channel): ' + stdoutAuditLines.length);
  console.log('denial records: ' + auditLines.filter((l) => /accessDenied/.test(l)).length);
  console.log('input_validation_failed records: ' + auditLines.filter((l) => /input_validation_failed/.test(l)).length);
  console.log('resourceIdHash present: ' + auditLines.filter((l) => /resourceIdHash/.test(l)).length);
  console.log('FINDINGS: ' + (findings.length ? findings.join(' | ') : 'none'));
  console.log('--- audit records (verbatim) ---');
  auditLines.forEach((l) => console.log(l));
  console.log('');
  return { findings, auditLines, stdoutAuditLines };
}

const fixed = report('FIXED BUILD (default sink = stderr)', await driveServer({}));

console.log('CANARY_LENGTH_SANITY=' + CANARY.length);
process.exit(fixed.findings.length === 0 ? 0 : 2);