/**
 * LANE G AUTHZ LEAK PROBE (parent)
 *
 * Spawns the child against dist/, captures stdout and stderr separately, and
 * greps both for the imported canary. Covers the two leaks the JSON-RPC probe
 * cannot reach from outside: the phi-authorization-engine catch block (leak 2)
 * and the raw resourceId nested inside metadata on the authorized path (leak 3).
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { CANARY } from '../dist/tests/fixtures/canary.js';

const here = dirname(fileURLToPath(import.meta.url));
const CANARY_FAMILY = 'Cohen';

const child = spawn(process.execPath, [join(here, 'lane-g-authz-probe-child.mjs')], {
  cwd: join(here, '..'),
  stdio: ['ignore', 'pipe', 'pipe']
});

let out = '';
let err = '';
child.stdout.on('data', (d) => { out += d.toString(); });
child.stderr.on('data', (d) => { err += d.toString(); });
await new Promise((resolve) => child.on('close', resolve));

const all = out + '\n' + err;
const auditLines = all.split('\n').filter((l) => l.trim().startsWith('{') && /"operation"/.test(l));
const stdoutAudit = out.split('\n').filter((l) => l.trim().startsWith('{') && /"traceId"/.test(l));

const findings = [];
if (all.includes(CANARY)) findings.push('CANARY PRESENT');
if (all.includes(CANARY_FAMILY)) findings.push('FAMILY NAME PRESENT');
if (all.includes('boom for patient')) findings.push('ERROR MESSAGE PRESENT');
if (/"resourceId"/.test(all)) findings.push('RAW "resourceId" KEY PRESENT');

console.log('==== AUTHZ PROBE (dist) ====');
console.log('audit records: ' + auditLines.length);
console.log('audit records ON STDOUT (protocol channel): ' + stdoutAudit.length);
console.log('records with resourceIdHash: ' + auditLines.filter((l) => /resourceIdHash/.test(l)).length);
console.log('FINDINGS: ' + (findings.length ? findings.join(' | ') : 'none'));
console.log('--- audit records (verbatim) ---');
auditLines.forEach((l) => console.log(l));
process.exit(findings.length === 0 ? 0 : 2);