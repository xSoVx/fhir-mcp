#!/usr/bin/env node
/**
 * Test-baseline gate.
 *
 * `npm test` cannot be used directly as a CI gate on this repo yet: repairing
 * the ESM setup (T0.1) revealed 8 pre-existing failures, so a raw `jest` exit
 * code is red on a clean checkout and therefore carries no information.
 *
 * This wrapper turns the suite into a real gate without suppressing anything.
 * It runs jest, then compares the actual failure set against
 * test-baseline.json and fails on any DIFFERENCE, in either direction:
 *
 *   new failure        -> a regression was introduced          -> exit 1
 *   listed test passes -> someone fixed it; prune the baseline -> exit 1
 *   zero tests ran     -> the harness broke again              -> exit 1
 *
 * The second rule is the important one. A quarantine list that only ever grows
 * is a blanket suppression; one that must shrink as fixes land keeps the
 * remediation lanes honest.
 *
 * Note on test.failing(): jest reports a test.failing() case that fails as
 * PASSED (the failure was expected) and one that passes as FAILED ("Failing
 * test passed unexpectedly"). The canary suite relies on that, and this gate
 * inherits it for free -- when a remediation lane fixes a leak, the canary
 * case starts passing, jest reports the test.failing() wrapper as failed, and
 * CI goes red until the lane flips it to a plain test(). That is the intended
 * "the canary stays green" contract.
 */
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { readFileSync, rmSync, existsSync, mkdtempSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, '..');
const baselinePath = join(packageRoot, 'test-baseline.json');

function fail(message) {
  console.error(`\n[test-baseline] FAIL: ${message}`);
  process.exit(1);
}

if (!existsSync(baselinePath)) {
  fail(`baseline manifest not found at ${baselinePath}`);
}

const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));
const expected = new Map(
  (baseline.knownFailures ?? []).map((entry) => [entry.fullName, entry])
);

const scratch = mkdtempSync(join(tmpdir(), 'fhir-mcp-test-gate-'));
const reportPath = join(scratch, 'jest-report.json');

let jestBin;
try {
  jestBin = require.resolve('jest/bin/jest');
} catch {
  fail('could not resolve the jest CLI -- run `npm ci` at the repo root first');
}

const run = spawnSync(
  process.execPath,
  [
    '--experimental-vm-modules',
    jestBin,
    '--json',
    `--outputFile=${reportPath}`,
    ...process.argv.slice(2)
  ],
  {
    cwd: packageRoot,
    stdio: 'inherit',
    env: {
      ...process.env,
      NODE_OPTIONS: [process.env.NODE_OPTIONS, '--experimental-vm-modules']
        .filter(Boolean)
        .join(' ')
    }
  }
);

if (run.error) {
  fail(`could not start jest: ${run.error.message}`);
}

if (!existsSync(reportPath)) {
  fail('jest produced no JSON report -- the runner itself is broken');
}

const report = JSON.parse(readFileSync(reportPath, 'utf8'));
rmSync(scratch, { recursive: true, force: true });

// --- Rule 3: the suite must actually execute something -----------------------
if (!report.numTotalTests || report.numTotalTests === 0) {
  fail(
    'ZERO tests executed. This is the exact failure mode T0.1 repaired -- the ' +
      'suite is not loading. Check for `Test suite failed to run` above.'
  );
}

const floor = baseline.expectedTotalTestsAtLeast ?? 0;
if (report.numTotalTests < floor) {
  fail(
    `only ${report.numTotalTests} tests executed, but the baseline records at ` +
      `least ${floor}. Tests have gone missing -- check testMatch and any ` +
      'suite that failed to load.'
  );
}

// --- Collect the actual outcome of every test --------------------------------
const actualFailures = new Set();
const actualNames = new Set();

for (const suite of report.testResults ?? []) {
  if (suite.testExecError) {
    fail(
      `suite failed to load: ${suite.name}\n  ${
        suite.testExecError.message ?? ''
      }`
    );
  }
  for (const assertion of suite.assertionResults ?? []) {
    actualNames.add(assertion.fullName);
    if (assertion.status === 'failed') {
      actualFailures.add(assertion.fullName);
    }
  }
}

// --- Rule 1: no unexpected failures ------------------------------------------
const unexpected = [...actualFailures].filter((name) => !expected.has(name));

// --- Rule 2: no stale baseline entries ---------------------------------------
const nowPassing = [...expected.keys()].filter(
  (name) => actualNames.has(name) && !actualFailures.has(name)
);
const vanished = [...expected.keys()].filter((name) => !actualNames.has(name));

let ok = true;

if (unexpected.length > 0) {
  ok = false;
  console.error('\n[test-baseline] NEW FAILURES (regressions):');
  for (const name of unexpected) console.error(`  - ${name}`);
  console.error(
    '\n  These are not in test-baseline.json. Either fix the regression, or -- ' +
      'if\n  the failure is genuinely pre-existing and out of scope -- add it to ' +
      'the\n  manifest with a reason and an owning lane.'
  );
}

if (nowPassing.length > 0) {
  ok = false;
  console.error('\n[test-baseline] FIXED, BUT STILL QUARANTINED:');
  for (const name of nowPassing) {
    console.error(`  - ${name}`);
    console.error(`      owner: ${expected.get(name).owner}`);
  }
  console.error(
    '\n  These now pass. Remove them from test-baseline.json in the same commit ' +
      'as\n  the fix, so the quarantine list shrinks instead of rotting into a ' +
      'blanket\n  suppression.'
  );
}

if (vanished.length > 0) {
  ok = false;
  console.error('\n[test-baseline] QUARANTINED TESTS NO LONGER EXIST:');
  for (const name of vanished) console.error(`  - ${name}`);
  console.error(
    '\n  A quarantined test was renamed or deleted. If that was deliberate, ' +
      'remove\n  the manifest entry. If not, a test has gone missing.'
  );
}

if (!ok) {
  process.exit(1);
}

console.log(
  `\n[test-baseline] OK -- ${report.numPassedTests}/${report.numTotalTests} ` +
    `passed, ${actualFailures.size} known failure(s), 0 regressions.`
);