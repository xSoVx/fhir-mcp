# FHIR-MCP Server — Test and QA Status

**Branch:** `integration/phase2` (lanes A–I merged)
**Method:** `npm run test:gate` in `packages/mcp-fhir-server`, which runs the jest suite and checks the result against `test-baseline.json`.

## Summary

| | |
|---|---|
| **Tests** | **250 passed, 8 failed, 258 total** |
| **Suites** | 12 passed, 2 failed, 14 total |
| **Regressions** | 0 |
| **Known failures** | 8, all enumerated with reasoning in `test-baseline.json` |
| **Assessment** | Not production ready. Four known open security issues, one a live PHI exposure. |

## Scope of this report

The figures above come from one `npm run test:gate` run on this branch. They supersede the "19/19 tests passed (100% success rate)" and "Test Coverage: 100%" figures that earlier revisions of this report carried; those are withdrawn, not superseded, because the jest suite could not execute at all under ESM until lane A repaired the runner (`edbceca`). The full record of what was withdrawn and why is in [CHANGELOG.md](../CHANGELOG.md).

One lesson from that episode is worth keeping in front of whoever reads this next. The earlier report's headline result was a CRITICAL bug "fixed" by changing `'birthDate'` to `'birthdate'` in an audit denylist. The denylist was the leak: it covered `token|authorization|password|secret|ssn|birthdate` and nothing else, so a live run against a real FHIR server wrote given names, family names and a nine-digit national ID into the audit log in clear text. Redacting `birthdate` correctly is precisely what made the control look like it was working. The denylist has since been replaced with a recursive structural allowlist. A control verified only against the cases it already knows about will pass every time.

## Known failures (8)

Full per-entry reasoning and ownership is in `packages/mcp-fhir-server/test-baseline.json`. Summary:

### Group 1 — the `PHILevel.MINIMAL` design question (3 tests)

| Test |
|---|
| `PHI Protection System › PHI Classification › should classify Organization resource as MINIMAL` |
| `PHI Protection System › PHI Authorization Engine › should allow masked access to minimal PHI resources` |
| `PHI Protection System › Integration Tests › should handle mixed resource bundles correctly` |

`phi-classifier.ts:109-110` sets `hasDirectIdentifiers` when a key is `identifier` **or** `id`; line 159 then upgrades `MINIMAL` → `IDENTIFIABLE`. The fixture Organization carries `id: 'org-123'`, so it classifies as `identifiable`, the unprivileged test user is denied, and the bundle returns 1 entry instead of 2. Tests two and three are strictly downstream of test one.

These are **quarantined pending an open design question, not left unfixed**: is a logical `id` on a non-Patient resource a direct identifier? Narrowing the rule reduces protection; keeping it makes `PHILevel.MINIMAL` unreachable dead code. No lane owned that decision and it was deliberately not taken during the merge. Lane C owned `phi-classifier.ts` and did not change the upgrade rule; lane E's authorization fix closed unmasked-ALLOW paths and this is a DENY, so neither flipped it.

### Group 2 — pre-existing, outside the PHI remediation plan (5 tests)

| Test | Note |
|---|---|
| `Security Integration Tests › Input Validation › should sanitize potentially harmful input` | Sanitized output still contains the rejected substring |
| `Security Integration Tests › Rate Limiting › should block excessive requests` | Rate-limiter behaviour disagreement |
| `Security Integration Tests › Rate Limiting › should detect suspicious rapid-fire requests` | Rate-limiter behaviour disagreement |
| `Security Integration Tests › Security Headers › should detect suspicious requests` | Security-headers behaviour disagreement |
| `Security Integration Tests › Security Middleware Integration › should enforce rate limits across middleware` | Downstream of the rate-limiter failures |

All five are unassigned and need their own triage. Two of them mean the rate limiter does not demonstrably block anything under test; the README's rate-limiting claims should be read with that in mind.

## The baseline gate

`scripts/check-test-baseline.mjs` enforces `test-baseline.json` in **both** directions:

- a test that fails and is not listed → CI fails (regression)
- a test that is listed and now passes → CI fails (prune the entry)

The second direction is what prevents the file from degrading into a blanket suppression. Remove an entry in the same commit as its fix.

## What is actually covered

14 jest suites, run against `src/` via ts-jest:

| Suite | Covers |
|---|---|
| `phi-canary.test.ts` | One planted canary value traced through every element a FHIR resource can hide an identifier in; asserts the leaky path ran before asserting the leak is closed |
| `phi-reidentification.test.ts` | Uniform `id` / `Reference.reference` tokenization across clinical types |
| `phi-fail-closed.test.ts` | Guard construction and denial paths |
| `phi-authz-invariant.test.ts` | Structural invariant: any `allowed: true` at IDENTIFIABLE+ carries a non-empty rule set |
| `phi-authz-canary.test.ts` | Role × mode × PHI-level sweep against the canary |
| `phi-masking-nested.test.ts` | `contained[]` and `Bundle.entry[].resource` recursion |
| `phi-masking-pseudonym.test.ts` | `PT_` token derivation and stability within a session |
| `phi-masking-cache.test.ts` | Bounded, expiring pseudonym cache |
| `phi-identifier-masking.test.ts` | Unconditional `identifier` masking |
| `phi-attachment-masking.test.ts` | `Attachment.data` removal, retained metadata |
| `phi-narrative-masking.test.ts` | `text.div` policy |
| `phi-protection.test.ts` | Classification and end-to-end integration |
| `golden-corpus.test.ts` | Replayed golden files |
| `security-integration.test.ts` | Validation, rate limiting, headers, middleware (5 of the 8 known failures live here) |

Plus standalone scripts outside jest: `scripts/lane-g-authz-leak-probe.mjs`, `scripts/lane-g-runtime-leak-probe.mjs`, `scripts/lane-h-e2e.mjs`, `test-basic-functionality.js`, `manual-qa-test.js`, `tests/e2e/test-fhir-mcp.js`.

## What is not covered

- **No coverage measurement is reported here.** `npm run test:coverage` exists; no threshold is enforced and no figure is claimed. The previous "100%" was unsubstantiated.
- **The suite does not test the deployed artifact.** Jest runs against `src/`; `package.json` `main`/`bin`, `npm start`, `npm run start:http` and the Dockerfile all consume `dist/`, which is gitignored. A green run says nothing about a stale `dist/`. Run `npm run build` before testing runtime behaviour.
- **No test covers the four open security issues below** — that is what makes them open.
- No penetration testing, dependency scanning or container scanning results are recorded on this branch.

## Open security issues

Carried here from `README.md` so this report cannot be read as a clean bill of health.

1. **`resourceIdHash` is reversible.** `AuditLogger.hashIdentifier` is unsalted, unkeyed `sha256` truncated to 16 hex (`audit-logger.ts:235-238`). A live patient id was recovered from a log line by direct comparison with `sha256(id)`. The repository's own canary module defines the identical construction as `LEGACY_UNSALTED_SHA256` and calls it "equivalent to publishing the ID" (`tests/fixtures/canary.ts:298-310`).
2. **Free text unmasked on Condition, MedicationRequest, Procedure, CarePlan, and partially DiagnosticReport.** Those types have no `case` arm in `getResourceSpecificMaskingRules()`. Observation and Encounter are clean — this is inconsistency between rule sets, not uniform absence.
3. **`resourceType` is echoed verbatim into audit logs** on an unauthenticated, pre-validation denial path (`fhir-tools.ts:335` → `security-middleware.ts:432,437`). Allowlisted values are length-bounded but not character-filtered: a log-injection channel.
4. **`PHILevel.MINIMAL` unreachable** — the open design question above.

## Assessment

**Not production ready.** The PHI remediation lanes closed a substantial set of real leaks and, importantly, built the harness (canary fixtures, golden corpus, enforced baseline) that makes the remaining ones visible. But masking was unreachable in production until lane H, three PHI log leaks were open until lane G, and issue 1 is a live exposure today.

Recommended before any deployment against real patient data:

1. Key the audit identifier hash (HMAC with a per-deployment secret), and delete the "not a reversible identifier" docstring.
2. Add `case` arms for Condition, MedicationRequest, Procedure and CarePlan, and extend DiagnosticReport to `presentedForm[].title` / `.url`.
3. Validate or hash `resourceType` before it reaches the audit writer.
4. Decide the `MINIMAL` question, then either fix the classifier or delete the level and update the three tests.
5. Triage the five pre-existing failures, starting with the two showing the rate limiter blocking nothing.
6. Add a `dist/`-freshness check to CI so a stale build cannot pass as a tested one.

---

*Status verified by running `npm run test:gate` on `integration/phase2`.*
