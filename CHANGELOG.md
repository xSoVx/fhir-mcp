# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — `integration/phase2`

PHI remediation lanes A–I, merged onto `integration/phase2` (35 commits ahead of `master`). No version number or release date is assigned: this branch is unreleased, and `packages/mcp-fhir-server/package.json` still reads `1.0.0` while the only tagged entry below is `0.1.0`. That discrepancy is pre-existing and is not resolved here.

### ⚠️ Breaking

- **Identity is now required to receive any IDENTIFIABLE or RESTRICTED resource body.** Without `MCP_SERVICE_PRINCIPAL_ID` configured, every such read is denied with `HEALTHCARE_COMPLIANCE_VIOLATION`. Before lane H the tool layer built its `SecurityContext` with no `userId`, so in practice every IDENTIFIABLE resource was suppressed *before* masking — the masking engine never ran in production. The new behaviour is fail-closed and deliberate, but it is a change from what the documentation described. See "Breaking change on this branch" in `README.md`.
- **Pseudonym tokens (`PT_…`) are per-process.** The masking session key is `crypto.randomBytes(32)` with no persistence, so the same patient yields a different token after a restart. Cross-session longitudinal linkage is impossible by design; any consumer caching tokens as stable keys will break silently.

### Added

- `src/security/identity.ts` — caller identity for the MCP tool surface (lane H): `ServicePrincipal`, a closed `SCOPE_GRANTS` table using SMART on FHIR scope spelling, strict parsing that fails at startup rather than downgrading, `StaticIdentityProvider` (stdio), `RequestScopedIdentityProvider` backed by `AsyncLocalStorage` (HTTP/SSE), and `ANONYMOUS_IDENTITY_PROVIDER` as the deny-by-default. Configuration cannot grant roles, `phiAccessLevel`, or emergency access.
- `MCP_SERVICE_PRINCIPAL_ID` and `MCP_SERVICE_PRINCIPAL_SCOPES` environment variables.
- `AUDIT_SINK=stdout` to restore audit records to stdout for deployments already scraping it.
- PHI canary harness, golden-file corpus replayed in CI, and `test-baseline.json` with `scripts/check-test-baseline.mjs` enforcing it in both directions — an unlisted failure is a regression, a listed test that passes must have its entry pruned.
- `scripts/run-jest.mjs`, a portable ESM-aware jest launcher that works on Windows without `cross-env`.
- Audit records for **denied** reads. Previously a denial produced no record at all: `fhir-tools` returned as soon as `allowed` was false and never reached `logFhirOperation`.
- `scripts/lane-g-authz-leak-probe.mjs`, `scripts/lane-g-runtime-leak-probe.mjs`, `scripts/lane-h-e2e.mjs`.

### Fixed

- **Jest could not run at all under ESM.** Repaired in lane A (`edbceca`), which is why no pre-lane-A pass rate exists.
- **Masking was unreachable in production** until identity was wired (lane H) — see Breaking above.
- **Three PHI log leaks** (lane G):
  - `originalInput` (a sanitized copy of the whole request) is no longer written to audit records.
  - The authorization catch block logs the error **class** only (`AuditLogger.errorClass`), never `error.message`. A forced throw during PHI authorization had produced `error: "boom for patient <name> MRN <id>"` in the audit stream.
  - Audit metadata now passes a recursive structural **allowlist** instead of a shallow keyword denylist. The denylist had written given names, family names and a nine-digit national ID into the log in clear text because `name`, `identifier` and `id` were not on it.
- `resourceId` in audit records replaced by `resourceIdHash`. **This hash is reversible — see Known issues.**
- `PhiGuard` construction now fails closed; an `AuditLogger` is required.
- `identifier` masking made unconditional and independent of the per-resource-type `switch`, rather than expressed once per type.
- `text.div` treated as untrusted HTML and dropped by default.
- `Attachment.data` stripped at ten known paths while `contentType`, `size`, `hash`, `title` and `creation` are retained, so the model is still told a document exists.
- `extension[]` and `modifierExtension[]` rebuilt from a whitelist — `url` retained, every `value[x]` dropped — including extensions on primitives via the `_field` sibling.
- `meta.source` removed; `meta.security[].display` and `meta.tag[].display` removed while `system`+`code` are retained deliberately, so downstream consumers are not told the resource is less sensitive than it is.
- `contained[]` and `Bundle.entry[].resource` recursed into and masked as resources in their own right.
- Person-valued `Reference` masking hoisted out of the per-type `switch`: `Condition.subject`, `Procedure.subject` and `MedicationRequest.subject` previously had no rule and emitted `Patient/<id>` raw.
- `resource.id` and `Reference.reference` tokenized uniformly across Condition, Observation, Encounter, MedicationRequest, Procedure and DiagnosticReport; the same patient yields the same token everywhere within a process (lane I).
- Masking invariant made structural: every unmasked-ALLOW path at IDENTIFIABLE and above is closed, so any `allowed: true` at that level carries a non-empty rule set (lane E).
- Pseudonym cache bounded and expiring.
- Masking-failure logging scrubbed; `suppressedCount` surfaced.

### Changed

- Audit records are emitted on **stderr** by default. stdout is the MCP protocol channel, so an audit trail written there lands wherever the client pipes the protocol rather than in a log the covered entity controls.

### Documentation

- `README.md` and `QA-REPORT.md` corrected. Withdrawn claims, each verified false against this branch: "19/19 tests passed (100% success rate)" (the suite could not run until lane A; the real figure is 250/258); "Phase 1 Security" and "QA" marked complete on the roadmap; SMART on FHIR / OAuth2 Authorization Code + PKCE / client credentials described as implemented (only two orphan type declarations exist); "ML-powered" PHI classification and anomaly detection (a static matrix plus regex field patterns); FHIR `AuditEvent` emission (none); tamper-proof and cryptographically validated audit logs (`console.error` output); `birthDate → "YYYY-**-**"` (removed outright); `identifier → "***"` (replaced with `PT_` tokens); bearer authentication required for all HTTP requests (only when `AUTH_TOKEN` is set — otherwise the bridge is open); and five documented environment variables read by nothing (`CORS_CREDENTIALS`, `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX_REQUESTS`, `FHIR_RATE_LIMIT_MAX`, `WRITE_RATE_LIMIT_MAX`).
- Documented the `dist/` build trap: `dist/` is gitignored but load-bearing for `main`, `bin`, `npm start`, `npm run start:http` and the Dockerfile, while jest runs against `src/`. A green suite does not mean the deployed path is fixed.
- Documented that `npm run start:http` uses POSIX `VAR=x` prefix syntax and therefore does not work in PowerShell. PowerShell equivalents added throughout.
- Documented the four known open security issues rather than omitting them.

### Known issues (open on this branch)

1. `AuditLogger.hashIdentifier` is unsalted, unkeyed `sha256` truncated to 16 hex (`audit-logger.ts:235-238`) and is therefore reversible for low-entropy identifier spaces; a live patient id was recovered from a log line. The repository's own `LEGACY_UNSALTED_SHA256` (`tests/fixtures/canary.ts:298-310`) defines the identical construction and calls it equivalent to publishing the ID.
2. Free text unmasked on Condition (`note[].text`, `code.text`), MedicationRequest (`note[]`, `dosageInstruction[].text`), Procedure (`note[]`, `report[].display`), CarePlan (`description`) and DiagnosticReport (`presentedForm[].title`, `.url`). Observation and Encounter are clean, so this is inconsistency between rule sets rather than uniform absence.
3. `resourceType` is echoed verbatim into audit logs on an unauthenticated, pre-validation denial path; allowlisted values are length-bounded but not character-filtered — a log-injection channel.
4. `phi-classifier.ts:109-110` sets `hasDirectIdentifiers` on `id` **or** `identifier`, making `PHILevel.MINIMAL` unreachable. Three tests are quarantined pending the design decision, not because they are unfixable.

Unverified: `DocumentReference` is `IDENTIFIABLE` in the PHI matrix and carries masking rules, but is absent from `InputValidator.isValidResourceType`'s allowlist, so it is unreachable through the tool surface. Nothing in the repository records whether that is intentional.

## [0.1.0] - 2025-01-12

### Added

- Initial release of FhirMCP server
- MCP server implementation with FHIR and terminology tools
- PHI Guard with configurable masking and redaction (`safe` and `trusted` modes)
- Audit logging with structured logs and trace IDs
- Support for HAPI FHIR and HL7 terminology services
- TypeScript implementation
- Token-efficient FHIR operations with field selection and pagination
- Documentation suite (QUICKSTART.md, PROMPTS.md, README.md)

### Tools Implemented

- `fhir.capabilities` — get FHIR server capability statement
- `fhir.search` — search FHIR resources with filtering and pagination
- `fhir.read` — read specific FHIR resources by ID
- `fhir.create` — create new FHIR resources (requires write permissions)
- `fhir.update` — update existing FHIR resources with optimistic concurrency
- `terminology.lookup` — look up code properties and display names
- `terminology.expand` — expand ValueSets to get contained codes
- `terminology.translate` — translate codes between coding systems

### Security Features

- PHI masking of sensitive fields
- Scope-based access control preparation
- Audit trail with PHI-safe logging
- Configurable field masking and removal

> **Retrospective note.** Several guarantees claimed for 0.1.0 did not hold. PHI masking did not run in production, because the tool layer supplied no caller identity and every IDENTIFIABLE resource was suppressed before the masking engine was reached. "PHI-safe logging" was a shallow keyword denylist that wrote names and national IDs to the audit log in clear text. There was no executing test suite behind the "comprehensive testing" claim. All three are addressed on `integration/phase2` above.

### Testing

- Basic functionality tests against public FHIR servers
- Build and type checking validation
- Server startup and MCP protocol verification
- Tested against HAPI FHIR v4.0.1 with 146 available resources

### Documentation

- README with setup and usage instructions
- Quick start guide
- Prompt library with LLM interaction patterns
- Security and configuration documentation
- MIT license
