# FHIR-MCP - FHIR Model Context Protocol Server

[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

FHIR-MCP is an open-source MCP (Model Context Protocol) server that lets LLMs interact with FHIR servers and HL7 terminology services behind a PHI de-identification layer. It provides FHIR read/search/create/update, terminology operations, PHI classification and masking, and audit logging.

> **Status: pre-production.** This branch carries nine lanes of PHI remediation (A-I) plus fixes for four issues found by a live audit against a real FHIR server. Several of those leaks were open in every release before this branch. Three of the four audit findings are fixed; one remains an open design question - see [Security issues found by the live audit](#security-issues-found-by-the-live-audit). Read that section before deploying against real patient data.

## Features

- **PHI protection**: rule-driven classification and masking, pseudonym tokens, fail-closed authorization
- **FHIR operations**: read, search, create, update
- **HL7 terminology**: ValueSet expansion, CodeSystem lookup, concept translation
- **Audit logging**: structured JSON records with trace IDs, emitted on stderr by default
- **Security hardening**: OWASP security headers, multi-tier rate limiting, Joi input validation
- **Token efficient**: field selection (`elements`), pagination
- **Interoperable**: works with HAPI FHIR, Firely and other R4/R4B servers
- **HTTP bridge**: REST API example with Docker packaging
- **Modern architecture**: ES modules, TypeScript

## Breaking change on this branch: identity is required for PHI

Before lane H, the tool layer built its `SecurityContext` without a `userId`. The measured effect against a live FHIR server was that **every IDENTIFIABLE resource was suppressed before masking**, so the masking engine never ran in production at all.

Lane H added `src/security/identity.ts` and wired a caller identity through. The consequence you will hit immediately:

**Without a configured principal, every read of an IDENTIFIABLE or RESTRICTED resource is denied with `HEALTHCARE_COMPLIANCE_VIOLATION` and returns no resource body.**

This is deliberate and it is fail-closed: `performComplianceChecks` (`src/security/security-middleware.ts`) blocks the request when `context.userId` is absent at those PHI levels. An unconfigured deployment behaves exactly as the old one did — denied — rather than quietly returning unmasked data.

To get resource bodies back, configure a service principal:

```bash
# PowerShell
$env:MCP_SERVICE_PRINCIPAL_ID = "svc-analytics"
$env:MCP_SERVICE_PRINCIPAL_SCOPES = "system/*.read"

# bash
export MCP_SERVICE_PRINCIPAL_ID="svc-analytics"
export MCP_SERVICE_PRINCIPAL_SCOPES="system/*.read"
```

See [Authentication & authorization](#authentication--authorization) for the full scope table and the transport-specific rules.

## Quick Start

1. **Install dependencies** (from the repository root — this is an npm workspace):

   ```bash
   npm install
   ```

2. **Build.** `dist/` is gitignored but load-bearing at runtime — see [The build trap](#the-build-trap). This step is not optional.

   ```bash
   npm run build
   ```

3. **Configure.**

   ```bash
   # bash
   export FHIR_BASE_URL="https://hapi.fhir.org/baseR4"
   export TERMINOLOGY_BASE_URL="https://tx.fhir.org/r4"
   export PHI_MODE="safe"
   export MCP_SERVICE_PRINCIPAL_ID="svc-analytics"
   export MCP_SERVICE_PRINCIPAL_SCOPES="system/*.read"
   ```

   ```powershell
   # PowerShell
   $env:FHIR_BASE_URL = "https://hapi.fhir.org/baseR4"
   $env:TERMINOLOGY_BASE_URL = "https://tx.fhir.org/r4"
   $env:PHI_MODE = "safe"
   $env:MCP_SERVICE_PRINCIPAL_ID = "svc-analytics"
   $env:MCP_SERVICE_PRINCIPAL_SCOPES = "system/*.read"
   ```

4. **Start the server:**

   ```bash
   cd packages/mcp-fhir-server
   npm start
   ```

5. **Smoke test:**

   ```bash
   node test-basic-functionality.js
   ```

## The build trap

`dist/` is in `.gitignore` (line 8), and it is what actually runs:

| Consumer | Path |
|---|---|
| `packages/mcp-fhir-server/package.json` `main` | `dist/index.js` |
| `packages/mcp-fhir-server/package.json` `bin.fhir-mcp` | `dist/index.js` |
| `npm start` | `node dist/index.js` |
| `npm run start:http` | `node dist/http.js` |
| `Dockerfile` runtime stage | copies `packages/*/dist` from the builder |
| MCP client config (below) | `.../dist/index.js` |

Jest, meanwhile, runs against `src/` via ts-jest. **A green test suite therefore says nothing about the deployed path.** `npm run build` is mandatory before deploying, before testing runtime behaviour, and after every pull that touches `src/`. A stale `dist/` will happily serve the pre-remediation masking code while the tests pass.

## Windows note: `npm run start:http` is broken on PowerShell

`packages/mcp-fhir-server/package.json` defines:

```
"start:http": "MCP_TRANSPORT=http PORT=8080 node dist/http.js"
```

That `VAR=value command` prefix is POSIX-shell syntax. On PowerShell it fails — PowerShell parses `MCP_TRANSPORT=http` as a command name. Every `VAR=... npm ...` line in this repository's docs has the same problem on Windows. Until the script is made portable (as `scripts/run-jest.mjs` already was for the test runner), use:

```powershell
$env:MCP_TRANSPORT = "http"
$env:PORT = "8080"
node dist/http.js
```

or `cmd /c "set MCP_TRANSPORT=http && set PORT=8080 && node dist/http.js"`.

## Available Tools

### FHIR Operations

- `fhir.capabilities` — get server capability statement
- `fhir.search` — search resources with filtering and pagination
- `fhir.read` — read a resource by ID
- `fhir.create` — create a resource
- `fhir.update` — update a resource

### Terminology Services

- `terminology.lookup` — look up code properties and display names
- `terminology.expand` — expand ValueSets
- `terminology.translate` — translate codes between systems

## Project Structure

```
packages/
├── mcp-fhir-server/         # Main MCP server
│   ├── src/
│   │   ├── providers/       # FHIR and terminology HTTP clients
│   │   ├── security/        # identity, PHI classifier/masking/authz, audit, validation
│   │   ├── tools/           # MCP tool handlers and schemas
│   │   ├── types/           # PHI matrix, masking rules, config types
│   │   └── tests/           # jest suites + canary fixtures (run against src/)
│   ├── scripts/             # portable jest launcher, baseline gate, e2e probes
│   └── dist/                # Compiled JS — gitignored, required at runtime
├── examples/
│   ├── http-bridge/         # HTTP REST API bridge for web clients
│   ├── claude-client/
│   └── copilot-integration/

docs/
├── QUICKSTART.md
├── PROMPTS.md
├── SECURITY.md
├── AI_INTEGRATION.md
└── QA-REPORT.md            # test status against test-baseline.json

tests/e2e/                   # standalone e2e script
```

## PHI protection

### What masking covers

Masking runs only after authorization allows the read. Rules come from three places: the PHI level defaults (`DEFAULT_MASKING_RULES`), a set of global rules applied to every resource type regardless of the per-type `switch`, and per-type rules in `PHIClassifier.getResourceSpecificMaskingRules()`.

Applied to an IDENTIFIABLE resource:

| Element | Treatment |
|---|---|
| `identifier` | replaced with a pseudonym token (`PT_…`) |
| `resource.id` | replaced with a pseudonym token |
| `Reference.reference` | rewritten to `Type/PT_…` |
| `name` | replaced with `***` |
| `birthDate` | removed |
| `telecom`, `address`, `contact`, `communication` | removed |
| `text.div` (narrative) | removed by default (`narrativePolicy`; `scrub` is the alternative) |
| `meta.source` | removed |
| `meta.security[].display`, `meta.tag[].display` | removed (`system`+`code` retained deliberately) |
| Attachment `.data` | removed at ten known paths; `contentType`, `size`, `hash`, `title`, `creation` retained |
| `contained[]`, `Bundle.entry[].resource` | recursed into and masked as resources in their own right |
| `extension[]` / `modifierExtension[]` | rebuilt from a whitelist — `url` retained, every `value[x]` dropped — including extensions on primitives via the `_field` sibling |

### Uniform tokenization

`resource.id` and `Reference.reference` are tokenized consistently across Condition, Observation, Encounter, MedicationRequest, Procedure and DiagnosticReport. **The same patient yields the same token everywhere within one process**, so a masked bundle stays internally joinable.

### Pseudonym tokens are per-process — read this before caching them

Tokens are `PT_` + 12 base64url characters, derived as `HMAC-SHA256(sessionKey, value)`. The session key is `crypto.randomBytes(32)`, generated in the `PHIMaskingEngine` constructor. Production constructs the engine with no key argument (`phi-authorization-engine.ts:250`), and **nothing persists the key**.

Consequences:

- **Restarting the server changes every token.** The same patient is `PT_aBc…` before a restart and something else after.
- **Cross-session longitudinal linkage is impossible by design.** This is a real unlinkability property, not an accident.
- **Any consumer that caches or stores `PT_` tokens as stable keys will break** at the next restart, silently, by splitting one patient into two. Treat a token as valid only within the response set it arrived in.

`rotateSessionKey()` exists and drops every derived pseudonym when called. There is currently no supported way to supply a stable key from configuration.

## Authentication & Authorization

This section describes what is wired on this branch. There is no OAuth2 or SMART authorization server in this repository; see [What does not exist](#what-does-not-exist) below for the full list.

### What exists

**Caller identity** (`src/security/identity.ts`, lane H). A single service principal is built from environment variables:

| Variable | Meaning |
|---|---|
| `MCP_SERVICE_PRINCIPAL_ID` | Principal id. Absent or empty → no principal → PHI denied. |
| `MCP_SERVICE_PRINCIPAL_SCOPES` | Space-separated scopes from the closed set below. |

Scope spelling follows SMART on FHIR, but **only as a naming convention** so that a future token issuer's `scope` claim maps across without translation. The complete grant table is:

| Scope | Grants |
|---|---|
| `patient/*.read`, `user/*.read`, `system/*.read` | `patient:read` |
| `patient/*.write`, `user/*.write`, `system/*.write` | `patient:write` |
| `x-restricted/*.read` | `restricted:read` |

`x-restricted/*.read` is non-standard on purpose: the RESTRICTED tier (Coverage, Claim, ExplanationOfBenefit, Bundle, Binary) has no SMART equivalent, so reaching it requires a scope that cannot be confused with a standard one and never rides along with an ordinary read scope.

Parsing is strict: an unrecognised scope, a malformed id, or an id declared with no scopes is a **startup error**, not a downgrade. A configured principal always has `roles: []` and never sets `phiAccessLevel` or `isEmergencyAccess` — those are independent grant routes inside the authorization engine, and configuration may not use them. The emergency grant is the only route that returns PHI unmasked, and no environment variable can open it.

**Transport binding:**

- **stdio** — `StaticIdentityProvider` holds the configured principal for the process lifetime.
- **HTTP/SSE** — `RequestScopedIdentityProvider` carries the principal in an `AsyncLocalStorage` entered only after a bearer token has been verified. A tool call arriving by any route that did not go through `runWithPrincipal` gets no identity at all.
- **Default** — `ANONYMOUS_IDENTITY_PROVIDER`, which returns `undefined`. Omitting a provider denies rather than grants.

**HTTP bearer authentication** is a single shared secret: `AUTH_TOKEN`, compared with a timing-safe comparison in `http.ts`. If `AUTH_TOKEN` is unset the HTTP bridge is **open** — it returns `allowed: true` — but binds no principal, so PHI stays denied. Setting a principal does not authenticate anyone; it only says who a verified caller is.

### What does not exist

- No OAuth2 authorization server, no Authorization Code flow, no PKCE, no client credentials grant, no token introspection, no JWKS verification, no per-user tokens, no token expiry.
- `AuthConfig` (`src/types/config.ts`) and `AuthConfigSchema` (`src/tools/schemas.ts`) are orphan type declarations with no implementation behind them.
- No FHIR `AuditEvent` resources are emitted. Audit records are this project's own JSON shape, written with `console.error` (or `console.log` when `AUDIT_SINK=stdout`).
- No machine learning is used anywhere in classification or anomaly detection. Classification is a static resource-type matrix plus regular-expression field-name patterns.

Real token-issuer integration remains Phase 2 work. `identity.ts` defines the seam it plugs into: anything that can verify a caller produces a `User` and hands it to an `IdentityProvider`.

## Audit logging

Records are structured JSON on stderr (stdout is the MCP protocol channel; `AUDIT_SINK=stdout` restores the old behaviour for deployments already scraping it).

Changes on this branch:

- `originalInput` is **no longer written**. It previously carried a sanitized copy of the whole request.
- Metadata passes through a **structural allowlist**, not a keyword denylist, and it is recursive. A key nobody anticipated is dropped rather than published.
- The authorization catch block logs the error **class** only (`AuditLogger.errorClass`), never `error.message` — a thrown message routinely quotes the resource that broke it.
- `resourceId` is replaced by `resourceIdHash`, a keyed HMAC-SHA256 (`AH_` prefix). It was previously an unsalted `sha256` truncated to 16 hex and was reversible; see issue 1 below.
- **Denied reads now produce an audit record.** They previously produced none: `fhir-tools` returned as soon as `allowed` was false and never reached `logFhirOperation`, so the single most reviewable event this control produces left no trace.

## Security issues found by the live audit

A live audit against a real FHIR server (HAPI R4) found four issues beyond the nine remediation lanes. Three are fixed on this branch; the fourth is an open design question. They are recorded here rather than only in an issue tracker because overclaiming is the specific failure mode that produced most of the defects lanes A-I were created to fix.

### 1. `resourceIdHash` was reversible - FIXED

`AuditLogger.hashIdentifier` was `sha256(value)` truncated to 16 hex characters, unsalted and unkeyed, under a docstring claiming it was "not a reversible identifier on its own." That was false for the low-entropy identifier spaces this server handles: a live patient id was recovered from a log line by direct comparison against `sha256(id)`.

The repository already condemned the identical construction - `src/tests/fixtures/canary.ts` defines it as `LEGACY_UNSALTED_SHA256` and describes it as "equivalent to publishing the ID." The audit logger and the canary module disagreed, and the canary module was right.

Now a keyed HMAC-SHA256, matching what `PHIMaskingEngine` already did for pseudonyms, emitting an `AH_`-prefixed token. The false docstring is gone. A regression test asserts the emitted digest is **not** equal to `sha256(id).substring(0,16)`.

### 2. Free text unmasked on several clinical resource types - FIXED

`getResourceSpecificMaskingRules()` had `case` arms for Patient, RelatedPerson, Observation, Encounter, Coverage, Organization, Practitioner, DocumentReference and DiagnosticReport - and no arm at all for Condition, MedicationRequest, Procedure or CarePlan, so their free-text elements survived masking: `note[].text` and `code.text` on Condition, `note[]` and `dosageInstruction[].text` on MedicationRequest, `note[]` and `report[].display` on Procedure, `description` on CarePlan, `presentedForm[].title` and `.url` on DiagnosticReport.

Observation and Encounter were clean, so this was inconsistency between rule sets rather than uniform absence - the guarantee had been written once per resource type, and was therefore missing for every type nobody got to. Clinical notes are exactly where a patient name or ID ends up in practice.

Closed as a class, not a list: `GLOBAL_FREE_TEXT_MASKING_RULES` is applied unconditionally to every resource rather than enumerated per type, so a resource type added later inherits the protection instead of silently missing it.

### 3. `resourceType` log-injection channel - FIXED

`handleRead` copied `args.resourceType` straight into the `SecurityContext`, and on the denial path `auditSecurityDenial` wrote it verbatim into the audit record - twice, as a top-level field and inside metadata. That path runs before validation succeeds and without authentication, so an unauthenticated caller could write chosen text, including forged record boundaries, into the audit stream.

`resourceType` is now deliberately absent from the audit allowlist and passes through `AuditLogger.safeResourceType()`, which emits a placeholder for any value not present in `RESOURCE_PHI_MATRIX`.

### 4. Open design question: is a logical `id` a direct identifier?

This one is **not** fixed, and deliberately so.

`phi-classifier.ts:109-110` sets `hasDirectIdentifiers` when a key is `identifier` **or** `id`, and line 159 then upgrades `MINIMAL` to `IDENTIFIABLE`. Since virtually every resource fetched from a server carries an `id`, `PHILevel.MINIMAL` is unreachable in practice.

Three tests are quarantined in `test-baseline.json` pending a decision. They are not defects to be silently fixed - the decision costs something either way:

- Narrowing `hasDirectIdentifiers` to `identifier` (plus `id` on patient-like types) **reduces protection**.
- Keeping the rule means `PHILevel.MINIMAL` is dead code and the tests should be changed to expect `identifiable`.

No lane owned this decision and it was deliberately not made during the merge. The other five baseline failures (input sanitization, rate limiting x3, security headers) are pre-existing and outside the PHI remediation plan; they need their own triage.

### Also unverified

`DocumentReference` is `IDENTIFIABLE` in `RESOURCE_PHI_MATRIX` (`phi-types.ts:105`) and carries per-type masking rules, but it is **absent from `InputValidator.isValidResourceType`'s allowlist** (`input-validator.ts:423-430`). Reads and searches for it are rejected at validation, so its masking rules are unreachable through the tool surface. Whether this is an intentional restriction or an oversight is not recorded anywhere in the repository; it is documented here as a limitation, not a decision.

## Testing

```bash
npm run build          # required before any runtime testing — see the build trap

cd packages/mcp-fhir-server
npm test               # jest, via the portable ESM launcher
npm run test:gate      # jest + enforce test-baseline.json in both directions
npm run typecheck
npm run typecheck:tests
npm run lint
```

**Current status on this branch: 250 of 258 tests pass, with 8 known failures and 0 regressions** (verified by `npm run test:gate`; 14 suites, 12 passing).

The 8 failures are enumerated with per-entry reasoning in `packages/mcp-fhir-server/test-baseline.json`: three are the `PHILevel.MINIMAL` design question above, five are pre-existing failures outside the PHI remediation plan.

`test:gate` enforces the baseline in **both** directions — an unlisted failure fails CI as a regression, and a listed test that starts passing also fails CI so the entry gets pruned. That is what stops the file from rotting into a blanket suppression.

Additional standalone scripts (not part of the jest suite):

```bash
node test-basic-functionality.js
node manual-qa-test.js
node tests/e2e/test-fhir-mcp.js
npm run test:e2e        # scripts/lane-h-e2e.mjs
```

## Configuration

Read by the MCP server (`packages/mcp-fhir-server`):

| Variable | Description | Default |
|---|---|---|
| `FHIR_BASE_URL` | FHIR server base URL | `https://hapi.fhir.org/baseR4` |
| `FHIR_TOKEN` | Bearer token sent to the FHIR server | — |
| `TERMINOLOGY_BASE_URL` | HL7 terminology service URL | `https://tx.fhir.org/r4` |
| `TERMINOLOGY_TOKEN` | Bearer token sent to the terminology service | — |
| `PHI_MODE` | `safe` or `trusted`. Unrecognised values are a startup error. | `safe` |
| `ENABLE_AUDIT` | Audit logging; any value other than `"false"` enables it | `true` |
| `MCP_SERVICE_PRINCIPAL_ID` | Caller identity. **Unset → all IDENTIFIABLE reads denied.** | — |
| `MCP_SERVICE_PRINCIPAL_SCOPES` | Space-separated scopes from the table above | — |
| `MCP_TRANSPORT` | `http` selects the HTTP/SSE bridge | stdio |
| `PORT` | HTTP transport port | `8080` |
| `AUTH_TOKEN` | Shared bearer secret for HTTP mode. **Unset → HTTP bridge is open.** | — |
| `AUDIT_SINK` | `stdout` writes audit records to stdout instead of stderr | stderr |
| `NODE_ENV` | Standard | — |

Read by the `packages/examples/http-bridge` example only, **not** by the MCP server: `ALLOWED_ORIGINS`, `REQUIRE_HTTPS`, `SECURITY_LOGGING`, `PORT`, `NODE_ENV`, `FHIR_BASE_URL`, `TERMINOLOGY_BASE_URL`.

Rate-limiter thresholds are compiled in, not configurable by environment variable.

## Using with Claude

```json
{
  "mcpServers": {
    "fhir": {
      "command": "node",
      "args": ["path/to/FHIR-MCP/packages/mcp-fhir-server/dist/index.js"],
      "env": {
        "FHIR_BASE_URL": "https://your-fhir-server.com/fhir",
        "TERMINOLOGY_BASE_URL": "https://tx.fhir.org/r4",
        "PHI_MODE": "safe",
        "ENABLE_AUDIT": "true",
        "MCP_SERVICE_PRINCIPAL_ID": "claude-desktop",
        "MCP_SERVICE_PRINCIPAL_SCOPES": "system/*.read"
      }
    }
  }
}
```

Run `npm run build` first — this config points at `dist/`, which is not in the repository.

Omit `MCP_SERVICE_PRINCIPAL_ID` and the server will start and answer `fhir.capabilities` and terminology calls normally, but every Patient read will come back as `Access denied: HEALTHCARE_COMPLIANCE_VIOLATION`.

## HTTP Bridge for Web Applications

For browser-based clients that cannot speak MCP directly.

```bash
cd packages/examples/http-bridge
npm run build
```

```powershell
# PowerShell
$env:PORT = "3001"
$env:FHIR_BASE_URL = "https://hapi.fhir.org/baseR4"
$env:TERMINOLOGY_BASE_URL = "https://tx.fhir.org/r4"
$env:PHI_MODE = "safe"
$env:ENABLE_AUDIT = "true"
npm start
```

```bash
# bash
PORT=3001 FHIR_BASE_URL="https://hapi.fhir.org/baseR4" \
  TERMINOLOGY_BASE_URL="https://tx.fhir.org/r4" \
  PHI_MODE="safe" ENABLE_AUDIT="true" npm start
```

### Docker

```bash
docker-compose up --build

docker build -t fhir-mcp .
docker run -p 3002:3001 \
  -e FHIR_BASE_URL="https://hapi.fhir.org/baseR4" \
  -e TERMINOLOGY_BASE_URL="https://tx.fhir.org/r4" \
  -e PHI_MODE="safe" -e ENABLE_AUDIT="true" fhir-mcp
```

Endpoints at `http://localhost:3002` (3001 for local dev):

- `GET /health` — health check
- `GET /tools` — list available tools
- `POST /fhir/capabilities` | `/fhir/search` | `/fhir/read` | `/fhir/create` | `/fhir/update`
- `POST /terminology/lookup` | `/terminology/expand` | `/terminology/translate`
- `POST /tools/{toolName}` — generic tool interface

The MCP server's own HTTP transport (`MCP_TRANSPORT=http`) exposes `/healthz` separately.

### Active controls

- OWASP security headers
- Multi-tier rate limiting (thresholds compiled in; three of the eight baseline test failures are rate-limiter behaviour disagreements, so verify against your own traffic rather than trusting the defaults)
- Joi input validation and sanitization
- PHI-aware authorization, fail-closed without a principal
- Audit logging on every allowed *and* denied read

## Roadmap

- [x] **MVP**: basic FHIR operations and terminology lookup
- [x] **ES Modules**: modern JavaScript module support
- [x] **HTTP Bridge**: web-accessible REST API
- [x] **Docker**: containerized deployment
- [x] **Test infrastructure**: jest running under ESM, golden corpus, PHI canary harness, enforced failure baseline (lane A)
- [x] **PHI remediation lanes A–I**: fail-closed guard construction, masking rules, masking engine, authorization invariant, log-leak closure, caller identity, uniform tokenization
- [ ] **Security Phase 1**: *not complete.* Three of four audit findings are fixed; one open design question remains, and five pre-existing baseline failures (input sanitization, rate limiting, security headers) are untriaged. See [Security issues found by the live audit](#security-issues-found-by-the-live-audit). Previous revisions of this file marked this done; masking was unreachable in production until lane H and three PHI log leaks were open until lane G.
- [ ] **QA**: *not complete.* 250/258 with 8 known failures; see [docs/QA-REPORT.md](docs/QA-REPORT.md).
- [ ] **Phase 2**: real OAuth2 / SMART-on-FHIR token verification, advanced policy engine
- [ ] **Phase 3**: delete operations, bulk export, R5 support
- [ ] **Future**: GraphQL support, subscription webhooks

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

If a change makes a listed known issue stale, update this README in the same commit. If a change makes a `test-baseline.json` entry pass, delete that entry in the same commit — `test:gate` will fail otherwise, on purpose.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- [HL7 FHIR](https://fhir.hl7.org/) for the interoperability standard
- [Model Context Protocol](https://modelcontextprotocol.io/) for the protocol specification
- [HAPI FHIR](https://hapifhir.io/) for the reference implementation
- [HL7 Terminology Services](https://terminology.hl7.org/) for code system management

