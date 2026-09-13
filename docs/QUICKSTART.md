# FHIR-MCP Quick Start Guide

FHIR-MCP is an MCP (Model Context Protocol) server that lets LLMs access FHIR servers and HL7 terminology services behind a PHI de-identification layer with audit logging.

> **Two things will trip you up on first run.** Read [Identity is required](#identity-is-required-for-phi) and [Build before you run](#build-before-you-run) before anything else. On Windows, also read [Windows shell note](#windows-shell-note) — the documented `npm run start:http` command does not work in PowerShell.

## Prerequisites

- Node.js 18 or later
- npm

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/fhir-mcp.git
   cd fhir-mcp
   ```

2. Install dependencies (from the repository root — this is an npm workspace):

   ```bash
   npm install
   ```

3. Build:

   ```bash
   npm run build
   ```

## Build before you run

`dist/` is gitignored, and it is what actually runs: `package.json` `main` and `bin`, `npm start`, `npm run start:http`, the Dockerfile, and the Claude Desktop config below all point at `dist/`. The test suite, by contrast, runs against `src/`.

**So a passing test run tells you nothing about what is deployed.** Run `npm run build` after cloning, after every pull that touches `src/`, and before every deployment. A stale `dist/` will silently serve older code.

## Identity is required for PHI

Since the lane-H identity work, **the server denies every IDENTIFIABLE or RESTRICTED read unless a caller principal is configured**. You will get:

```
Read access denied: HEALTHCARE_COMPLIANCE_VIOLATION
```

This is deliberate and fail-closed. Before identity was wired, the tool layer supplied no `userId`, so every IDENTIFIABLE resource was suppressed *before* masking — the masking engine never ran in production while the docs said it did. The fix makes the denial explicit rather than accidental.

Set a principal to get resource bodies:

```powershell
# PowerShell
$env:MCP_SERVICE_PRINCIPAL_ID = "svc-quickstart"
$env:MCP_SERVICE_PRINCIPAL_SCOPES = "system/*.read"
```

```bash
# bash
export MCP_SERVICE_PRINCIPAL_ID="svc-quickstart"
export MCP_SERVICE_PRINCIPAL_SCOPES="system/*.read"
```

Valid scopes are a closed set: `patient/*.read`, `user/*.read`, `system/*.read`, `patient/*.write`, `user/*.write`, `system/*.write`, `x-restricted/*.read`. Anything else is a **startup error**, not a downgrade. See [SECURITY.md](SECURITY.md) for the full grant table.

Without a principal, `fhir.capabilities` and the terminology tools still work — it is PHI-bearing reads that are denied.

## Windows shell note

`npm run start:http` is defined as:

```
"start:http": "MCP_TRANSPORT=http PORT=8080 node dist/http.js"
```

The `VAR=value command` prefix is POSIX-shell syntax. PowerShell parses `MCP_TRANSPORT=http` as a command name and fails. The same applies to every `VAR=... npm ...` line in this repository's documentation.

On Windows, set the variables first and invoke node directly:

```powershell
$env:MCP_TRANSPORT = "http"
$env:PORT = "8080"
node dist/http.js
```

## Configuration

```powershell
# PowerShell
$env:FHIR_BASE_URL = "https://hapi.fhir.org/baseR4"
$env:FHIR_TOKEN = "your-bearer-token-here"          # optional, sent to the FHIR server
$env:TERMINOLOGY_BASE_URL = "https://tx.fhir.org/r4"
$env:TERMINOLOGY_TOKEN = "your-terminology-token"   # optional
$env:PHI_MODE = "safe"                              # or "trusted"
$env:ENABLE_AUDIT = "true"
$env:MCP_SERVICE_PRINCIPAL_ID = "svc-quickstart"
$env:MCP_SERVICE_PRINCIPAL_SCOPES = "system/*.read"
```

```bash
# bash
export FHIR_BASE_URL="https://hapi.fhir.org/baseR4"
export FHIR_TOKEN="your-bearer-token-here"          # optional
export TERMINOLOGY_BASE_URL="https://tx.fhir.org/r4"
export TERMINOLOGY_TOKEN="your-terminology-token"   # optional
export PHI_MODE="safe"
export ENABLE_AUDIT="true"
export MCP_SERVICE_PRINCIPAL_ID="svc-quickstart"
export MCP_SERVICE_PRINCIPAL_SCOPES="system/*.read"
```

`PHI_MODE` accepts only `safe` or `trusted`; anything else is a startup error. `ENABLE_AUDIT` is on unless set to exactly `"false"`.

Full variable table, including which are read only by the HTTP bridge example and which are read by nothing, is in the main [README](../README.md#-configuration).

## Running the Server

### Option 1 — stdio (Claude Desktop)

```bash
cd packages/mcp-fhir-server
npm run build
npm start
```

with the environment set as above.

### Option 2 — HTTP/SSE (remote access)

```powershell
cd packages/mcp-fhir-server
npm run build
$env:MCP_TRANSPORT = "http"
$env:PORT = "8080"
$env:AUTH_TOKEN = "<long random secret>"
node dist/http.js
```

**If `AUTH_TOKEN` is unset the bridge is open** — it accepts unauthenticated requests. It binds no principal in that case, so PHI stays denied, but set the token anyway for anything beyond a local experiment.

### Option 3 — HTTP bridge (web applications)

```powershell
cd packages/examples/http-bridge
npm run build
$env:PORT = "3001"
npm start
```

**Transport options:**

- **stdio** (default) — direct Claude Desktop integration
- **HTTP/SSE** — MCP protocol over HTTP with Server-Sent Events; health endpoint at `/healthz`
- **HTTP bridge** — a separate REST API example wrapper, not native MCP; health endpoint at `/health`

## Available Tools

### FHIR Operations

- **`fhir.capabilities`** — get server capability statement
- **`fhir.search`** — search FHIR resources
- **`fhir.read`** — read a resource by ID
- **`fhir.create`** — create a resource (write scope required)
- **`fhir.update`** — update a resource (write scope required)

### Terminology Operations

- **`terminology.lookup`** — look up code properties and display
- **`terminology.expand`** — expand a ValueSet
- **`terminology.translate`** — translate codes between systems

`resourceType` is checked against an allowlist of 20 types. Note that **`DocumentReference` is not on it**, so requests for it are rejected at validation even though the PHI layer has masking rules for it. See [SECURITY.md](SECURITY.md#limitation-documentreference-is-unreachable).

## Quick Examples

### Search for Patients

```json
{
  "name": "fhir.search",
  "arguments": {
    "resourceType": "Patient",
    "params": { "name": "John", "_count": "5" },
    "elements": ["id", "name", "gender", "birthDate"]
  }
}
```

Requesting `name` and `birthDate` in `elements` does not get you their values in `safe` mode — `name` comes back as `***` and `birthDate` is removed entirely. `elements` reduces what the FHIR server sends; masking then applies on top.

### Read a Specific Patient

```json
{
  "name": "fhir.read",
  "arguments": {
    "resourceType": "Patient",
    "id": "123456",
    "elements": ["id", "name", "gender"]
  }
}
```

The returned `id` is a pseudonym token (`PT_…`), not `123456`.

### Look Up a LOINC Code

```json
{
  "name": "terminology.lookup",
  "arguments": { "system": "http://loinc.org", "code": "29463-7" }
}
```

### Search for Latest Lab Results

```json
{
  "name": "fhir.search",
  "arguments": {
    "resourceType": "Observation",
    "params": {
      "patient": "Patient/123",
      "category": "laboratory",
      "date": "ge2024-01-01"
    },
    "sort": "-date",
    "count": 10,
    "elements": ["id", "code", "effectiveDateTime", "valueQuantity"]
  }
}
```

## What you will see in masked output

In `safe` mode on an IDENTIFIABLE resource:

| Field | What comes back |
|---|---|
| `identifier` | `PT_` + 12 characters |
| `id` | `PT_` + 12 characters |
| `Reference.reference` | `Patient/PT_…` |
| `name` | `***` |
| `birthDate` | absent |
| `telecom`, `address`, `contact` | absent |
| `text.div` | absent |
| `meta.source` | absent |
| Attachment `.data` | absent; `contentType`, `size`, `title` retained |
| `extension[]` | `url` retained, values dropped |

### Pseudonym tokens do not survive a restart

`PT_` tokens are derived from a session key generated with `crypto.randomBytes(32)` at process start and never persisted. The same patient yields the **same** token everywhere within one process, and a **different** token after a restart.

This is intentional unlinkability, but it means **any client that caches or stores `PT_` tokens as stable identifiers will break silently**, splitting one patient into two. Treat a token as meaningful only within the response set it arrived in.

### Known gaps

Free text is **not** masked on Condition (`note[].text`, `code.text`), MedicationRequest (`note[]`, `dosageInstruction[].text`), Procedure (`note[]`, `report[].display`), CarePlan (`description`) or DiagnosticReport (`presentedForm[].title`, `.url`). Observation and Encounter are clean. If you search those types, expect clinical notes to come through intact. See [SECURITY.md](SECURITY.md#-known-open-security-issues).

## Audit Logging

Every operation is logged with a timestamp, trace ID, operation type, success/failure and allowlisted metadata. **Denied reads are logged too**, which was not previously the case.

Records go to **stderr** by default, because stdout is the MCP protocol channel. Set `AUDIT_SINK=stdout` if you are already scraping stdout.

Metadata passes a structural allowlist — an unanticipated key is dropped rather than published. Note the open issue: the `resourceIdHash` field in audit records is an unsalted SHA-256 truncated to 16 hex characters and is **reversible** for real patient ids. Treat current audit logs as PHI-bearing. See [SECURITY.md](SECURITY.md#1-resourceidhash-is-reversible--live-phi-exposure).

## Testing

```bash
npm run build                 # first — the suite runs against src/, deployment uses dist/

cd packages/mcp-fhir-server
npm test                      # jest: 250/258 pass, 8 known failures on this branch
npm run test:gate             # jest + baseline enforcement (exits 0 with the 8 known failures)
npm run typecheck
npm run lint
```

Standalone scripts, outside the jest suite:

```bash
node manual-qa-test.js
node tests/e2e/test-fhir-mcp.js
node test-basic-functionality.js
npm run test:e2e              # scripts/lane-h-e2e.mjs
```

HTTP bridge smoke test:

```bash
curl -s http://localhost:3001/health
curl -s http://localhost:3001/tools
```

These run against public HAPI FHIR and HL7 terminology servers. The 8 known failures and their reasoning are in `packages/mcp-fhir-server/test-baseline.json` and summarised in [QA-REPORT.md](../QA-REPORT.md).

## Using with Claude

### Claude Desktop

```json
{
  "mcpServers": {
    "fhir": {
      "command": "node",
      "args": ["path/to/fhir-mcp/packages/mcp-fhir-server/dist/index.js"],
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

Run `npm run build` first — `dist/index.js` is not in the repository. Omit the two principal variables and every Patient read will come back denied.

### HTTP bridge (web applications)

```javascript
const response = await fetch('http://localhost:3001/fhir/capabilities', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ "_summary": "true" })
});
const capabilities = await response.json();
```

## Token Efficiency Tips

1. **Use field selection** — specify `elements` to limit returned fields
2. **Filter early** — include specific search parameters like `patient`, `code`, `date`
3. **Sort and limit** — use `sort` with `count` to get relevant results first
4. **Batch** — combine searches where possible

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Access denied: HEALTHCARE_COMPLIANCE_VIOLATION` on every Patient read | No `MCP_SERVICE_PRINCIPAL_ID` configured. This is the expected fail-closed behaviour. |
| Server starts then exits with a config error | An unrecognised scope in `MCP_SERVICE_PRINCIPAL_SCOPES`, or a `PHI_MODE` other than `safe`/`trusted`. Strict parsing is deliberate. |
| `MCP_TRANSPORT=http : The term ... is not recognized` | PowerShell cannot use POSIX env-prefix syntax. See [Windows shell note](#windows-shell-note). |
| `Cannot find module '.../dist/index.js'` | `npm run build` not run. `dist/` is gitignored. |
| Masking looks like the old behaviour | Stale `dist/`. Rebuild. |
| The same patient has two different `PT_` tokens | The server restarted between the two responses. Tokens are per-process by design. |
| Connection errors | Verify `FHIR_BASE_URL` is reachable |
| Timeouts | Some FHIR servers are slow; the HTTP client uses a 30s timeout. Request smaller result sets. |
| Schema errors | Check the request matches the tool schema; note the `resourceType` allowlist |

### Logging verbosity

There is no `DEBUG` environment variable — earlier versions of this guide suggested `DEBUG="fhir-mcp:*"`, which is read by nothing. The server writes its startup banner and all audit records to stderr; capture stderr to see them. `AUDIT_SINK=stdout` moves audit records to stdout.

## Next Steps

- [Prompt Library](PROMPTS.md) — LLM usage patterns
- [Security Guide](SECURITY.md) — production deployment, PHI details, **and the four known open issues**
- [QA-REPORT.md](../QA-REPORT.md) — current test status
- `packages/examples/` — client implementations
