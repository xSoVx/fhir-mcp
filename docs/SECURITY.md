# FHIR-MCP Security Guide

Security guidance for deploying FHIR-MCP, covering what the PHI protection layer actually does on the `integration/phase2` branch, what it does not do, and what is still open.

> **Read this first.** This guide previously described a security posture the code did not have. Every claim below has been checked against the source on this branch; claims that could not be verified are marked as such. There are **four known open security issues**, one of which is a live PHI exposure in audit logs. Do not treat this document as a compliance attestation.

## 🛡️ Threat model and scope

FHIR-MCP sits between an LLM client and a FHIR server. Its job is to ensure that what reaches the model is de-identified according to policy, and that every access attempt is recorded. It is not an authorization server, not a FHIR façade with its own access policy engine, and not a substitute for controls on the upstream FHIR server.

```
┌──────────────────────────────────────────────────────────────┐
│ Layer                          │ Implemented on this branch   │
├──────────────────────────────────────────────────────────────┤
│ 1. Network (HTTPS/TLS)         │ Deploy behind a TLS proxy    │
│ 2. Input validation            │ Joi, allowlisted types       │
│ 3. Rate limiting               │ Yes — see caveat below       │
│ 4. Caller identity             │ Static service principal     │
│ 5. Authorization (PHI)         │ Fail-closed engine           │
│ 6. Masking / de-identification │ Rule-driven, gaps documented │
│ 7. Audit logging               │ JSON on stderr               │
│ 8. Container isolation         │ Non-root Alpine image        │
└──────────────────────────────────────────────────────────────┘
```

## 🔑 Caller identity — mandatory for PHI

This is the change most likely to break an existing deployment.

Before lane H, the tool layer built its `SecurityContext` with no `userId`. Measured against a live FHIR server, the result was that **every IDENTIFIABLE resource was suppressed before masking** — the masking engine never executed in production, while the documentation described it as active.

`src/security/identity.ts` supplies the missing identity. The enforcement point is `performComplianceChecks` in `src/security/security-middleware.ts`:

```ts
if (context.phiLevel === PHILevel.IDENTIFIABLE || context.phiLevel === PHILevel.RESTRICTED) {
  if (!context.userId)   { violations.push('PHI access requires authenticated user'); blockRequest = true; }
  if (!context.sessionId || context.sessionId === 'anonymous') { ...; blockRequest = true; }
}
```

**With no configured principal, every IDENTIFIABLE or RESTRICTED read returns `HEALTHCARE_COMPLIANCE_VIOLATION` and no resource body.** That is the intended fail-closed behaviour, and an unconfigured deployment behaves bit-for-bit as the old one did: denied.

### Configuring a principal

```powershell
# PowerShell
$env:MCP_SERVICE_PRINCIPAL_ID = "svc-analytics"
$env:MCP_SERVICE_PRINCIPAL_SCOPES = "system/*.read"
```

```bash
# bash
export MCP_SERVICE_PRINCIPAL_ID="svc-analytics"
export MCP_SERVICE_PRINCIPAL_SCOPES="system/*.read"
```

The scope set is closed. Anything outside it is a **startup error**, not a silent downgrade — a DLP control should refuse to start rather than quietly resolve to something weaker.

| Scope | Grants | Notes |
|---|---|---|
| `patient/*.read` | `patient:read` | |
| `user/*.read` | `patient:read` | |
| `system/*.read` | `patient:read` | |
| `patient/*.write` | `patient:write` | |
| `user/*.write` | `patient:write` | |
| `system/*.write` | `patient:write` | |
| `x-restricted/*.read` | `restricted:read` | Non-standard `x-` prefix on purpose |

Scope *spelling* follows SMART on FHIR so that a future token issuer's `scope` claim maps across without translation. It does not imply a SMART authorization server exists here — it does not.

The RESTRICTED tier (Coverage, Claim, ExplanationOfBenefit, Bundle, Binary) has no SMART equivalent. Reaching it requires `x-restricted/*.read`, which cannot be mistaken for a standard scope and never comes along for the ride with an ordinary read scope.

### What configuration cannot do

By construction, a configured principal always has `roles: []`, never sets `phiAccessLevel`, and has `isEmergencyAccess` pinned `false`. Roles and `phiAccessLevel` are independent grant routes inside the authorization engine; allowing configuration to set them would make the scope table an incomplete statement of what configuration can grant. Emergency access is the only route that returns PHI **unmasked**, and no environment variable can open it.

### Transport binding

| Transport | Provider | Behaviour |
|---|---|---|
| stdio | `StaticIdentityProvider` | One principal for the process lifetime |
| HTTP/SSE | `RequestScopedIdentityProvider` | Principal carried in `AsyncLocalStorage`, entered in `http.ts` **only after** the bearer token is verified. `runWithPrincipal(undefined, …)` explicitly *exits* the store, so no request inherits another's principal. |
| default | `ANONYMOUS_IDENTITY_PROVIDER` | Returns `undefined` — omitting a provider denies rather than grants |

### HTTP authentication is a shared secret

`AUTH_TOKEN` is a single static bearer token compared with a timing-safe comparison. It is **not** OAuth2, has no expiry, no rotation, no per-user identity and no revocation.

Two consequences worth stating plainly:

- **If `AUTH_TOKEN` is unset, the HTTP bridge is open.** `authenticate()` returns `allowed: true`. It binds no principal, so PHI stays denied — but non-PHI operations are reachable by anyone who can route to the port.
- **Setting a principal does not authenticate anyone.** It only declares who a verified caller *is*. If you set `MCP_SERVICE_PRINCIPAL_ID` without `AUTH_TOKEN` on the HTTP transport, the startup banner warns about it, and the identity is not bound to unverified requests.

Terminate TLS in front of this and restrict network access to the port. The token travels in a header.

## 🔒 PHI masking

Masking runs only after authorization allows the read. The rule set is assembled from three sources, deliberately independent of each other so that adding a resource type cannot silently omit the global layer.

### Global rules (every resource type, regardless of the per-type `switch`)

| Rule | Effect |
|---|---|
| `identifier` | pseudonym token |
| narrative `text` / `text.div` | removed by default; `narrativePolicy: 'scrub'` is the alternative |
| Attachment `.data` at ten paths | removed; `contentType`, `size`, `hash`, `title`, `creation` retained so the model still knows a document exists |
| `meta.source` | removed — pipelines build it from the record they extracted |
| `meta.security[].display`, `meta.tag[].display` | removed; `system`+`code` **retained deliberately**, because deleting the confidentiality label would tell a downstream consumer the resource is less sensitive than it is |
| person-valued `Reference`s | tokenized |

### PHI-level defaults at IDENTIFIABLE

`name` → `***`; `identifier` → token; `birthDate`, `address`, `telecom`, `contact`, `communication` → removed.

Note: the Patient per-type rule says `birthDate: partial` ("year only") but the IDENTIFIABLE default says `remove`, and **removal is what happens** — `phi-authz-canary.test.ts:113` asserts `masked.birthDate` is `undefined` and passes. Earlier documentation claiming `birthDate → "YYYY-**-**"` was wrong.

### Structural handling

- **`contained[]` and `Bundle.entry[].resource`** are classified and masked as resources in their own right, not walked as plain objects.
- **`extension[]` / `modifierExtension[]`** are *rebuilt from a whitelist* rather than filtered by a denylist. `url` survives so the consumer is told which extension was present; every `value[x]` is dropped. This covers extensions on **primitives** via the `_field` sibling (`_birthDate.extension[]`), which has no dot-path and so cannot be expressed as a masking rule at all. `modifierExtension` is included because it carries the same free-form payload and differs only in that ignoring it changes meaning.
- **RESTRICTED** removes all fields except `resourceType`.

### Pseudonym tokens are per-process

`PT_` + 12 base64url characters, derived as `HMAC-SHA256(sessionKey, value)`. The session key is `crypto.randomBytes(32)` created in the `PHIMaskingEngine` constructor; production constructs the engine with no key (`phi-authorization-engine.ts:250`) and **nothing persists it**.

| Property | Consequence |
|---|---|
| Stable within a process | `resource.id` and `Reference.reference` tokenize to the same value across Condition, Observation, Encounter, MedicationRequest, Procedure and DiagnosticReport, so a masked bundle stays internally joinable |
| Not stable across restarts | The same patient gets a different token after a restart |
| No persistence path | Cross-session longitudinal linkage is **impossible by design** — a genuine unlinkability property |
| — | **Any consumer caching `PT_` tokens as stable keys will break silently**, splitting one patient into two records. Treat a token as valid only within the response set it arrived in. |

`rotateSessionKey()` drops every derived pseudonym. There is currently no supported way to supply a stable key from configuration; adding one would trade unlinkability for linkage and should be a deliberate, documented decision.

## 🚦 Rate limiting

Six buckets, all with a **one-minute** window. Earlier documentation said 15 minutes; that was wrong.

| Bucket | Limit | Key |
|---|---|---|
| `default` | 100 / min | |
| `search` | 50 / min | |
| `phi_access` | 20 / min | `phi:{userId\|sessionId}` |
| `write` | 10 / min | `write:{userId\|sessionId}` |
| `emergency` | 5 / min | |
| `ip_based` | 200 / min | anonymous requests |

**Caveat.** Two of the eight known test failures are `Security Integration Tests › Rate Limiting`, where the suite observes zero blocked requests where it expects some, plus a third downstream middleware failure. The limiter's behaviour under test does not match its stated intent. Verify against your own traffic before relying on these numbers, and do not treat rate limiting as a control you have evidence for.

Thresholds are **compiled in**. `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX_REQUESTS`, `FHIR_RATE_LIMIT_MAX` and `WRITE_RATE_LIMIT_MAX` appeared in earlier versions of this guide and are read by nothing.

## ✅ Input validation

Joi-based, in `src/security/input-validator.ts`.

- `resourceType` is checked against an allowlist of 20 types. **`DocumentReference` is not on it**, despite being `IDENTIFIABLE` in the PHI matrix with its own masking rules — so those rules are unreachable through the tool surface. See open issues.
- `id` must match `/^[A-Za-z0-9\-_.]+$/`, 1–64 characters.
- Rejected values are **not interpolated into error messages**, because those messages are returned to the caller *and* handed to the audit logger. Validation failures name the field, not the value. A rejected search-parameter name carries no field at all, since it is arbitrary caller-controlled text.

## 📝 Audit logging

Structured JSON, written with `console.error` to **stderr** by default. stdout is the MCP protocol channel — an audit trail written there lands wherever the client pipes the protocol rather than in a log the covered entity controls. `AUDIT_SINK=stdout` restores the old behaviour for deployments already scraping stdout.

### What changed on this branch

| Change | Why |
|---|---|
| `originalInput` no longer written | It carried a sanitized copy of the whole request |
| Metadata: recursive structural **allowlist** | The previous shallow keyword denylist (`token\|authorization\|password\|secret\|ssn\|birthdate`) wrote given names, family names and a nine-digit national ID to the log in clear text, because `name`, `identifier` and `id` were not on it. An allowlist inverts the failure mode: an unanticipated key is dropped rather than published. |
| Authorization catch logs error **class** only | A forced throw during PHI authorization had produced `error: "boom for patient <name> MRN <id>"` in the audit stream |
| Metadata key names checked against `/^[A-Za-z0-9_]{1,40}$/` | A key name must not become a smuggling channel for a value |
| `resourceId` → `resourceIdHash` | **See open issue 1 — this hash is reversible** |
| Denied reads now produce a record | They previously produced none. A refusal that is not recorded cannot be reviewed, and a DLP control whose refusals are invisible cannot be distinguished from one that was never consulted. |

### What audit logging is not

- **No FHIR `AuditEvent` resources are emitted.** The records are this project's own JSON shape. Earlier documentation claimed standards-compliant `AuditEvent` emission; there is no such code.
- **Logs are not tamper-proof and there is no cryptographic validation of them.** They are console output. Integrity, retention and write-once storage are the responsibility of whatever collects stderr.
- **There is no built-in real-time alerting.** Log analysis examples below assume you have shipped the stream somewhere.
- The `/var/log/fhir-mcp/*.log` paths in earlier versions of this guide were illustrative and are not created by the server.

## 🤖 No machine learning is involved

Earlier versions of this guide described "ML-powered" PHI classification and "behavioural analysis" for anomaly detection. Neither exists. Classification is:

1. a static resource-type matrix (`RESOURCE_PHI_MATRIX` in `src/types/phi-types.ts`), and
2. regular-expression field-name patterns (`SENSITIVE_FIELD_PATTERNS`: `/name/i`, `/identifier/i`, `/birth/i`, `/address/i`, `/phone/i`, `/email/i`, `/ssn/i`, `/social/i`, `/contact/i`, `/telecom/i`, `/photo/i`, `/image/i`).

This matters for your risk assessment: the system recognises what it was told to recognise. A PHI-bearing field with an unanticipated name is not detected by pattern matching, which is precisely why the structural and allowlist-based defences above carry the real weight.

## 🚨 Known open security issues

### 1. `resourceIdHash` is reversible — live PHI exposure

**Severity: high. Status: open.**

`AuditLogger.hashIdentifier` (`audit-logger.ts:235-238`):

```ts
return createHash('sha256').update(value).digest('hex').substring(0, 16);
```

Unsalted, unkeyed, truncated. Its docstring claims it is "not a reversible identifier on its own." That is false for the identifier spaces this server handles. A live patient id was recovered from a log line by direct comparison against `sha256(id)`.

The repository already condemns this exact construction. `src/tests/fixtures/canary.ts:298-310` computes `LEGACY_UNSALTED_SHA256` identically and documents it as the **pre-fix** behaviour:

> the Israeli ID space is ~10^8 after the check digit, so a complete rainbow table over these values is minutes of GPU time — the value below is therefore equivalent to publishing the ID.

The audit logger and the canary module contradict each other, and the canary module is correct.

**Fix direction:** HMAC the digest with a per-deployment secret, as `PHIMaskingEngine` already does for pseudonyms, and delete the docstring's safety claim. Rotating the key breaks historical log correlation — that trade should be made explicitly.

**OWASP:** A02:2021 Cryptographic Failures; A09:2021 Security Logging and Monitoring Failures.

### 2. Free text unmasked on several clinical resource types

**Severity: high. Status: open.**

`PHIClassifier.getResourceSpecificMaskingRules()` has `case` arms for Patient, RelatedPerson, Observation, Encounter, Coverage, Organization, Practitioner, DocumentReference and DiagnosticReport — and **none** for Condition, MedicationRequest, Procedure or CarePlan. Those types receive only the global rules.

| Resource | Unmasked |
|---|---|
| Condition | `note[].text`, `code.text` |
| MedicationRequest | `note[]`, `dosageInstruction[].text` |
| Procedure | `note[]`, `report[].display` |
| CarePlan | `description` |
| DiagnosticReport | `presentedForm[].title`, `presentedForm[].url` — `conclusion` and `presentedForm[].data` *are* handled |

Observation (`note` → remove) and Encounter are clean. **This is inconsistency between rule sets, not uniform absence** — the same defect shape as the `identifier` and `extension` findings before it: a guarantee expressed once per resource type is missing for every type nobody got to.

Clinical notes are where a patient name or ID actually ends up in practice. A Condition whose structured fields are fully masked can still return `note[0].text: "Patient Yossi Cohen, ID 123456782, seen today"`.

**Fix direction:** add the missing arms, or better, hoist free-text handling into the global layer the way `identifier` and references already were.

### 3. `resourceType` log-injection channel

**Severity: medium. Status: open.**

`handleRead` copies `args.resourceType` straight into the `SecurityContext` (`fhir-tools.ts:335`). On denial, `auditSecurityDenial` writes `context.resourceType` verbatim into the audit record twice — as a top-level field and inside metadata (`security-middleware.ts:432,437`). **That path runs before validation succeeds and without authentication.**

`resourceType` is on the audit allowlist (`audit-logger.ts:36`). Allowlisted *keys* are checked against `/^[A-Za-z0-9_]{1,40}$/`; allowlisted *values* are only length-bounded by `boundString` — no character filtering, so newlines and JSON survive. An unauthenticated caller can write chosen text, including forged record boundaries, into the audit stream, corrupting exactly the artifact a breach investigation depends on.

**Fix direction:** validate `resourceType` against the allowlist before it reaches the `SecurityContext`, or emit a `code`-style substitution (`unknown_resource_type`) rather than the value — the same discipline `input-validator.ts` already applies to its error messages.

**OWASP:** A09:2021 Security Logging and Monitoring Failures; CWE-117 Improper Output Neutralization for Logs.

### 4. Open design question: is a logical `id` a direct identifier?

**Severity: informational. Status: undecided, deliberately.**

`phi-classifier.ts:109-110` sets `hasDirectIdentifiers` when a key is `identifier` **or** `id`; line 159 upgrades `MINIMAL` → `IDENTIFIABLE`. Since nearly every resource fetched from a server carries an `id`, **`PHILevel.MINIMAL` is unreachable in practice**.

Three tests are quarantined in `test-baseline.json` awaiting a decision. This is a question, not a defect:

- Narrowing `hasDirectIdentifiers` to `identifier` (plus `id` on patient-like types) **reduces protection** — a server-assigned `id` can be a re-identification handle when combined with anything else.
- Keeping the rule means `PHILevel.MINIMAL` is dead code and the three tests should be changed to expect `identifiable`.

No lane owned the decision and it was deliberately not taken during the merge rather than resolved in whichever direction made the tests green.

### Limitation: `DocumentReference` is unreachable

`DocumentReference` is `IDENTIFIABLE` in `RESOURCE_PHI_MATRIX` (`phi-types.ts:105`) and has per-type masking rules, but it is absent from `InputValidator.isValidResourceType`'s 20-entry allowlist (`input-validator.ts:423-430`). Reads and searches for it are rejected at validation, so its masking rules never execute through the tool surface.

**Unverified:** nothing in the repository records whether this is an intentional restriction or an oversight. It is documented as a limitation, not a decision. If it is later added to the allowlist, its masking rules and the tests around them already exist.

## 🔧 Production deployment

### Environment

```powershell
# PowerShell
$env:NODE_ENV = "production"
$env:PHI_MODE = "safe"
$env:ENABLE_AUDIT = "true"

# Identity — without this, every IDENTIFIABLE read is denied
$env:MCP_SERVICE_PRINCIPAL_ID = "svc-production"
$env:MCP_SERVICE_PRINCIPAL_SCOPES = "system/*.read"

# HTTP transport
$env:MCP_TRANSPORT = "http"
$env:PORT = "8080"
$env:AUTH_TOKEN = "<long random secret>"   # unset = open bridge
```

```bash
# bash
export NODE_ENV=production
export PHI_MODE=safe
export ENABLE_AUDIT=true
export MCP_SERVICE_PRINCIPAL_ID="svc-production"
export MCP_SERVICE_PRINCIPAL_SCOPES="system/*.read"
export MCP_TRANSPORT=http
export PORT=8080
export AUTH_TOKEN="<long random secret>"
```

`npm run start:http` uses POSIX `VAR=x command` prefix syntax and **fails on PowerShell**. Set the variables first and run `node dist/http.js` directly.

Read only by the `packages/examples/http-bridge` example: `ALLOWED_ORIGINS`, `REQUIRE_HTTPS`, `SECURITY_LOGGING`. Read by nothing anywhere: `CORS_CREDENTIALS`, `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX_REQUESTS`, `FHIR_RATE_LIMIT_MAX`, `WRITE_RATE_LIMIT_MAX`.

### Build before deploying

`dist/` is gitignored but is what `main`, `bin`, `npm start`, `npm run start:http` and the Dockerfile all load. Jest runs against `src/`. **A green test suite does not mean the deployed path carries the fixes.** Run `npm run build` before every deployment and after every pull that touches `src/`; a stale `dist/` will serve pre-remediation masking code while CI stays green.

### TLS termination

```nginx
server {
    listen 443 ssl http2;
    server_name your-fhir-mcp-domain.com;

    ssl_certificate     /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=63072000" always;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Container hardening

The shipped `Dockerfile` is a multi-stage build on `node:18-alpine` running as a non-root user, and `docker-compose.yml` is the reference deployment. Recommended additions if you are writing your own compose file:

```yaml
services:
  fhir-mcp-bridge:
    security_opt: [ "no-new-privileges:true" ]
    read_only: true
    tmpfs: [ "/tmp:noexec,nosuid,size=100m" ]
    cap_drop: [ ALL ]
    deploy:
      resources:
        limits: { cpus: '1.0', memory: 512M }
```

## 🏥 HIPAA considerations

This section lists what the software contributes toward a Security Rule assessment. **It is not an attestation, and several safeguards are the deployer's responsibility, not the software's.**

| Safeguard | Provided by FHIR-MCP | Your responsibility |
|---|---|---|
| §164.312(a) Access control | Fail-closed PHI authorization; scope-gated principal | Real user authentication; the shared `AUTH_TOKEN` is not per-user attribution |
| §164.312(b) Audit controls | Structured record per allowed and denied access | Log shipping, retention, integrity, review. **Issue 1 means ids in current logs are recoverable.** |
| §164.312(c) Integrity | — | Log write-once storage, backup integrity |
| §164.312(e) Transmission security | — | TLS termination; the server speaks plain HTTP |
| §164.308 Administrative | — | Workforce training, incident response, BAAs, risk analysis |
| §164.310 Physical | Non-root container, resource limits | Host and datacentre controls |
| De-identification (§164.514) | Rule-driven masking + pseudonymisation | **Neither Safe Harbor nor Expert Determination is claimed.** Open issue 2 means free text on several clinical types is returned intact, which alone defeats Safe Harbor. |

## 📊 Security testing

```bash
cd packages/mcp-fhir-server
npm test              # 250/258 on this branch
npm run test:gate     # + enforce test-baseline.json in both directions
npm run test:e2e      # scripts/lane-h-e2e.mjs
npm audit --audit-level high
```

There is **no** `npm run test:security` script; earlier versions of this guide referenced one.

The PHI-specific suites are the useful security artifact. `phi-canary.test.ts` plants a single canary value in every element a FHIR resource can hide an identifier in and **asserts the leaky path actually ran before asserting the leak is gone** — a non-vacuous test, which is the property the original QA pass lacked. `phi-authz-invariant.test.ts` pins the structural rule that any `allowed: true` at IDENTIFIABLE or above carries a non-empty rule set.

Not performed on this branch: penetration testing, container image scanning, formal dependency review. Treat the penetration-testing and compliance checklists that used to appear here as work items, not as completed items.

## 🚨 If you suspect a breach

1. **Contain** — revoke `AUTH_TOKEN`, restrict network access to the port, preserve the audit stream before rotation.
2. **Assess scope with issue 1 in mind** — `resourceIdHash` values in your existing logs are recoverable by anyone who obtains them. Treat historical audit logs as PHI-bearing until the hash is keyed.
3. **Check free-text exposure** — if Condition, MedicationRequest, Procedure, CarePlan or DiagnosticReport resources were read, assume clinical notes reached the model unmasked (issue 2).
4. **Check log integrity** — `resourceType` is attacker-controllable in denial records (issue 3), so audit records may contain forged content.
5. **Verify the deployed build** — confirm `dist/` was rebuilt from the branch you think is running. A stale `dist/` is an easy way to have been running unremediated code.

## 📚 References

- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [HL7 FHIR Security](https://www.hl7.org/fhir/security.html)
- [Trivy](https://github.com/aquasecurity/trivy) for container scanning

---

**⚠️** Phase 2 — real OAuth2 / SMART-on-FHIR token verification and an advanced policy engine — is not started. `identity.ts` defines the seam it plugs into. Consult your organisation's security and compliance teams before deploying against real patient data, and give them the open-issues section above.
