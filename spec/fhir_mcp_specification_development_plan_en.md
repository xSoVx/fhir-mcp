# FhirMCP – Specification & Development Plan

## Executive Summary
FhirMCP is an open‑source MCP (Model Context Protocol) server that connects any LLM to FHIR servers and to an HL7 Terminology Service, through a well‑defined, schema‑first toolset. It emphasizes secure access (SMART on FHIR / OAuth2), strict scope enforcement, PHI minimization/masking, and portable interoperability across popular FHIR servers (HAPI, Firely, public sandboxes). The goal is to enable LLMs to reason over clinical data and terminology via precise, auditable MCP tools—without free‑form scraping.

---

## Goals
- **Simplicity:** Provide a concise set of MCP tools covering read/search (MVP) and controlled write operations (later).
- **Security:** OAuth2/SMART scopes, least‑privilege, PHI masking, explicit user confirmation for risky operations, full audit trail.
- **Interoperability:** Work with R4/R4B first; accommodate R5 later. Compatible with multiple FHIR and terminology endpoints.
- **Token Efficiency:** Support field selection (`_elements`), sorted & paginated queries, tight filters, and short, composable prompt templates.
- **Extensibility:** Modular provider abstraction (FHIR, Terminology), policy engine, telemetry hooks.

---

## Primary Use Cases
1. **Context‑aware clinical summarization:** LLM calls `fhir.search`/`fhir.read` for Patient/Encounter/Observation and synthesizes output.
2. **Documentation assistant:** Draft a `CarePlan` or `DocumentReference` via `fhir.create` (with confirmation & schema validation).
3. **Terminology interpretation:** Resolve codes via `$lookup`, expand value sets with `$expand`, or map concepts via `$translate`.
4. **Population analytics (future):** Bulk Data `$export` with async polling and controlled destinations.

---

## High‑Level Architecture
```
LLM Client ⇄ MCP Client ⇄ (stdio / HTTP SSE) ⇄ FhirMCP Server
                                     │
                                     ├── Auth (SMART/OAuth2, scopes)
                                     ├── FHIR Provider (REST)
                                     ├── Terminology Provider (HL7 Terminology Service)
                                     ├── Policy Engine (RBAC/ABAC)
                                     ├── PHI Guard (mask/redact)
                                     └── Audit & Telemetry
```

### Components
- **MCP Server (TypeScript):** Exposes tools with JSON Schemas; manages sessions, prompts, and structured results.
- **FHIR Provider:** REST client with `_elements`, `_count`, `_sort`, `_include/_revinclude`, optimistic concurrency (If‑Match).
- **Terminology Provider:** `$expand` (ValueSet), `$lookup` (CodeSystem), `$translate` (ConceptMap); configurable base path.
- **Auth & Token Cache:** Authorization Code + PKCE and Client Credentials; refresh support.
- **Policy Engine:** Enforces scopes, resource/type/operation policies, and prompt‑time constraints (e.g., read‑only modes).
- **PHI Guard:** Field‑level masking/omission strategies; configurable safe/strict modes.
- **Audit & Telemetry:** Structured logs, trace IDs, optional FHIR `AuditEvent` emission.

---

## Repository Layout (proposed)
```
/ (root)
├─ packages/
│  ├─ mcp-fhir-server/          # MCP server (TS)
│  ├─ fhir-provider-rest/       # FHIR client abstraction
│  ├─ terminology-provider/     # HL7 terminology client
│  ├─ policy-engine/            # RBAC/ABAC + scope mapping
│  ├─ phi-guard/                # masking/redaction utilities
│  └─ examples/
│     ├─ claude-client/
│     └─ openai-client/
├─ docs/
│  ├─ QUICKSTART.md
│  ├─ SECURITY.md
│  └─ PROMPTS.md
└─ tests/
   ├─ e2e/
   └─ conformance/
```

---

## MCP Tools (Schemas & Behavior)
> All tools return deterministic JSON objects. Error conditions return MCP‑standard JSON‑RPC errors with `code` and `message`.

### 1) `fhir.capabilities`
- **Input:** `{ baseUrl?: string }`
- **Output:** `{ fhirVersion, formats, resources: Array<{ type, interactions: string[] }>, terminologyOps?: string[] }`
- **Notes:** Summarized `CapabilityStatement`. Heavy fields are omitted unless explicitly requested.

### 2) `fhir.search`
- **Input:**
  ```json
  {
    "resourceType": "Observation",
    "params": { "patient": "<id>", "code": "<system|code>", "date": "ge2024-01-01" },
    "count": 10,
    "sort": "-date",
    "elements": ["id", "code", "effectiveDateTime", "valueQuantity"]
  }
  ```
- **Output:** `{ total?: number, entries: Array<{ id: string, resource: object }>, nextPage?: string }`
- **Notes:** Applies `_elements`, `_count`, `_sort`. Provider may add `_summary=data` for token savings.

### 3) `fhir.read`
- **Input:** `{ resourceType: string, id: string, elements?: string[] }`
- **Output:** `{ resource: object }`
- **Notes:** Uses `_elements` when supported; otherwise post‑filters fields server‑side.

### 4) `fhir.create` (M2/M3)
- **Input:** `{ resourceType: string, resource: object }`
- **Output:** `{ id: string, resource?: object, versionId?: string }`
- **Notes:** Requires write scopes; can enforce explicit user confirmation. Supports Location and ETag headers.

### 5) `fhir.update` (M2/M3)
- **Input:** `{ resourceType: string, id: string, resource: object, ifMatchVersionId?: string }`
- **Output:** `{ id: string, resource?: object, versionId?: string }`

### 6) `fhir.patch` (M2/M3)
- **Input:** `{ resourceType: string, id: string, patch: object|array, contentType: "application/json-patch+json"|"application/fhir+json" }`
- **Output:** `{ id: string, resource?: object, versionId?: string }`

### 7) `fhir.delete` (M3)
- **Input:** `{ resourceType: string, id: string }`
- **Output:** `{ outcome?: object }`

### 8) `terminology.expand`
- **Input:** `{ url?: string, id?: string, filter?: string, count?: number, offset?: number }`
- **Output:** `{ expansion: { total?: number, contains: Array<{ system, code, display }> } }`
- **Notes:** Enforces server‑side limits; strongly recommend `filter` for large sets.

### 9) `terminology.lookup`
- **Input:** `{ system: string, code: string }`
- **Output:** `{ valid?: boolean, display?: string, properties?: Record<string, string|number|boolean> }`

### 10) `terminology.translate`
- **Input:** `{ code: string, system: string, targetSystem?: string, conceptMapUrlOrId?: string }`
- **Output:** `{ result: boolean, match?: { code: string, system: string, display?: string } }`

### 11) `auth.login` / `auth.logout`
- **`auth.login` Input:** `{ flow: "authorization_code"|"client_credentials", clientId?: string, authUrl?: string, tokenUrl?: string, scopes?: string[] }`
- **Output:** `{ accessToken: string, expiresAt?: string, refreshToken?: string }`
- **Notes:** For MVP, tokens can be provided via config; interactive flows added in M2.

---

## HL7 Terminology Integration
- **Endpoints:** `$expand` (ValueSet), `$lookup` (CodeSystem), `$translate` (ConceptMap). Base URL is configurable and may differ from FHIR base.
- **Firely/HAPI nuances:** Support administrative prefix paths and POST with `Parameters` when URIs exceed GET limits.
- **Safeguards:** Hard caps on expansions; require `filter` for very large ValueSets; optional caching for repeated expansions.

---

## Security, Privacy, and Audit
- **SMART on FHIR / OAuth2:** Authorization Code + PKCE and Client Credentials. Scope‑to‑tool mapping (e.g., `patient/*.read` ⇒ hide write tools).
- **Least‑Privilege:** Tools list filtered at `tools/list` time; server‑side enforcement per call.
- **PHI Guard:** Configurable `safe` (mask names, addresses, identifiers, DOB → age) vs `trusted` mode. Never emit government IDs to LLM endpoints by default.
- **User Confirmation:** Elicitation for destructive/write operations and for high‑risk mutations.
- **Audit:** Structured logs with trace IDs; optional FHIR `AuditEvent` emit; redact secrets/PHI from logs.
- **Transport:** stdio for local; HTTPS + TLS for remote HTTP/SSE.

---

## Token‑Efficiency Guidelines
- Prefer `_elements` to restrict fields; add `_summary=data` when full content isn’t needed.
- Use `_sort=-date` + `_count=1` to fetch the most recent clinical fact.
- Filter early: include `code`, `category`, `date`, and `patient` in queries.
- Limit terminology expansions with `filter`, `count`, and pagination.
- Return compact JSON to the LLM; post‑process summaries server‑side when possible.
- Keep tool descriptions short and actionable; push examples to docs.

---

## Prompt Library (Ready‑to‑Use, terse)
> Keep answers concise; only fetch what’s necessary; never disclose PHI beyond policy.

**SYSTEM (attach at session start)**
"""
You can call MCP tools to retrieve FHIR data and HL7 terminology. Follow these rules:
1) Minimize tokens: filter and limit with `_elements`, `_count`, `_sort`, and specific params.
2) Prefer latest facts: for “last” values, request `_sort=-date&_count=1`.
3) Use terminology tools before explaining codes.
4) Do not reveal identifiers or PHI unless explicitly allowed by policy.
5) Ask for confirmation before any write or destructive action.
"""

**TOOL‑USAGE SNIPPETS**
- *Get patient by id*: "Call `fhir.read` with `{ resourceType: "Patient", id, elements: ["id","name","birthDate","gender"] }`. Answer using age rather than full DOB."
- *Find latest HbA1c*: "Call `fhir.search` with `{ resourceType: "Observation", params: { patient: PID, code: "http://loinc.org|4548-4" }, sort: "-date", count: 1, elements: ["id","effectiveDateTime","valueQuantity"] }`."
- *Explain a code*: "Call `terminology.lookup` with `{ system: SYS, code }` and use `display` in the answer."
- *Translate a code*: "Call `terminology.translate` with `{ code, system, targetSystem }` and include the mapped display if present."
- *Expand small ValueSet*: "Call `terminology.expand` with `{ url, filter, count: 20 }`. Never expand huge sets without a filter."
- *Before write*: "Explain the change and ask: ‘Proceed?’ Only then call `fhir.create/update/patch`."

**ANSWER TONES**
- *Clinical fact*: short bullet with value + unit + date.
- *Code meaning*: 1 line: `CODE – Display (System)`.
- *No data*: one sentence: "No matching data found for <criteria>."

---

## Development Plan & Milestones

### MVP (Weeks 1–3)
- MCP server skeleton (TS) with stdio + optional HTTP SSE.
- Tools: `fhir.capabilities`, `fhir.search`, `fhir.read`; `terminology.lookup`.
- Config‑based tokens (bearer) and base URLs.
- PHI Guard (safe defaults) + basic audit.
- E2E tests against HAPI & a public terminology endpoint; docs: QUICKSTART.

### M2 (Weeks 4–6)
- Tools: `terminology.expand`, `terminology.translate`; `fhir.create`, `fhir.update`, `fhir.patch` (behind scopes + confirmation).
- OAuth2 (Authorization Code + PKCE, Client Credentials) + token refresh.
- Policy engine (scope → tool visibility); telemetry (OpenTelemetry), caching for terminology.
- PROMPTS.md with examples; SECURITY.md with PHI policies.

### M3 (Weeks 7–9)
- `fhir.delete` (guarded); Bulk `$export` (async job + status tool).
- Optional FHIR `AuditEvent` emit; consent hooks; rate‑limit/backoff.
- Samples: Claude/OpenAI clients; CI (GitHub Actions), coverage, Docker/Helm.
- Conformance suite across HAPI/Firely; R5 adaptations.

---

## Testing Strategy
- **Unit:** Schema validation (zod/ajv), provider mocks, PHI masking rules.
- **E2E:** Live against HAPI/Firely; golden files for typical flows.
- **Conformance:** Capability checks, OperationOutcome handling, OAuth flows.
- **Security:** Scope denial tests, confirmation gates, log redaction.

---

## License & Community
- **License:** MIT (or Apache‑2.0) – permissive, compatible with MCP SDK and FHIR clients.
- **Community:** GitHub Discussions, good‑first‑issue labels, sample videos, blog post on release. Target inclusion in public MCP connectors lists.

---

## Initial TODO
- [ ] Create public repo; scaffold TS workspace; choose MCP TS SDK.
- [ ] Implement `fhir.capabilities`, `fhir.search`, `fhir.read`, `terminology.lookup`.
- [ ] Add PHI Guard default rules; audit logging.
- [ ] E2E script vs HAPI + terminology server; QUICKSTART and PROMPTS docs.

