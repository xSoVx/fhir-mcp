# FHIR-MCP Prompt Library

This guide provides ready-to-use prompts and patterns for working with FHIR-MCP tools effectively.

> **Before you use these prompts, four behaviours will change what comes back.**
>
> 1. **Identity is required.** Without `MCP_SERVICE_PRINCIPAL_ID` configured, every IDENTIFIABLE read returns `HEALTHCARE_COMPLIANCE_VIOLATION` and no resource body. None of the patterns below will return data. See [QUICKSTART.md](QUICKSTART.md#identity-is-required-for-phi).
> 2. **Identifiers come back as `PT_` tokens**, not values — and those tokens change on every server restart. A prompt that asks the model to remember or correlate an id across sessions will silently correlate the wrong things.
> 3. **`birthDate` is removed, not partially masked.** There is no age to compute and no partial date to parse; ask for neither.
> 4. **Free text is masked globally.** `note[]`, `code.text`, `description` and related elements were previously unmasked on Condition, MedicationRequest, Procedure, CarePlan and DiagnosticReport; they are now covered by a global rule set. See [SECURITY.md](SECURITY.md#2-free-text-unmasked-on-several-clinical-resource-types).

## System Prompt

Add this to your LLM system prompt:

```
You can access FHIR data and HL7 terminology through FhirMCP tools. Follow these guidelines:

1. **Token Efficiency**: Always use `elements` parameter to limit fields. Use `count` and `sort` for focused results.
2. **Latest Data**: For "most recent" queries, use `sort: "-date"` with `count: 1`.  
3. **Terminology First**: Look up codes with `terminology.lookup` before explaining clinical meanings.
4. **PHI Awareness**: Never reveal identifiers, full names, addresses, or birth dates unless explicitly permitted.
5. **Confirmation**: Ask for user confirmation before any write operations (create/update).
6. **Error Handling**: If searches return no results, suggest alternative search parameters.
```

## Common Usage Patterns

### Patient Information

**Get patient demographics (safe)**:
```json
{
  "name": "fhir.read",
  "arguments": {
    "resourceType": "Patient",
    "id": "{{patient_id}}",
    "elements": ["id", "gender", "maritalStatus"]
  }
}
```

**Search patients by name**:
```json
{
  "name": "fhir.search", 
  "arguments": {
    "resourceType": "Patient",
    "params": {
      "name": "{{partial_name}}",
      "_count": "5"
    },
    "elements": ["id", "name", "gender", "birthDate"]
  }
}
```

### Clinical Data Queries

**Latest vital signs**:
```json
{
  "name": "fhir.search",
  "arguments": {
    "resourceType": "Observation", 
    "params": {
      "patient": "Patient/{{id}}",
      "category": "vital-signs"
    },
    "sort": "-date",
    "count": 5,
    "elements": ["id", "code", "effectiveDateTime", "valueQuantity", "component"]
  }
}
```

**Most recent lab results**:
```json
{
  "name": "fhir.search",
  "arguments": {
    "resourceType": "Observation",
    "params": {
      "patient": "Patient/{{id}}",
      "category": "laboratory", 
      "date": "ge2024-01-01"
    },
    "sort": "-date",
    "count": 10,
    "elements": ["id", "code", "effectiveDateTime", "valueQuantity", "interpretation"]
  }
}
```

**Active medications**:
```json
{
  "name": "fhir.search",
  "arguments": {
    "resourceType": "MedicationRequest",
    "params": {
      "patient": "Patient/{{id}}",
      "status": "active"
    },
    "elements": ["id", "medicationCodeableConcept", "dosageInstruction", "authoredOn"]
  }
}
```

**Current conditions**:
```json
{
  "name": "fhir.search",
  "arguments": {
    "resourceType": "Condition",
    "params": {
      "patient": "Patient/{{id}}",
      "clinical-status": "active"
    },
    "elements": ["id", "code", "onsetDateTime", "clinicalStatus"]
  }
}
```

### Specific Clinical Searches

**Blood pressure readings**:
```json
{
  "name": "fhir.search",
  "arguments": {
    "resourceType": "Observation",
    "params": {
      "patient": "Patient/{{id}}",
      "code": "http://loinc.org|85354-9"
    },
    "sort": "-date",
    "count": 3,
    "elements": ["id", "effectiveDateTime", "component"]
  }
}
```

**HbA1c results**:
```json
{
  "name": "fhir.search",
  "arguments": {
    "resourceType": "Observation", 
    "params": {
      "patient": "Patient/{{id}}",
      "code": "http://loinc.org|4548-4"
    },
    "sort": "-date",
    "count": 1,
    "elements": ["id", "effectiveDateTime", "valueQuantity"]
  }
}
```

### Terminology Operations

**Explain a clinical code**:
```json
{
  "name": "terminology.lookup",
  "arguments": {
    "system": "http://snomed.info/sct",
    "code": "73211009"
  }
}
```

**Find gender codes**:
```json
{
  "name": "terminology.expand",
  "arguments": {
    "url": "http://hl7.org/fhir/ValueSet/administrative-gender",
    "count": 10
  }
}
```

**Translate ICD-10 to SNOMED**:
```json
{
  "name": "terminology.translate",
  "arguments": {
    "code": "E11.9",
    "system": "http://hl7.org/fhir/sid/icd-10-cm",
    "targetSystem": "http://snomed.info/sct"
  }
}
```

## Response Templates

### Clinical Summary Template
```
**Patient Summary** (Safe Mode - PHI Protected)
- Gender: {{gender}}
- Last Visit: {{encounter.period.start | date}}

**Recent Vitals** ({{observation.effectiveDateTime | date}})
- Blood Pressure: {{systolic}}/{{diastolic}} mmHg
- Heart Rate: {{pulse}} bpm
- Temperature: {{temp}}°F

**Active Conditions**
- {{condition.code.text}}

*Note: identifiers and ids replaced with per-process `PT_` pseudonym tokens; name masked; birthDate, telecom and address removed. Tokens are NOT stable across server restarts.*

There is no age field: `birthDate` is removed, so nothing downstream can derive one. `condition.code.text` is not masked (open issue 2) and can contain a patient name — review it before rendering it into a summary.
```

### Code Explanation Template
```
**Code Lookup Result**
{{code}} – {{display}} ({{system}})

{{#if properties}}
**Properties:**
{{#each properties}}
- {{@key}}: {{this}}
{{/each}}
{{/if}}
```

### Error Response Template
```
**Search Results**
No {{resourceType}} records found matching: {{search_criteria}}

**Suggestions:**
- Try broader search parameters
- Check date ranges (use format: ge2024-01-01)
- Verify patient ID is correct
- Consider different resource types
```

## LLM Prompt Recipes

### Clinical Decision Support
```
"Based on this patient's latest lab results and vital signs, provide a brief clinical assessment. First search for recent observations, then look up any abnormal codes you find."
```

### Medication Review
```
"Review this patient's current medications. Search for active MedicationRequests, look up any codes you don't recognize, and check for potential interactions or concerns."
```

### Care Gap Analysis  
```
"Analyze this patient's preventive care status. Search for recent observations related to diabetes management (HbA1c, glucose), and check if overdue for any routine screenings."
```

### Documentation Assistant
```
"Help me document this patient encounter. First read the patient demographics, then search for any relevant recent results or conditions I should reference."
```

## Best Practices

### Token Optimization

- **Always specify elements**: `["id", "code", "effectiveDateTime", "valueQuantity"]`
- **Use filters early**: Include `patient`, `date`, `category`, `status` in initial search
- **Limit results**: Default `count: 5-10` for exploratory searches
- **Sort strategically**: `-date` for latest, `-_lastUpdated` for most recent changes

### Error Handling

- Check for empty search results and suggest alternatives
- Handle network timeouts gracefully with retry suggestions  
- Validate date formats before searches
- Provide helpful error messages for schema validation failures

### PHI Protection

In `safe` mode the server has already applied these before the model sees anything — these guidelines are about not undoing that.

- Never display full names, addresses or contact details; in `safe` mode they arrive as `***` or absent already
- **Do not ask for or compute an age.** `birthDate` is removed outright, so there is nothing to derive one from
- Reference patients by the returned `PT_` token only. **Do not treat a token as a durable identifier** — it is per-process and changes on restart, so carrying one across sessions correlates the wrong patient
- **Treat free text from Condition, MedicationRequest, Procedure, CarePlan and DiagnosticReport as unmasked.** `note[]`, `code.text`, `dosageInstruction[].text`, `report[].display`, `description` and `presentedForm[].title` are not covered by the masking rules (open issue 2), so a name or ID can arrive in them intact. Observation and Encounter are clean.
- `DocumentReference` cannot be read or searched at all — it is missing from the validator's resource-type allowlist

### Audit Awareness

- All tool calls are logged, including **denied** reads
- Metadata passes a structural allowlist, so unanticipated keys are dropped rather than logged
- Failed operations generate audit events; the error **class** is recorded, never the message
- Trace IDs link related operations together
- Records go to stderr by default (stdout is the MCP protocol channel)
- **Note:** the `resourceIdHash` field is a keyed HMAC-SHA256 (`AH_` prefix). Audit records still describe PHI access, so retain them accordingly.

## Advanced Patterns

### Batch Patient Analysis

Ask the FHIR server for the join, in one search, and let masking tokenize the result as a unit:

```javascript
// One search. _revinclude makes the server attach each patient's Observations
// to the same Bundle, so no client-side id is ever fed back into a query.
const bundle = await fhir.search("Patient", {
  _count: 10,
  _revinclude: "Observation:patient"
});

// Within one Bundle the same patient carries the same PT_ token on
// Patient.id and on Observation.subject.reference, so the join survives masking.
const byPatient = new Map();
for (const entry of bundle.entries) {
  const r = entry.resource;
  if (r.resourceType === "Patient") continue;
  const token = r.subject?.reference;          // "Patient/PT_..."
  if (!token) continue;
  if (!byPatient.has(token)) byPatient.set(token, []);
  byPatient.get(token).push(r);
}
```

Do **not** loop over a masked result and feed `patient.id` back into a second search. In `safe` mode that field is a `PT_` pseudonym token, not the server-side id, so `Patient/PT_...` does not resolve upstream. Chaining needs the real id, which masking exists to withhold.

`_revinclude` support depends on your FHIR server; the MCP server passes search parameters through without inspecting them. If yours does not support it, run chained retrieval before masking on a trusted path instead.

### Longitudinal Data Analysis
```javascript
// Get trend data over time
const hba1c_trend = await fhir.search("Observation", {
  patient: "Patient/123",
  code: "http://loinc.org|4548-4",
  date: "ge2023-01-01",
  sort: "date"  // chronological order
});
```

### Terminology-Driven Search
```javascript
// First expand a value set to get codes
const codes = await terminology.expand({
  url: "http://hl7.org/fhir/ValueSet/observation-vitalsignresult"
});

// Then search using those codes
const vitals = await fhir.search("Observation", {
  patient: "Patient/123",
  code: codes.expansion.contains.map(c => `${c.system}|${c.code}`).join(",")
});
```

This prompt library should be customized based on your specific FHIR server capabilities and clinical workflows.
