# FHIR-MCP Prompt Library

This guide provides ready-to-use prompts and patterns for working with FHIR-MCP tools effectively.

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
    "elements": ["id", "gender", "age", "maritalStatus"]
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
- Age: {{calculated_age}} years  
- Last Visit: {{encounter.period.start | date}}

**Recent Vitals** ({{observation.effectiveDateTime | date}})
- Blood Pressure: {{systolic}}/{{diastolic}} mmHg
- Heart Rate: {{pulse}} bpm
- Temperature: {{temp}}°F

**Active Conditions**
- {{condition.code.text}} (since {{condition.onsetDateTime | date}})

*Note: Personal identifiers masked for privacy*
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
- Never display full names, addresses, SSNs, or exact birth dates
- Use age instead of birth date when possible
- Reference patients by ID only in subsequent searches
- Redact contact information in summaries

### Audit Awareness
- All tool calls are automatically logged
- Operation metadata is captured (but PHI is redacted)
- Failed operations generate audit events
- Trace IDs link related operations together

## Advanced Patterns

### Batch Patient Analysis
```javascript
// First get patient list
const patients = await fhir.search("Patient", {_count: 10});

// Then get latest vitals for each
for (const patient of patients.entries) {
  const vitals = await fhir.search("Observation", {
    patient: `Patient/${patient.id}`,
    category: "vital-signs",
    sort: "-date", 
    count: 1
  });
}
```

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