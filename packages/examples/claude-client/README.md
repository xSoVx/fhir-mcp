# Claude Integration with FhirMCP

This directory contains configuration and examples for using FhirMCP with Claude Desktop.

## Quick Setup

1. **Copy Configuration**:
   
  **macOS**: 
   ```bash
   cp claude-config.json ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```
   
  **Windows**:
   ```bash
   copy claude-config.json %APPDATA%\Claude\claude_desktop_config.json
   ```

2. **Update Path**: Edit the config file to use your actual path to FhirMCP

3. **Restart Claude Desktop**

## Configuration Details

The `claude-config.json` configures Claude to:

- Connect to your local FhirMCP server
- Use PHI-safe mode for data protection  
- Enable audit logging
- Connect to HAPI FHIR and HL7 terminology services

## Example Prompts

Once configured, you can ask Claude:

### Patient Data Analysis
```
"Search for patients named 'Johnson' and analyze their demographics"
```

### Clinical Code Lookup
```
"What does LOINC code 29463-7 represent?"
```

### Latest Lab Results
```
"Find the most recent laboratory observations for patient ID 1234567 from the last 30 days"
```

### Terminology Exploration
```
"Expand the administrative-gender value set and show me the available codes"
```

## Before this returns any patient data

**Set a caller principal.** Without `MCP_SERVICE_PRINCIPAL_ID` and `MCP_SERVICE_PRINCIPAL_SCOPES`, every IDENTIFIABLE read is denied with `HEALTHCARE_COMPLIANCE_VIOLATION` and no resource body comes back. Add both to `claude-config.json` alongside `PHI_MODE`. Run `npm run build` first as well — the config points at `dist/`, which is gitignored.

## What masking does

In `safe` mode, on an IDENTIFIABLE resource:

- `name` is replaced with `***`; `address`, `telecom` and `contact` are removed
- `birthDate` is **removed**. There is no age field and no partial date — do not ask Claude to compute an age
- `identifier` and `id` become per-process `PT_` pseudonym tokens. They are **not** stable across server restarts, so do not store them as patient keys
- every operation is logged, including denied reads

Known gap: free text on Condition, MedicationRequest, Procedure, CarePlan and DiagnosticReport is **not** masked and can carry a patient name into the conversation. See [SECURITY.md](../../../docs/SECURITY.md#known-open-security-issues).

## Advanced Usage

### Clinical Decision Support
```
"Based on this patient's latest HbA1c and glucose levels, provide clinical insights for diabetes management"
```

### Population Health
```
"Search for all patients with diabetes-related conditions and summarize the demographics"
```

### Code System Analysis
```
"Compare LOINC codes for different types of blood pressure measurements"
```

Claude speaks MCP natively, so this integration needs no bridge process. It is not a compliance control on its own — read [SECURITY.md](../../../docs/SECURITY.md) before pointing it at real patient data.