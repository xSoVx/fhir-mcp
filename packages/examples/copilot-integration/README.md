# GitHub Copilot Integration for FhirMCP

This example shows how to integrate GitHub Copilot with FhirMCP for AI-assisted healthcare development.

## 🚀 Setup

1. **Start the HTTP Bridge**:
   ```bash
   cd packages/examples/http-bridge
   npm install
   npm run build
   npm start
   ```

2. **Include the Copilot Helper**:
   ```javascript
   // In your project
   const { searchPatients, getPatient, lookupCode } = require('./copilot-fhir.js');
   ```

3. **Configure VS Code** (optional):
   Add to your `.vscode/settings.json`:
   ```json
   {
     "github.copilot.enable": {
       "*": true,
       "javascript": true,
       "typescript": true
     }
   }
   ```

## 💡 How It Works

The `copilot-fhir.js` file provides Copilot-friendly functions with:
- Clear JSDoc documentation
- Common parameter patterns  
- Example usage in comments
- Descriptive function names

When you start typing healthcare-related code, Copilot will suggest these functions.

## 📝 Usage Examples

### Patient Search
```javascript
// Copilot will suggest this when you type "search patient"
const patients = await searchPatients({ name: "John", gender: "male" });

// Or when you type "get patient by id"
const patient = await getPatient("Patient/123");
```

### Clinical Data
```javascript
// Type "get latest vitals" and Copilot suggests:
const vitals = await getLatestVitals("Patient/123");

// Type "search lab results" and get:
const labs = await getLatestLabResults("Patient/123", "ge2024-01-01");
```

### Code Lookups
```javascript
// Type "lookup LOINC code" and Copilot suggests:
const codeInfo = await lookupCode("http://loinc.org", "29463-7");
console.log(`Weight measurement: ${codeInfo.display}`);

// Use common codes:
const bp = await searchObservations("123", {
    code: COMMON_LOINC_CODES.BLOOD_PRESSURE,
    _sort: "-date",
    _count: 1
});
```

## 🎯 Copilot Training Tips

1. **Add Context Comments**:
   ```javascript
   // Get patient demographics for clinical summary
   const patient = await getPatient(patientId);
   ```

2. **Use Descriptive Variable Names**:
   ```javascript
   const latestBloodPressure = await searchObservations(patientId, {
       code: COMMON_LOINC_CODES.BLOOD_PRESSURE
   });
   ```

3. **Include Domain Context**:
   ```javascript
   // Clinical decision support: Check HbA1c levels for diabetes management
   const hba1cResults = await searchObservations(patientId, {
       code: COMMON_LOINC_CODES.HEMOGLOBIN_A1C,
       _sort: "-date"
   });
   ```

## 🔧 Advanced Integration

### Custom Copilot Completions

Add this to your workspace for better Copilot suggestions:

```javascript
/**
 * @copilot-context FHIR Healthcare Development
 * 
 * This project uses FHIR R4 standard for healthcare interoperability.
 * Available through FhirMCP server with PHI protection.
 * 
 * Common patterns:
 * - Patient search: searchPatients({ name, gender, birthdate })
 * - Observations: searchObservations(patientId, { category, code, date })
 * - Code lookup: lookupCode(system, code)
 * 
 * LOINC codes for vitals: blood pressure (85354-9), weight (29463-7)
 * Categories: vital-signs, laboratory, procedure, survey
 */
```

### VS Code Snippets

Add to `.vscode/fhir.code-snippets`:

```json
{
  "FHIR Patient Search": {
    "scope": "javascript,typescript",
    "prefix": "fhir-search-patient",
    "body": [
      "const patients = await searchPatients({",
      "  name: \"${1:search-term}\",",
      "  gender: \"${2|male,female,other,unknown|}\"",
      "});",
      "",
      "for (const entry of patients.entries) {",
      "  console.log(`Patient: ${entry.resource.id} - ${entry.resource.name?.[0]?.family}`);",
      "}"
    ],
    "description": "Search for FHIR patients"
  },
  "FHIR Code Lookup": {
    "scope": "javascript,typescript", 
    "prefix": "fhir-lookup-code",
    "body": [
      "const codeInfo = await lookupCode(\"${1|http://loinc.org,http://snomed.info/sct|}\", \"${2:code}\");",
      "console.log(`Code meaning: ${codeInfo.display}`);"
    ],
    "description": "Look up clinical code meaning"
  }
}
```

## 🔍 Debugging

If Copilot isn't suggesting FHIR functions:

1. **Check HTTP Bridge**: Ensure it's running on port 3001
2. **Add More Context**: Include more healthcare-related comments
3. **Use Consistent Naming**: Stick to medical terminology
4. **Include Examples**: Add more example usage in comments

## 🛡️ Security Notes

- All data is automatically PHI-masked by FhirMCP
- Use `PHI_MODE=safe` for production
- HTTP bridge should use HTTPS in production
- Consider rate limiting for production deployments

## 📊 Monitoring Usage

The HTTP bridge logs all requests. Monitor for:
- Response times
- Error rates  
- Usage patterns
- Security events

This integration makes healthcare development with Copilot much more intuitive and productive!