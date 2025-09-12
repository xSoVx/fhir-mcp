# Claude Integration with FhirMCP

This directory contains configuration and examples for using FhirMCP with Claude Desktop.

## 🚀 Quick Setup

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

## 🔧 Configuration Details

The `claude-config.json` configures Claude to:
- Connect to your local FhirMCP server
- Use PHI-safe mode for data protection  
- Enable audit logging
- Connect to HAPI FHIR and HL7 terminology services

## 💬 Example Prompts

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

## 🛡️ Privacy Features

Claude with FhirMCP automatically:
- Masks patient names, addresses, and SSNs
- Converts birth dates to ages
- Removes government identifiers
- Logs all operations with audit trails

## 📊 Advanced Usage

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

This integration provides the most seamless experience for healthcare AI assistance with full FHIR compliance and PHI protection.