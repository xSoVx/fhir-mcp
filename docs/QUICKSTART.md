# FHIR-MCP Quick Start Guide

FHIR-MCP is an MCP (Model Context Protocol) server that enables LLMs to securely access FHIR servers and HL7 terminology services with built-in PHI protection and audit logging.

## Prerequisites

- Node.js 18 or later
- npm or yarn package manager

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/fhir-mcp.git
cd fhir-mcp
```

2. Install dependencies:
```bash
npm install
```

3. Build the project:
```bash
npm run build
```

## Configuration

Configure the server using environment variables:

```bash
# FHIR Server Configuration
export FHIR_BASE_URL="https://hapi.fhir.org/baseR4"
export FHIR_TOKEN="your-bearer-token-here"  # Optional

# Terminology Server Configuration  
export TERMINOLOGY_BASE_URL="https://tx.fhir.org/r4"
export TERMINOLOGY_TOKEN="your-terminology-token"  # Optional

# Security Configuration
export PHI_MODE="safe"  # or "trusted"
export ENABLE_AUDIT="true"
```

## Running the Server

Start the MCP server:
```bash
cd packages/mcp-fhir-server
npm start
```

The server will start in stdio mode and is ready to accept MCP requests.

## Available Tools

### FHIR Operations

- **`fhir.capabilities`** - Get server capability statement
- **`fhir.search`** - Search FHIR resources with parameters
- **`fhir.read`** - Read specific resource by ID
- **`fhir.create`** - Create new FHIR resource (write permission required)
- **`fhir.update`** - Update existing resource (write permission required)

### Terminology Operations

- **`terminology.lookup`** - Look up code properties and display
- **`terminology.expand`** - Expand ValueSet to get contained codes
- **`terminology.translate`** - Translate codes between systems

## Quick Examples

### Search for Patients
```json
{
  "name": "fhir.search",
  "arguments": {
    "resourceType": "Patient",
    "params": {
      "name": "John",
      "_count": "5"
    },
    "elements": ["id", "name", "gender", "birthDate"]
  }
}
```

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

### Look Up a LOINC Code
```json
{
  "name": "terminology.lookup",
  "arguments": {
    "system": "http://loinc.org",
    "code": "29463-7"
  }
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

## Security Features

### PHI Protection
- **Safe Mode** (default): Automatically masks names, addresses, birth dates, SSNs, and other PII
- **Trusted Mode**: Returns data as-is (use only in secure environments)

### Audit Logging
All operations are logged with:
- Timestamp and unique trace ID
- Operation type and parameters
- Success/failure status
- Redacted metadata (no PHI in logs)

## Testing

Run the E2E test suite:
```bash
node tests/e2e/test-fhir-mcp.js
```

This tests against public HAPI FHIR and HL7 terminology servers.

## Using with Claude

Add to your Claude configuration:
```json
{
  "mcpServers": {
    "fhir": {
      "command": "node",
      "args": ["path/to/fhir-mcp/packages/mcp-fhir-server/dist/index.js"],
      "env": {
        "FHIR_BASE_URL": "https://your-fhir-server.com/fhir",
        "PHI_MODE": "safe"
      }
    }
  }
}
```

## Token Efficiency Tips

1. **Use field selection**: Always specify `elements` parameter to limit returned fields
2. **Filter early**: Include specific search parameters like `patient`, `code`, `date`  
3. **Sort and limit**: Use `sort` with `count` to get most relevant results first
4. **Batch operations**: Combine multiple searches when possible

## Troubleshooting

### Common Issues

**Connection errors**: Verify FHIR_BASE_URL is accessible and correct
**Auth errors**: Check bearer token configuration and permissions
**Timeout errors**: Some FHIR servers may be slow; consider smaller result sets
**Schema errors**: Verify request format matches tool schemas

### Debug Mode
Enable verbose logging:
```bash
export DEBUG="fhir-mcp:*"
npm start
```

## Next Steps

- Review the [Prompt Library](PROMPTS.md) for LLM usage patterns
- See [Security Guide](SECURITY.md) for production deployment
- Check examples in `packages/examples/` for client implementations