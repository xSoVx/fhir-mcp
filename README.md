# FhirMCP - FHIR Model Context Protocol Server

[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

FhirMCP is an open-source MCP (Model Context Protocol) server that enables LLMs to securely interact with FHIR servers and HL7 terminology services. It provides a comprehensive toolset for healthcare interoperability with built-in PHI protection, audit logging, and token-efficient operations.

## ✨ Features

- 🔐 **Secure Access**: SMART on FHIR / OAuth2 support with scope-based authorization
- 🛡️ **PHI Protection**: Configurable masking and redaction of sensitive healthcare data
- 📊 **Comprehensive FHIR Support**: Read, search, create, and update operations
- 🏥 **HL7 Terminology**: ValueSet expansion, CodeSystem lookup, and concept translation
- 📝 **Audit Logging**: Complete audit trail with structured logging and trace IDs
- ⚡ **Token Efficient**: Field selection, pagination, and optimized queries
- 🔧 **Interoperable**: Works with HAPI FHIR, Firely, and other R4/R4B servers
- ✅ **QA Tested**: 100% function coverage with comprehensive security validation
- 🌐 **HTTP Bridge**: Web-accessible REST API for browser-based AI assistants
- 🔒 **ES Module Support**: Modern JavaScript module system compatibility

## 🚀 Quick Start

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Build the project:**
   ```bash
   npm run build
   ```

3. **Configure environment:**
   ```bash
   export FHIR_BASE_URL="https://hapi.fhir.org/baseR4"
   export TERMINOLOGY_BASE_URL="https://tx.fhir.org/r4"
   export PHI_MODE="safe"
   ```

4. **Start the server:**
   ```bash
   cd packages/mcp-fhir-server
   npm start
   ```

5. **Test functionality:**
   ```bash
   node test-basic-functionality.js
   ```

## 🛠️ Available Tools

### FHIR Operations
- `fhir.capabilities` - Get server capability statement
- `fhir.search` - Search resources with advanced filtering
- `fhir.read` - Read specific resources by ID
- `fhir.create` - Create new FHIR resources
- `fhir.update` - Update existing resources

### Terminology Services
- `terminology.lookup` - Look up code properties and display names
- `terminology.expand` - Expand ValueSets to get contained codes
- `terminology.translate` - Translate codes between coding systems

## 📁 Project Structure

```
packages/
├── mcp-fhir-server/     # Main MCP server implementation
│   ├── src/
│   │   ├── providers/   # FHIR and terminology providers
│   │   ├── security/    # PHI guard and audit logging
│   │   ├── tools/       # MCP tool handlers and schemas
│   │   └── types/       # TypeScript definitions
│   └── dist/           # Compiled JavaScript (ES modules)
├── examples/
│   └── http-bridge/    # HTTP REST API bridge for web clients
│
docs/
├── QUICKSTART.md       # Getting started guide
├── PROMPTS.md         # LLM prompt library
├── SECURITY.md        # Security and privacy guide
└── AI_INTEGRATION.md   # AI assistant integration examples

tests/
├── e2e/               # End-to-end tests
└── QA-REPORT.md       # Comprehensive QA test results
```

## 🔒 Security Features

### PHI Protection
- **Safe Mode**: Automatically masks names, addresses, birth dates, and identifiers
- **Trusted Mode**: Returns data as-is for secure environments
- **Configurable**: Custom field masking and removal rules

### Audit & Compliance
- Structured logging with trace IDs for all operations
- PHI-safe audit trails with sensitive data redaction
- Optional FHIR AuditEvent emission for compliance

### Authentication
- SMART on FHIR / OAuth2 Authorization Code + PKCE flow
- Client Credentials flow for server-to-server access
- Scope-based tool visibility and access control

## 📖 Documentation

- **[Quick Start Guide](docs/QUICKSTART.md)** - Installation and basic usage
- **[Prompt Library](docs/PROMPTS.md)** - Ready-to-use LLM prompts and patterns
- **[Security Guide](docs/SECURITY.md)** - Production deployment and security considerations

## 🧪 Testing

Run the test suites:

```bash
# Build the project first
npm run build

# Full QA test suite (comprehensive function testing)
node manual-qa-test.js

# E2E integration tests
node tests/e2e/test-fhir-mcp.js

# Type checking
npm run typecheck

# Linting (with improved type safety)
npm run lint
```

**QA Test Results**: ✅ 19/19 tests passed (100% success rate)
- All core functions validated
- Security features verified
- PHI protection tested
- Audit logging validated
- ES module compatibility confirmed

See [QA-REPORT.md](QA-REPORT.md) for detailed test results.

## 🔧 Configuration

Configure via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `FHIR_BASE_URL` | FHIR server base URL | `https://hapi.fhir.org/baseR4` |
| `FHIR_TOKEN` | Bearer token for FHIR server | - |
| `TERMINOLOGY_BASE_URL` | HL7 terminology service URL | `https://tx.fhir.org/r4` |
| `TERMINOLOGY_TOKEN` | Bearer token for terminology service | - |
| `PHI_MODE` | PHI protection mode (`safe` or `trusted`) | `safe` |
| `ENABLE_AUDIT` | Enable audit logging | `true` |

## 🤖 Using with Claude

Add to your Claude MCP configuration:

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

## 🌐 HTTP Bridge for Web Applications

For browser-based AI assistants that can't use MCP directly:

```bash
# Start the HTTP bridge server
cd packages/examples/http-bridge
npm start
```

The bridge provides REST endpoints at `http://localhost:3001`:
- `GET /health` - Health check
- `GET /tools` - List available tools
- `POST /fhir/capabilities` - FHIR server capabilities
- `POST /fhir/search` - Search FHIR resources
- `POST /fhir/read` - Read FHIR resources
- `POST /terminology/lookup` - Terminology lookup
- `POST /terminology/expand` - ValueSet expansion

## 📋 Roadmap

- [x] **MVP**: Basic FHIR operations and terminology lookup
- [x] **QA**: Comprehensive testing and security validation
- [x] **ES Modules**: Modern JavaScript module support
- [x] **HTTP Bridge**: Web-accessible REST API
- [ ] **M2**: OAuth2 flows, write operations, policy engine
- [ ] **M3**: Delete operations, bulk export, R5 support
- [ ] **Future**: GraphQL support, subscription webhooks

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [HL7 FHIR](https://fhir.hl7.org/) for the interoperability standard
- [Model Context Protocol](https://modelcontextprotocol.io/) for the protocol specification
- [HAPI FHIR](https://hapifhir.io/) for the reference implementation
- [HL7 Terminology Services](https://terminology.hl7.org/) for code system management

---

**Built with ❤️ for healthcare interoperability**