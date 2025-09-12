# FHIR-MCP - FHIR Model Context Protocol Server

[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

FHIR-MCP is an open-source MCP (Model Context Protocol) server that enables LLMs to securely interact with FHIR servers and HL7 terminology services. It provides a comprehensive toolset for healthcare interoperability with enterprise-grade security hardening, PHI protection, audit logging, and token-efficient operations.

## ✨ Features

- 🔐 **Enterprise Security**: OWASP-compliant hardening with multi-tier rate limiting
- 🛡️ **PHI Protection**: Advanced masking, classification, and redaction of sensitive healthcare data
- 📊 **Comprehensive FHIR Support**: Read, search, create, and update operations
- 🏥 **HL7 Terminology**: ValueSet expansion, CodeSystem lookup, and concept translation
- 📝 **Audit Logging**: HIPAA-compliant audit trail with structured logging and trace IDs
- ⚡ **Token Efficient**: Field selection, pagination, and optimized queries
- 🔧 **Interoperable**: Works with HAPI FHIR, Firely, and other R4/R4B servers
- ✅ **Production Ready**: Security hardening Phase 1 complete with comprehensive validation
- 🌐 **HTTP Bridge**: Secure REST API with Docker containerization support
- 🔒 **Modern Architecture**: ES modules, TypeScript, and cloud-native deployment

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

## 🔒 Security Features (Phase 1 Complete)

### Enterprise Security Hardening
- **OWASP Compliance**: Complete security headers and content security policies
- **Multi-Tier Rate Limiting**: PHI-aware rate limiting with progressive delays
- **Input Validation**: Comprehensive Joi-based validation with SQL injection prevention
- **Request Monitoring**: Suspicious activity detection with automated IP blocking
- **Emergency Access**: Break-glass mechanisms for critical healthcare scenarios

### PHI Protection & Classification
- **Advanced PHI Engine**: ML-powered classification of sensitive healthcare data
- **Safe Mode**: Automatically masks names, addresses, birth dates, and identifiers
- **Trusted Mode**: Returns data as-is for secure environments  
- **Dynamic Masking**: Context-aware redaction based on PHI sensitivity levels
- **Authorization Engine**: Role-based access control with healthcare-specific permissions

### Audit & HIPAA Compliance
- **Comprehensive Audit Trail**: Structured logging with trace IDs for all operations
- **PHI-Safe Logging**: Automatic redaction of sensitive data in audit logs
- **FHIR AuditEvent Support**: Standards-compliant audit event emission
- **Security Monitoring**: Real-time threat detection and response
- **Compliance Reporting**: Automated generation of security and access reports

### Authentication & Authorization
- **SMART on FHIR / OAuth2**: Authorization Code + PKCE flow support
- **Client Credentials**: Server-to-server access with scope validation
- **Emergency Override**: Break-glass access for critical patient care situations
- **Session Management**: Secure token handling with automatic expiration

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

Add FHIR-MCP to your Claude MCP configuration:

```json
{
  "mcpServers": {
    "fhir": {
      "command": "node",
      "args": ["path/to/FHIR-MCP/packages/mcp-fhir-server/dist/index.js"],
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

### Local Development
```bash
# Start the HTTP bridge server
cd packages/examples/http-bridge
npm start
```

### Docker Deployment (Recommended)
```bash
# Build and start with Docker Compose
docker-compose up --build

# Or run individual commands
docker build -t fhir-mcp .
docker run -p 3002:3001 -e FHIR_BASE_URL="https://hapi.fhir.org/baseR4" fhir-mcp
```

The bridge provides secure REST endpoints at `http://localhost:3002`:
- `GET /health` - Health check with security status
- `GET /tools` - List available tools
- `POST /fhir/capabilities` - FHIR server capabilities
- `POST /fhir/search` - Search FHIR resources  
- `POST /fhir/read` - Read FHIR resources
- `POST /fhir/create` - Create FHIR resources (write operations)
- `POST /fhir/update` - Update FHIR resources (write operations)
- `POST /terminology/lookup` - Terminology lookup
- `POST /terminology/expand` - ValueSet expansion

### Security Features Active
- ✅ OWASP security headers
- ✅ Multi-tier rate limiting
- ✅ Input validation & sanitization
- ✅ PHI-aware authorization
- ✅ Comprehensive audit logging
- ✅ Emergency access controls

## 📋 Roadmap

- [x] **MVP**: Basic FHIR operations and terminology lookup
- [x] **QA**: Comprehensive testing and security validation  
- [x] **ES Modules**: Modern JavaScript module support
- [x] **HTTP Bridge**: Web-accessible REST API
- [x] **Phase 1 Security**: Enterprise hardening with PHI protection
- [x] **Docker**: Containerized deployment with security hardening
- [ ] **Phase 2**: OAuth2 flows, advanced policy engine
- [ ] **Phase 3**: Delete operations, bulk export, R5 support
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

**FHIR-MCP: Built with ❤️ for healthcare interoperability**