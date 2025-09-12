# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-01-12

### Added
- Initial release of FhirMCP server
- Complete MCP server implementation with FHIR and terminology tools
- PHI Guard with configurable masking and redaction (`safe` and `trusted` modes)
- Comprehensive audit logging with structured logs and trace IDs
- Support for HAPI FHIR and HL7 terminology services
- TypeScript implementation with full type safety
- Token-efficient FHIR operations with field selection and pagination
- Complete documentation suite (QUICKSTART.md, PROMPTS.md, README.md)
- Comprehensive testing suite with E2E tests

### Tools Implemented
- `fhir.capabilities` - Get FHIR server capability statement
- `fhir.search` - Search FHIR resources with advanced filtering and pagination
- `fhir.read` - Read specific FHIR resources by ID
- `fhir.create` - Create new FHIR resources (requires write permissions)
- `fhir.update` - Update existing FHIR resources with optimistic concurrency
- `terminology.lookup` - Look up code properties and display names
- `terminology.expand` - Expand ValueSets to get contained codes
- `terminology.translate` - Translate codes between coding systems

### Security Features
- PHI protection with automatic masking of sensitive fields
- Scope-based access control preparation
- Audit trail with PHI-safe logging
- Configurable field masking and removal

### Testing
- Basic functionality tests against public FHIR servers
- Build and type checking validation
- Server startup and MCP protocol verification
- Successfully tested against HAPI FHIR v4.0.1 with 146 available resources

### Documentation
- Comprehensive README with setup and usage instructions
- Quick start guide for immediate deployment
- Prompt library with ready-to-use LLM interaction patterns
- Security and configuration documentation
- MIT license for open-source distribution