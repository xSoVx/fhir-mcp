#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import { FhirProvider } from './providers/fhir-provider.js';
import { TerminologyProvider } from './providers/terminology-provider.js';
import { PhiGuard } from './security/phi-guard.js';
import { AuditLogger } from './security/audit-logger.js';
import { SecurityMiddleware } from './security/security-middleware.js';
import { FhirTools } from './tools/fhir-tools.js';
import { TerminologyTools } from './tools/terminology-tools.js';
import { FhirMcpConfig } from './types/config.js';

class FhirMcpServer {
  private server: Server;
  private config: FhirMcpConfig;
  private fhirProvider: FhirProvider;
  private terminologyProvider: TerminologyProvider;
  private phiGuard: PhiGuard;
  private auditLogger: AuditLogger;
  private securityMiddleware: SecurityMiddleware;
  private fhirTools: FhirTools;
  private terminologyTools: TerminologyTools;

  constructor() {
    // Load configuration (in production, this would come from config files or environment)
    this.config = {
      fhir: {
        baseUrl: process.env.FHIR_BASE_URL || 'https://hapi.fhir.org/baseR4',
        bearerToken: process.env.FHIR_TOKEN
      },
      terminology: {
        baseUrl: process.env.TERMINOLOGY_BASE_URL || 'https://tx.fhir.org/r4',
        bearerToken: process.env.TERMINOLOGY_TOKEN
      },
      security: {
        phiMode: (process.env.PHI_MODE as 'safe' | 'trusted') || 'safe',
        enableAudit: process.env.ENABLE_AUDIT !== 'false'
      }
    };

    // Initialize providers and security components
    this.fhirProvider = new FhirProvider(this.config.fhir.baseUrl, this.config.fhir.bearerToken);
    this.terminologyProvider = new TerminologyProvider(
      this.config.terminology.baseUrl, 
      this.config.terminology.bearerToken
    );
    
    this.auditLogger = new AuditLogger(this.config.security.enableAudit);
    
    this.phiGuard = new PhiGuard({
      mode: this.config.security.phiMode,
      maskFields: [],
      removeFields: []
    }, this.auditLogger);

    // Initialize enhanced security middleware
    this.securityMiddleware = new SecurityMiddleware({
      enableInputValidation: true,
      enableRateLimiting: true,
      enableSecurityHeaders: true,
      enableAuditLogging: this.config.security.enableAudit,
      healthcareCompliant: true,
      rateLimitOverrides: {
        'phi_strict': {
          windowMs: 60 * 1000,
          maxRequests: this.config.security.phiMode === 'safe' ? 10 : 50,
          keyGenerator: (req: any) => `phi_strict:${req.userId || req.sessionId}`
        }
      }
    }, this.auditLogger);

    // Initialize tool handlers with enhanced security
    this.fhirTools = new FhirTools(
      this.fhirProvider, 
      this.phiGuard, 
      this.auditLogger,
      this.securityMiddleware
    );
    this.terminologyTools = new TerminologyTools(this.terminologyProvider, this.auditLogger);

    // Initialize MCP server
    this.server = new Server(
      {
        name: 'fhir-mcp',
        version: '0.1.0'
      },
      {
        capabilities: {
          tools: {}
        }
      }
    );

    this.setupHandlers();
  }

  private setupHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          this.fhirTools.getCapabilitiesTool(),
          this.fhirTools.getSearchTool(),
          this.fhirTools.getReadTool(),
          this.fhirTools.getCreateTool(),
          this.fhirTools.getUpdateTool(),
          this.terminologyTools.getExpandTool(),
          this.terminologyTools.getLookupTool(),
          this.terminologyTools.getTranslateTool()
        ]
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'fhir.capabilities':
            return await this.fhirTools.handleCapabilities(args);
          case 'fhir.search':
            return await this.fhirTools.handleSearch(args);
          case 'fhir.read':
            return await this.fhirTools.handleRead(args);
          case 'fhir.create':
            return await this.fhirTools.handleCreate(args);
          case 'fhir.update':
            return await this.fhirTools.handleUpdate(args);
          case 'terminology.expand':
            return await this.terminologyTools.handleExpand(args);
          case 'terminology.lookup':
            return await this.terminologyTools.handleLookup(args);
          case 'terminology.translate':
            return await this.terminologyTools.handleTranslate(args);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        this.auditLogger.log({
          operation: name,
          success: false,
          error: errorMessage
        });
        
        throw error;
      }
    });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    
    // Log server startup with security information
    console.error('🔒 FHIR-MCP server started with enhanced security');
    console.error(`📍 FHIR Base URL: ${this.config.fhir.baseUrl}`);
    console.error(`📚 Terminology Base URL: ${this.config.terminology.baseUrl}`);
    console.error(`🛡️ PHI Protection Mode: ${this.config.security.phiMode}`);
    console.error(`📋 Audit Logging: ${this.config.security.enableAudit ? 'ENABLED' : 'DISABLED'}`);
    
    // Log security features status
    const securityStats = this.securityMiddleware.getStats();
    console.error('🔐 Security Features:');
    console.error(`   • Input Validation: ENABLED`);
    console.error(`   • Rate Limiting: ENABLED`);
    console.error(`   • Security Headers: ENABLED`);
    console.error(`   • Healthcare Compliance: ENABLED`);
    console.error(`   • PHI Authorization: ENABLED`);
    console.error(`   • Compliance Level: ${securityStats.securityHeaders.complianceLevel.toUpperCase()}`);
    
    // Log initial security audit
    await this.auditLogger.log({
      operation: 'server.startup',
      success: true,
      metadata: {
        phiMode: this.config.security.phiMode,
        auditEnabled: this.config.security.enableAudit,
        securityFeaturesEnabled: {
          inputValidation: true,
          rateLimiting: true,
          securityHeaders: true,
          healthcareCompliant: true,
          phiAuthorization: true
        },
        timestamp: new Date().toISOString(),
        version: '0.1.0'
      }
    });
  }
}

// Start the server
const server = new FhirMcpServer();
server.run().catch(console.error);