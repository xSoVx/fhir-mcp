#!/usr/bin/env node
import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { URL } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import { FhirProvider } from './providers/fhir-provider.js';
import { TerminologyProvider } from './providers/terminology-provider.js';
import { PhiGuard, parsePhiGuardMode } from './security/phi-guard.js';
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
  private authToken?: string;

  constructor() {
    // Load configuration
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
        // Parsed, not cast. An unchecked cast let PHI_MODE='Safe' (or any typo,
        // or an env var set to '') resolve to a weaker engine mode at runtime.
        // parsePhiGuardMode throws instead, so the process fails at startup.
        phiMode: parsePhiGuardMode(process.env.PHI_MODE ?? 'safe', 'process.env.PHI_MODE'),
        enableAudit: process.env.ENABLE_AUDIT !== 'false'
      }
    };

    // Optional authentication token for HTTP mode
    this.authToken = process.env.AUTH_TOKEN;

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

  private authenticate(req: IncomingMessage): boolean {
    if (!this.authToken) {
      return true; // No auth required
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return false;
    }

    const token = authHeader.substring(7);
    return token === this.authToken;
  }

  private sendUnauthorized(res: ServerResponse) {
    res.writeHead(401, { 'Content-Type': 'text/plain' });
    res.end('Unauthorized');
  }

  async runHttp() {
    const port = parseInt(process.env.PORT || '8080', 10);
    const sessions = new Map<string, SSEServerTransport>();

    const httpServer = createServer(async (req, res) => {
      if (req.method === 'GET' && req.url === '/healthz') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
        return;
      }

      if (!this.authenticate(req)) {
        this.sendUnauthorized(res);
        return;
      }

      if (req.method === 'GET' && req.url?.startsWith('/sse')) {
        const transport = new SSEServerTransport('/mcp', res);
        sessions.set(transport.sessionId, transport);
        
        transport.onclose = () => {
          sessions.delete(transport.sessionId);
        };

        await transport.start();
        await this.server.connect(transport);
        return;
      }

      if (req.method === 'POST' && req.url?.startsWith('/mcp')) {
        const url = new URL(req.url, `http://${req.headers.host}`);
        const sessionId = url.searchParams.get('sessionId');
        
        if (!sessionId || !sessions.has(sessionId)) {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('Bad Request: Invalid session');
          return;
        }

        const transport = sessions.get(sessionId)!;
        await transport.handlePostMessage(req, res);
        return;
      }

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    });

    httpServer.listen(port, '0.0.0.0', () => {
      console.error(`🌐 FHIR-MCP HTTP server started on port ${port}`);
      console.error(`📍 FHIR Base URL: ${this.config.fhir.baseUrl}`);
      console.error(`📚 Terminology Base URL: ${this.config.terminology.baseUrl}`);
      console.error(`🛡️ PHI Protection Mode: ${this.config.security.phiMode}`);
      console.error(`📋 Audit Logging: ${this.config.security.enableAudit ? 'ENABLED' : 'DISABLED'}`);
      console.error(`🔐 Authentication: ${this.authToken ? 'ENABLED' : 'DISABLED'}`);
      console.error(`🔗 SSE Endpoint: http://0.0.0.0:${port}/sse`);
      console.error(`📡 MCP Endpoint: http://0.0.0.0:${port}/mcp`);
      console.error(`❤️  Health Check: http://0.0.0.0:${port}/healthz`);
    });
  }

  async runStdio() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    
    console.error('🔒 FHIR-MCP server started with enhanced security (STDIO mode)');
    console.error(`📍 FHIR Base URL: ${this.config.fhir.baseUrl}`);
    console.error(`📚 Terminology Base URL: ${this.config.terminology.baseUrl}`);
    console.error(`🛡️ PHI Protection Mode: ${this.config.security.phiMode}`);
    console.error(`📋 Audit Logging: ${this.config.security.enableAudit ? 'ENABLED' : 'DISABLED'}`);
  }
}

// Determine transport mode and start server
const transport = process.env.MCP_TRANSPORT || 'stdio';
const server = new FhirMcpServer();

if (transport === 'http') {
  server.runHttp().catch(console.error);
} else {
  server.runStdio().catch(console.error);
}