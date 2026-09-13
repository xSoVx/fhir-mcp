#!/usr/bin/env node
import { timingSafeEqual } from 'node:crypto';
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
import {
  RequestScopedIdentityProvider,
  ServicePrincipal,
  servicePrincipalFromEnv,
  describePrincipal,
  PRINCIPAL_ID_ENV,
  PRINCIPAL_SCOPES_ENV
} from './security/identity.js';

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
  private servicePrincipal?: ServicePrincipal;
  private identityProvider = new RequestScopedIdentityProvider();

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

    // ------------------------------------------------------------------
    // Caller identity for the HTTP bridge.
    //
    // Unlike stdio, this transport DOES have a caller-authentication
    // channel, and it was throwing the result away: authenticate() verified
    // the bearer token and then returned a bare boolean, so a caller who had
    // just proved possession of the shared secret still reached the tool
    // layer as an anonymous request and was denied every PHI-bearing
    // resource.
    //
    // The identity is bound per request (see runHttp), and ONLY when the
    // bearer token was actually verified. Two deliberate consequences:
    //
    //   * AUTH_TOKEN unset -> authenticate() still returns true (unchanged,
    //     open deployment) but binds NO principal. An unauthenticated
    //     deployment must not gain PHI access merely because a principal is
    //     configured; that is precisely the safe-looking-but-permissive
    //     failure mode. Both an identity AND proof of it are required.
    //   * No principal configured -> nothing to bind, and the request is
    //     anonymous exactly as it is today.
    // ------------------------------------------------------------------
    this.servicePrincipal = servicePrincipalFromEnv();

    // Initialize tool handlers with enhanced security
    this.fhirTools = new FhirTools(
      this.fhirProvider, 
      this.phiGuard, 
      this.auditLogger,
      this.securityMiddleware,
      this.identityProvider
    );
    this.terminologyTools = new TerminologyTools(this.terminologyProvider, this.auditLogger);

    // Initialize MCP server (used by the stdio path; each SSE session gets
    // its own instance - see createMcpServer).
    this.server = this.createMcpServer();
  }

  /**
   * Build an MCP `Server` with this process's tool handlers registered.
   *
   * ONE INSTANCE PER TRANSPORT, deliberately. `Server.connect()` stores a
   * single `_transport`, so sharing one `Server` across concurrent SSE
   * sessions makes the second connection silently take ownership of the
   * response channel and every reply - including masked PHI bodies - is
   * delivered to whichever caller connected most recently. With per-request
   * identity now meaningful, that is a cross-caller disclosure, not just a
   * routing bug, so the sessions are isolated at the Server level.
   */
  private createMcpServer(): Server {
    const server = new Server(
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

    this.setupHandlers(server);
    return server;
  }

  private setupHandlers(server: Server) {
    // List available tools
    server.setRequestHandler(ListToolsRequestSchema, async () => {
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
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
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

  /**
   * Authenticate a request and, when it is genuinely verified, report the
   * principal it should run as.
   *
   * `verified` is the narrow notion: the caller presented a bearer token that
   * matched the configured AUTH_TOKEN. `allowed` is the broader, pre-existing
   * notion that also covers "no AUTH_TOKEN configured, so the bridge is open".
   * They are kept separate on purpose - only `verified` may carry identity.
   */
  private authenticate(req: IncomingMessage): { allowed: boolean; principal?: ServicePrincipal } {
    if (!this.authToken) {
      // Unchanged: an unconfigured bridge remains open. But it is NOT
      // authenticated, so no principal is bound and PHI stays denied.
      return { allowed: true };
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return { allowed: false };
    }

    if (!this.tokenMatches(authHeader.substring(7))) {
      return { allowed: false };
    }

    // Verified caller. Bind the configured principal if there is one;
    // `undefined` when none is configured, which denies as before.
    return { allowed: true, principal: this.servicePrincipal };
  }

  /** Constant-time comparison so the shared secret is not probeable. */
  private tokenMatches(presented: string): boolean {
    const expected = Buffer.from(this.authToken ?? '', 'utf8');
    const actual = Buffer.from(presented, 'utf8');
    if (expected.length !== actual.length) {
      return false;
    }
    return timingSafeEqual(expected, actual);
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

      const auth = this.authenticate(req);
      if (!auth.allowed) {
        this.sendUnauthorized(res);
        return;
      }

      if (req.method === 'GET' && req.url?.startsWith('/sse')) {
        const transport = new SSEServerTransport('/mcp', res);
        sessions.set(transport.sessionId, transport);

        transport.onclose = () => {
          sessions.delete(transport.sessionId);
        };

        // `connect()` calls `transport.start()` itself. The previous code
        // called start() first and then connect(), so the SDK threw
        // "SSEServerTransport already started!" out of an async handler with
        // no catch - which terminated the whole process on the FIRST SSE
        // connection. The HTTP bridge could therefore never serve a single
        // tool call, masked or otherwise.
        await this.createMcpServer().connect(transport);
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

        // Tool calls arrive here. Enter the identity scope around the
        // dispatch so FhirTools resolves this caller's principal, and only
        // this caller's. `runWithPrincipal(undefined, ...)` explicitly EXITS
        // any ambient store rather than inheriting one, so an unverified
        // request can never pick up a neighbouring request''s identity.
        await this.identityProvider.runWithPrincipal(
          auth.principal,
          () => transport.handlePostMessage(req, res)
        );
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
      console.error(`👤 Caller Identity: ${describePrincipal(this.servicePrincipal)}`);
      if (this.servicePrincipal && !this.authToken) {
        console.error(
          `     ↳ ${PRINCIPAL_ID_ENV} is configured but AUTH_TOKEN is not, so no ` +
          'request can be verified and the principal is never bound. PHI-bearing ' +
          'resources stay denied. Set AUTH_TOKEN to activate the identity.'
        );
      } else if (!this.servicePrincipal) {
        console.error(
          `     ↳ no ${PRINCIPAL_ID_ENV} configured; PHI-bearing resources will be ` +
          `denied before masking runs. Set ${PRINCIPAL_ID_ENV}, ` +
          `${PRINCIPAL_SCOPES_ENV} and AUTH_TOKEN to enable masked PHI access.`
        );
      }
      console.error(`🔗 SSE Endpoint: http://0.0.0.0:${port}/sse`);
      console.error(`📡 MCP Endpoint: http://0.0.0.0:${port}/mcp`);
      console.error(`❤️  Health Check: http://0.0.0.0:${port}/healthz`);
    });
  }

  async runStdio() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    
    console.error('🔒 FHIR-MCP server started with enhanced security (STDIO mode)');
    console.error('👤 Caller Identity: none (this entry point binds identity per verified HTTP request; stdio mode has no request to verify)');
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