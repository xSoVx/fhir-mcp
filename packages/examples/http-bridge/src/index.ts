import express, { Request, Response } from 'express';
import cors from 'cors';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import Joi from 'joi';

// Security middleware imports
import {
  validationSchemas,
  validateRequest,
  validateToolParameters,
  validateContentType,
  validateRequestSize
} from './security/validation.js';
import {
  generalRateLimit,
  fhirRateLimit,
  writeRateLimit,
  progressiveDelay,
  checkBlocked,
  recordFailedAttempt,
  handleSuspiciousErrors
} from './security/rate-limiting.js';
import {
  securityHeaders,
  sensitiveEndpointSecurity,
  validateRequestPatterns,
  securityMonitoring,
  securityErrorHandler
} from './security/headers.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Trust proxy for proper IP detection behind load balancer
app.set('trust proxy', 1);

// Security middleware stack - ORDER IS IMPORTANT
app.use(...securityHeaders);
app.use(validateRequestPatterns);
app.use(securityMonitoring);
app.use(checkBlocked);
app.use(recordFailedAttempt);
app.use(validateContentType);
app.use(validateRequestSize(1024 * 1024)); // 1MB limit
// Rate limiting after basic validation
app.use(progressiveDelay);
app.use(generalRateLimit);

// CORS with stricter configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:8080'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Request-ID'],
  exposedHeaders: ['X-Request-ID', 'X-Rate-Limit-Remaining']
}));

// Body parsing with size limits
app.use(express.json({ 
  limit: '1mb',
  strict: true,
  verify: (req: any, _res: any, buf: Buffer) => {
    // Store raw body for signature verification if needed
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

interface McpRequest {
  jsonrpc: string;
  id: number;
  method: string;
  params?: unknown;
}

interface McpResponse {
  jsonrpc: string;
  id: number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

class HttpMcpBridge {
  private mcpProcess: any;
  private requestQueue: Map<number, { resolve: (value: unknown) => void; reject: (reason?: unknown) => void }> = new Map();
  private requestId = 1;

  constructor() {
    this.startMcpServer();
  }

  private startMcpServer() {
    const serverPath = path.join(__dirname, '../../../mcp-fhir-server/dist/index.js');
    
    this.mcpProcess = spawn('node', [serverPath], {
      stdio: ['pipe', 'pipe', 'inherit'],
      env: {
        ...process.env,
        FHIR_BASE_URL: process.env.FHIR_BASE_URL || 'https://hapi.fhir.org/baseR4',
        TERMINOLOGY_BASE_URL: process.env.TERMINOLOGY_BASE_URL || 'https://tx.fhir.org/r4',
        PHI_MODE: 'safe',
        ENABLE_AUDIT: 'true'
      }
    });

    // Handle responses
    let responseBuffer = '';
    this.mcpProcess.stdout.on('data', (data: Buffer) => {
      responseBuffer += data.toString();
      
      const lines = responseBuffer.split('\n');
      responseBuffer = lines.pop() || ''; // Keep incomplete line in buffer
      
      for (const line of lines) {
        if (line.trim()) {
          try {
            const response: McpResponse = JSON.parse(line.trim());
            const pending = this.requestQueue.get(response.id);
            if (pending) {
              this.requestQueue.delete(response.id);
              if (response.error) {
                pending.reject(new Error(response.error.message || 'MCP Error'));
              } else {
                pending.resolve(response.result);
              }
            }
          } catch (e) {
            console.error('Failed to parse MCP response:', line);
          }
        }
      }
    });

    this.mcpProcess.on('error', (error: Error) => {
      console.error('MCP process error:', error);
    });
  }

  async sendRequest(method: string, params: unknown = {}): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const id = this.requestId++;
      const request: McpRequest = {
        jsonrpc: '2.0',
        id,
        method,
        params
      };

      this.requestQueue.set(id, { resolve, reject });
      
      this.mcpProcess.stdin.write(JSON.stringify(request) + '\n');
      
      // Timeout after 30 seconds
      setTimeout(() => {
        if (this.requestQueue.has(id)) {
          this.requestQueue.delete(id);
          reject(new Error('Request timeout'));
        }
      }, 30000);
    });
  }
}

const bridge = new HttpMcpBridge();

// Health check endpoint
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// List available tools
app.get('/tools', async (_req: Request, res: Response) => {
  try {
    const result = await bridge.sendRequest('tools/list');
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

// FHIR Capabilities
app.post('/fhir/capabilities', 
  fhirRateLimit,
  sensitiveEndpointSecurity,
  validateRequest(Joi.object({
    _summary: Joi.string().valid('true', 'false', 'text', 'data').optional(),
    _format: Joi.string().valid('json', 'xml', 'application/fhir+json', 'application/fhir+xml').optional()
  }).unknown(false)),
  async (req: Request, res: Response) => {
    try {
      const result = await bridge.sendRequest('tools/call', {
        name: 'fhir.capabilities',
        arguments: req.body
      });
      res.json(result);
    } catch (error) {
      res.status(500).json({ 
        error: 'FHIR capabilities request failed',
        message: process.env.NODE_ENV === 'production' ? 'Internal server error' : (error as Error).message,
        requestId: req.get('X-Request-ID'),
        timestamp: new Date().toISOString()
      });
    }
  }
);

// FHIR Search
app.post('/fhir/search', 
  fhirRateLimit,
  sensitiveEndpointSecurity,
  validateRequest(validationSchemas.fhirSearch),
  async (req: Request, res: Response) => {
    try {
      const result = await bridge.sendRequest('tools/call', {
        name: 'fhir.search',
        arguments: req.body
      });
      res.json(result);
    } catch (error) {
      res.status(500).json({ 
        error: 'FHIR search request failed',
        message: process.env.NODE_ENV === 'production' ? 'Internal server error' : (error as Error).message,
        requestId: req.get('X-Request-ID'),
        timestamp: new Date().toISOString()
      });
    }
  }
);

// FHIR Read
app.post('/fhir/read', 
  fhirRateLimit,
  sensitiveEndpointSecurity,
  validateRequest(validationSchemas.fhirRead),
  async (req: Request, res: Response) => {
    try {
      const result = await bridge.sendRequest('tools/call', {
        name: 'fhir.read',
        arguments: req.body
      });
      res.json(result);
    } catch (error) {
      res.status(500).json({ 
        error: 'FHIR read request failed',
        message: process.env.NODE_ENV === 'production' ? 'Internal server error' : (error as Error).message,
        requestId: req.get('X-Request-ID'),
        timestamp: new Date().toISOString()
      });
    }
  }
);

// Terminology Lookup
app.post('/terminology/lookup', 
  fhirRateLimit,
  validateRequest(validationSchemas.terminologyLookup),
  async (req: Request, res: Response) => {
    try {
      const result = await bridge.sendRequest('tools/call', {
        name: 'terminology.lookup',
        arguments: req.body
      });
      res.json(result);
    } catch (error) {
      res.status(500).json({ 
        error: 'Terminology lookup request failed',
        message: process.env.NODE_ENV === 'production' ? 'Internal server error' : (error as Error).message,
        requestId: req.get('X-Request-ID'),
        timestamp: new Date().toISOString()
      });
    }
  }
);

// Terminology Expand
app.post('/terminology/expand', 
  fhirRateLimit,
  validateRequest(validationSchemas.terminologyExpand),
  async (req: Request, res: Response) => {
    try {
      const result = await bridge.sendRequest('tools/call', {
        name: 'terminology.expand',
        arguments: req.body
      });
      res.json(result);
    } catch (error) {
      res.status(500).json({ 
        error: 'Terminology expand request failed',
        message: process.env.NODE_ENV === 'production' ? 'Internal server error' : (error as Error).message,
        requestId: req.get('X-Request-ID'),
        timestamp: new Date().toISOString()
      });
    }
  }
);

// FHIR Create (Write operation)
app.post('/fhir/create', 
  writeRateLimit,
  sensitiveEndpointSecurity,
  validateRequest(validationSchemas.fhirResource),
  async (req: Request, res: Response) => {
    try {
      const result = await bridge.sendRequest('tools/call', {
        name: 'fhir.create',
        arguments: req.body
      });
      res.json(result);
    } catch (error) {
      res.status(500).json({ 
        error: 'FHIR create request failed',
        message: process.env.NODE_ENV === 'production' ? 'Internal server error' : (error as Error).message,
        requestId: req.get('X-Request-ID'),
        timestamp: new Date().toISOString()
      });
    }
  }
);

// FHIR Update (Write operation)
app.post('/fhir/update', 
  writeRateLimit,
  sensitiveEndpointSecurity,
  validateRequest(validationSchemas.fhirResource),
  async (req: Request, res: Response) => {
    try {
      const result = await bridge.sendRequest('tools/call', {
        name: 'fhir.update',
        arguments: req.body
      });
      res.json(result);
    } catch (error) {
      res.status(500).json({ 
        error: 'FHIR update request failed',
        message: process.env.NODE_ENV === 'production' ? 'Internal server error' : (error as Error).message,
        requestId: req.get('X-Request-ID'),
        timestamp: new Date().toISOString()
      });
    }
  }
);

// Generic tool call endpoint
app.post('/tools/:toolName', 
  fhirRateLimit,
  validateToolParameters,
  async (req: Request, res: Response) => {
    try {
      const toolName = req.params.toolName;
      const result = await bridge.sendRequest('tools/call', {
        name: toolName,
        arguments: req.body
      });
      res.json(result);
    } catch (error) {
      res.status(500).json({ 
        error: `Tool ${req.params.toolName} request failed`,
        message: process.env.NODE_ENV === 'production' ? 'Internal server error' : (error as Error).message,
        requestId: req.get('X-Request-ID'),
        timestamp: new Date().toISOString()
      });
    }
  }
);

const PORT = process.env.PORT || 3001;

// Error handling middleware - MUST BE LAST
app.use(handleSuspiciousErrors);
app.use(securityErrorHandler);

// 404 handler
app.use('*', (req: Request, res: Response) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested endpoint does not exist',
    path: req.originalUrl,
    requestId: req.get('X-Request-ID'),
    timestamp: new Date().toISOString()
  });
});

app.listen(PORT, () => {
  console.log(`🌐 FHIR-MCP HTTP Bridge running on port ${PORT}`);
  console.log(`🔒 Security hardening: Phase 1 implemented`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔧 Tools list: http://localhost:${PORT}/tools`);
  console.log(`🏥 FHIR endpoints: http://localhost:${PORT}/fhir/*`);
  console.log(`📚 Terminology endpoints: http://localhost:${PORT}/terminology/*`);
  
  if (process.env.NODE_ENV === 'production') {
    console.log(`⚠️  Production mode: Enhanced security active`);
    console.log(`🛡️  Rate limiting: Active`);
    console.log(`🔐 HTTPS required: ${process.env.REQUIRE_HTTPS !== 'false'}`);
  }
});

export { HttpMcpBridge };