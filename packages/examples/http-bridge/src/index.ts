import express, { Request, Response } from 'express';
import cors from 'cors';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

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
app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// List available tools
app.get('/tools', async (req: Request, res: Response) => {
  try {
    const result = await bridge.sendRequest('tools/list');
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

// FHIR Capabilities
app.post('/fhir/capabilities', async (req: Request, res: Response) => {
  try {
    const result = await bridge.sendRequest('tools/call', {
      name: 'fhir.capabilities',
      arguments: req.body
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

// FHIR Search
app.post('/fhir/search', async (req: Request, res: Response) => {
  try {
    const result = await bridge.sendRequest('tools/call', {
      name: 'fhir.search',
      arguments: req.body
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

// FHIR Read
app.post('/fhir/read', async (req: Request, res: Response) => {
  try {
    const result = await bridge.sendRequest('tools/call', {
      name: 'fhir.read',
      arguments: req.body
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

// Terminology Lookup
app.post('/terminology/lookup', async (req: Request, res: Response) => {
  try {
    const result = await bridge.sendRequest('tools/call', {
      name: 'terminology.lookup',
      arguments: req.body
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

// Terminology Expand
app.post('/terminology/expand', async (req: Request, res: Response) => {
  try {
    const result = await bridge.sendRequest('tools/call', {
      name: 'terminology.expand',
      arguments: req.body
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

// Generic tool call endpoint
app.post('/tools/:toolName', async (req: Request, res: Response) => {
  try {
    const toolName = req.params.toolName;
    const result = await bridge.sendRequest('tools/call', {
      name: toolName,
      arguments: req.body
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: (error as Error).message });
  }
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`🌐 FHIR-MCP HTTP Bridge running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔧 Tools list: http://localhost:${PORT}/tools`);
  console.log(`🏥 FHIR endpoints: http://localhost:${PORT}/fhir/*`);
  console.log(`📚 Terminology endpoints: http://localhost:${PORT}/terminology/*`);
});

export { HttpMcpBridge };