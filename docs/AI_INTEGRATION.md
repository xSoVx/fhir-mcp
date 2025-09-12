# AI Assistant Integration with FhirMCP

This guide explains how to connect various AI assistants and tools to your FhirMCP server for healthcare data analysis and clinical decision support.

## 🤖 GitHub Copilot Integration

### Method 1: VS Code Extension with MCP Support

Currently, GitHub Copilot doesn't natively support MCP servers, but you can create a bridge:

#### A. Create a Copilot Extension Bridge

```typescript
// copilot-fhir-bridge.ts
import { spawn } from 'child_process';
import * as vscode from 'vscode';

export class FhirMcpBridge {
    private mcpProcess: any;
    
    constructor() {
        this.startMcpServer();
    }
    
    private startMcpServer() {
        this.mcpProcess = spawn('node', ['path/to/fhir-mcp/packages/mcp-fhir-server/dist/index.js'], {
            stdio: ['pipe', 'pipe', 'inherit'],
            env: {
                ...process.env,
                FHIR_BASE_URL: vscode.workspace.getConfiguration('fhirMcp').get('fhirUrl'),
                PHI_MODE: 'safe'
            }
        });
    }
    
    async sendMcpRequest(method: string, params: any = {}) {
        return new Promise((resolve, reject) => {
            const request = {
                jsonrpc: '2.0',
                id: Math.floor(Math.random() * 1000),
                method,
                params
            };

            const requestJson = JSON.stringify(request) + '\n';
            this.mcpProcess.stdin.write(requestJson);
            
            // Handle response...
        });
    }
    
    // Copilot-friendly wrapper methods
    async getFhirCapabilities(): Promise<string> {
        const result = await this.sendMcpRequest('tools/call', {
            name: 'fhir.capabilities',
            arguments: {}
        });
        return JSON.stringify(result, null, 2);
    }
    
    async searchPatients(searchParams: any): Promise<string> {
        const result = await this.sendMcpRequest('tools/call', {
            name: 'fhir.search',
            arguments: {
                resourceType: 'Patient',
                params: searchParams,
                elements: ['id', 'name', 'gender', 'birthDate']
            }
        });
        return JSON.stringify(result, null, 2);
    }
}
```

#### B. VS Code Extension Configuration

Create `.vscode/settings.json`:

```json
{
    "fhirMcp": {
        "fhirUrl": "https://hapi.fhir.org/baseR4",
        "terminologyUrl": "https://tx.fhir.org/r4",
        "phiMode": "safe",
        "enableAudit": true
    },
    "github.copilot.enable": {
        "*": true,
        "fhir": true,
        "json": true,
        "typescript": true
    }
}
```

### Method 2: Copilot Chat Integration

Create context-aware prompts for Copilot Chat:

```typescript
// Add to your workspace for Copilot context
/**
 * @copilot-context FhirMCP Integration
 * 
 * This workspace uses FhirMCP server for FHIR data access.
 * 
 * Available tools:
 * - fhir.capabilities: Get server capabilities
 * - fhir.search: Search FHIR resources
 * - fhir.read: Read specific resource
 * - terminology.lookup: Look up codes
 * 
 * Example usage:
 * const result = await fhirBridge.searchPatients({ name: "John" });
 */
```

## 🧠 Claude Integration (Recommended)

FhirMCP is designed to work seamlessly with Claude through MCP protocol:

### Claude Desktop Configuration

Add to your Claude configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "fhir": {
      "command": "node",
      "args": ["C:/path/to/fhir-mcp/packages/mcp-fhir-server/dist/index.js"],
      "env": {
        "FHIR_BASE_URL": "https://hapi.fhir.org/baseR4",
        "TERMINOLOGY_BASE_URL": "https://tx.fhir.org/r4",
        "PHI_MODE": "safe",
        "ENABLE_AUDIT": "true"
      }
    }
  }
}
```

### Claude System Prompt

Add this system prompt for healthcare contexts:

```
You have access to FHIR healthcare data through FhirMCP tools. Always:
1. Use PHI-safe practices - never expose full names, SSNs, or addresses
2. Prioritize patient privacy and data security
3. Use token-efficient queries with _elements parameter
4. Look up clinical codes before explaining their meaning
5. Ask for confirmation before any write operations
```

## 🔧 OpenAI GPT Integration

### Method 1: Custom GPT with Actions

Create a Custom GPT with these actions:

```yaml
# openapi.yaml for Custom GPT
openapi: 3.0.0
info:
  title: FhirMCP API
  version: 1.0.0
servers:
  - url: https://your-fhir-mcp-server.com
paths:
  /fhir/capabilities:
    post:
      summary: Get FHIR server capabilities
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                baseUrl:
                  type: string
      responses:
        '200':
          description: Capabilities response
  /fhir/search:
    post:
      summary: Search FHIR resources
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [resourceType]
              properties:
                resourceType:
                  type: string
                params:
                  type: object
                elements:
                  type: array
                  items:
                    type: string
```

### Method 2: OpenAI API with Function Calling

```python
# openai-fhir-bridge.py
import openai
import subprocess
import json

class FhirMcpClient:
    def __init__(self):
        self.mcp_process = subprocess.Popen([
            'node', 'path/to/fhir-mcp/packages/mcp-fhir-server/dist/index.js'
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    def send_mcp_request(self, method, params=None):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or {}
        }
        
        self.mcp_process.stdin.write(json.dumps(request) + '\n')
        self.mcp_process.stdin.flush()
        
        response = json.loads(self.mcp_process.stdout.readline())
        return response.get('result', {})
    
    def search_patients(self, search_params):
        return self.send_mcp_request('tools/call', {
            'name': 'fhir.search',
            'arguments': {
                'resourceType': 'Patient',
                'params': search_params,
                'elements': ['id', 'name', 'gender']
            }
        })

# OpenAI Function definitions
functions = [
    {
        "name": "search_patients",
        "description": "Search for patients in FHIR server",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Patient name to search for"},
                "gender": {"type": "string", "description": "Patient gender"}
            }
        }
    }
]

# Use with OpenAI API
client = openai.OpenAI()
fhir_client = FhirMcpClient()

def process_with_openai(user_message):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_message}],
        functions=functions,
        function_call="auto"
    )
    
    if response.choices[0].message.function_call:
        function_name = response.choices[0].message.function_call.name
        function_args = json.loads(response.choices[0].message.function_call.arguments)
        
        if function_name == "search_patients":
            result = fhir_client.search_patients(function_args)
            return result
    
    return response.choices[0].message.content
```

## 🛠 VS Code Integration

### Extension for FHIR Development

Create a VS Code extension that integrates with FhirMCP:

```typescript
// extension.ts
import * as vscode from 'vscode';
import { FhirMcpBridge } from './fhir-mcp-bridge';

export function activate(context: vscode.ExtensionContext) {
    const fhirBridge = new FhirMcpBridge();
    
    // Register commands
    let searchCommand = vscode.commands.registerCommand('fhirMcp.searchPatients', async () => {
        const searchTerm = await vscode.window.showInputBox({
            prompt: 'Enter patient search term'
        });
        
        if (searchTerm) {
            const results = await fhirBridge.searchPatients({ name: searchTerm });
            
            // Show results in new document
            const doc = await vscode.workspace.openTextDocument({
                content: JSON.stringify(results, null, 2),
                language: 'json'
            });
            await vscode.window.showTextDocument(doc);
        }
    });
    
    // Code completion provider
    let completionProvider = vscode.languages.registerCompletionItemProvider(
        { scheme: 'file', language: 'typescript' },
        {
            provideCompletionItems(document, position) {
                // Provide FHIR-specific completions
                const fhirCompletion = new vscode.CompletionItem('fhir.search');
                fhirCompletion.insertText = new vscode.SnippetString(
                    'fhir.search({\n\tresourceType: "${1:Patient}",\n\tparams: { ${2} },\n\telements: [${3}]\n})'
                );
                fhirCompletion.documentation = 'Search FHIR resources using FhirMCP';
                
                return [fhirCompletion];
            }
        }
    );
    
    context.subscriptions.push(searchCommand, completionProvider);
}
```

### Package.json for VS Code Extension

```json
{
    "name": "fhir-mcp-integration",
    "displayName": "FHIR MCP Integration",
    "description": "Integrate FhirMCP server with VS Code",
    "version": "0.1.0",
    "engines": {
        "vscode": "^1.74.0"
    },
    "categories": ["Other"],
    "contributes": {
        "commands": [
            {
                "command": "fhirMcp.searchPatients",
                "title": "Search Patients",
                "category": "FHIR"
            }
        ],
        "configuration": {
            "title": "FHIR MCP",
            "properties": {
                "fhirMcp.serverPath": {
                    "type": "string",
                    "description": "Path to FhirMCP server"
                },
                "fhirMcp.fhirUrl": {
                    "type": "string",
                    "default": "https://hapi.fhir.org/baseR4",
                    "description": "FHIR server base URL"
                }
            }
        }
    }
}
```

## 🌐 Web-based AI Integration

### HTTP Bridge for Web AIs

Create an HTTP wrapper for web-based AI tools:

```typescript
// http-bridge.ts
import express from 'express';
import cors from 'cors';
import { spawn } from 'child_process';

const app = express();
app.use(cors());
app.use(express.json());

class HttpMcpBridge {
    private mcpProcess: any;
    
    constructor() {
        this.startMcpServer();
    }
    
    private startMcpServer() {
        this.mcpProcess = spawn('node', ['../packages/mcp-fhir-server/dist/index.js'], {
            stdio: ['pipe', 'pipe', 'inherit'],
            env: {
                ...process.env,
                FHIR_BASE_URL: process.env.FHIR_BASE_URL || 'https://hapi.fhir.org/baseR4'
            }
        });
    }
    
    async sendRequest(method: string, params: any) {
        return new Promise((resolve, reject) => {
            const request = {
                jsonrpc: '2.0',
                id: Math.floor(Math.random() * 1000),
                method,
                params
            };

            this.mcpProcess.stdin.write(JSON.stringify(request) + '\n');
            
            let responseData = '';
            const responseHandler = (data: any) => {
                responseData += data.toString();
                try {
                    const response = JSON.parse(responseData.trim());
                    this.mcpProcess.stdout.removeListener('data', responseHandler);
                    resolve(response.result);
                } catch (e) {
                    // Continue receiving data
                }
            };

            this.mcpProcess.stdout.on('data', responseHandler);
            
            setTimeout(() => {
                this.mcpProcess.stdout.removeListener('data', responseHandler);
                reject(new Error('Request timeout'));
            }, 15000);
        });
    }
}

const bridge = new HttpMcpBridge();

// REST API endpoints
app.post('/fhir/capabilities', async (req, res) => {
    try {
        const result = await bridge.sendRequest('tools/call', {
            name: 'fhir.capabilities',
            arguments: req.body
        });
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/fhir/search', async (req, res) => {
    try {
        const result = await bridge.sendRequest('tools/call', {
            name: 'fhir.search',
            arguments: req.body
        });
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(3001, () => {
    console.log('FhirMCP HTTP Bridge running on port 3001');
});
```

## 📱 Usage Examples

### Example 1: Patient Search with AI Assistant

```javascript
// For any AI assistant with JavaScript support
async function searchPatientsWithAI(searchTerm) {
    const response = await fetch('http://localhost:3001/fhir/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            resourceType: 'Patient',
            params: { name: searchTerm },
            count: 5,
            elements: ['id', 'name', 'gender', 'birthDate']
        })
    });
    
    const data = await response.json();
    return data;
}
```

### Example 2: Clinical Code Lookup

```python
# Python example for any AI that supports Python
import requests

def lookup_clinical_code(system, code):
    response = requests.post('http://localhost:3001/terminology/lookup', 
        json={'system': system, 'code': code})
    return response.json()

# Example: Look up LOINC code
result = lookup_clinical_code('http://loinc.org', '29463-7')
print(f"Code meaning: {result.get('display', 'Unknown')}")
```

## 🔐 Security Considerations

1. **PHI Protection**: Always use `PHI_MODE=safe` for AI integrations
2. **Network Security**: Use HTTPS for all HTTP bridges
3. **Authentication**: Implement proper auth for production deployments
4. **Audit Logging**: Monitor all AI assistant interactions
5. **Rate Limiting**: Implement rate limits to prevent abuse

## 📊 Monitoring AI Usage

Add monitoring to track AI assistant usage:

```typescript
// Add to your bridge
class AIUsageMonitor {
    logUsage(aiAssistant: string, operation: string, success: boolean) {
        console.log(JSON.stringify({
            timestamp: new Date().toISOString(),
            aiAssistant,
            operation,
            success,
            traceId: Math.random().toString(36)
        }));
    }
}
```

This comprehensive guide provides multiple methods to integrate FhirMCP with various AI assistants, with Claude being the most seamless option due to native MCP support.