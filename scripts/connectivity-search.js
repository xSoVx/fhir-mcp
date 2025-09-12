#!/usr/bin/env node

const { spawn } = require('child_process');

async function run() {
  const resourceType = process.argv[2] || process.env.RESOURCE_TYPE || 'Patient';
  console.log(`🔎 Connectivity check: fhir.search (${resourceType})`);

  const serverProcess = spawn('node', ['packages/mcp-fhir-server/dist/index.js'], {
    stdio: ['pipe', 'pipe', 'inherit'],
    env: {
      ...process.env,
      FHIR_BASE_URL: process.env.FHIR_BASE_URL || 'https://hapi.fhir.org/baseR4',
      TERMINOLOGY_BASE_URL: process.env.TERMINOLOGY_BASE_URL || 'https://tx.fhir.org/r4',
      PHI_MODE: 'safe',
      ENABLE_AUDIT: 'true'
    }
  });

  // Give the server a moment to boot
  await new Promise(r => setTimeout(r, 1500));

  try {
    const result = await sendMcpRequest(serverProcess, 'tools/call', {
      name: 'fhir.search',
      arguments: {
        resourceType,
        params: { _count: '3' },
        elements: ['id', 'name', 'gender']
      }
    });

    if (!result.content || !result.content[0] || !result.content[0].text) {
      throw new Error('No search content returned');
    }

    const data = JSON.parse(result.content[0].text);
    const entries = Array.isArray(data.entries) ? data.entries : [];
    console.log(`✅ Search ok. Returned entries: ${entries.length}`);
    entries.forEach((e, i) => {
      const name = (e.name && e.name[0] && (e.name[0].text || (e.name[0].given||[]).join(' ') + ' ' + (e.name[0].family||''))) || '—';
      console.log(`  • [${i+1}] id=${e.id || '—'} name=${name.trim()}`);
    });
  } catch (err) {
    console.error('❌ Search failed:', err.message);
    process.exitCode = 1;
  } finally {
    serverProcess.kill();
  }
}

function sendMcpRequest(serverProcess, method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 10000);
    const request = { jsonrpc: '2.0', id, method, params };
    const payload = JSON.stringify(request) + '\n';

    let buffer = '';
    const timeout = setTimeout(() => {
      serverProcess.stdout.removeListener('data', onData);
      reject(new Error(`Timeout waiting for response to ${method}`));
    }, 20000);

    function onData(chunk) {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line.trim());
          if (msg.id === id) {
            clearTimeout(timeout);
            serverProcess.stdout.removeListener('data', onData);
            if (msg.error) reject(new Error(msg.error.message || 'MCP error'));
            else resolve(msg.result);
            return;
          }
        } catch (_) {
          // ignore non-JSON lines
        }
      }
    }

    serverProcess.stdout.on('data', onData);
    serverProcess.stdin.write(payload);
  });
}

run().catch(e => {
  console.error('Unexpected failure:', e);
  process.exit(1);
});
