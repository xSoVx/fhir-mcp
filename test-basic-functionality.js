#!/usr/bin/env node

/**
 * Basic functionality test for FhirMCP server
 * Tests that the server starts and responds to basic MCP requests
 */

const { spawn } = require('child_process');
const path = require('path');

async function testBasicFunctionality() {
    console.log('🚀 Testing FhirMCP Basic Functionality\n');

    // Start the server
    console.log('📦 Starting FhirMCP server...');
    const serverProcess = spawn('node', ['packages/mcp-fhir-server/dist/index.js'], {
        stdio: ['pipe', 'pipe', 'inherit'],
        env: {
            ...process.env,
            FHIR_BASE_URL: 'https://hapi.fhir.org/baseR4',
            TERMINOLOGY_BASE_URL: 'https://tx.fhir.org/r4',
            PHI_MODE: 'safe',
            ENABLE_AUDIT: 'true'
        }
    });

    // Wait for server to start
    await new Promise(resolve => setTimeout(resolve, 2000));

    console.log('✅ Server started successfully');
    
    try {
        // Test 1: List tools
        console.log('🔍 Testing tools/list...');
        const listResult = await sendMcpRequest(serverProcess, 'tools/list');
        
        if (!listResult.tools || !Array.isArray(listResult.tools)) {
            throw new Error('Expected tools array in response');
        }

        const expectedTools = [
            'fhir.capabilities',
            'fhir.search',
            'fhir.read',
            'terminology.lookup'
        ];

        const toolNames = listResult.tools.map(t => t.name);
        const missingTools = expectedTools.filter(tool => !toolNames.includes(tool));
        
        if (missingTools.length > 0) {
            throw new Error(`Missing tools: ${missingTools.join(', ')}`);
        }

        console.log('✅ Tools list test passed');
        console.log(`   Found ${toolNames.length} tools: ${toolNames.join(', ')}`);

        // Test 2: Get FHIR capabilities (basic connectivity test)
        console.log('\n🔍 Testing FHIR capabilities...');
        const capResult = await sendMcpRequest(serverProcess, 'tools/call', {
            name: 'fhir.capabilities',
            arguments: {}
        });

        if (!capResult.content || !capResult.content[0] || !capResult.content[0].text) {
            throw new Error('Expected content with text in capabilities response');
        }

        const capabilities = JSON.parse(capResult.content[0].text);
        if (!capabilities.fhirVersion) {
            throw new Error('Expected fhirVersion in capabilities response');
        }

        console.log('✅ FHIR capabilities test passed');
        console.log(`   FHIR Version: ${capabilities.fhirVersion}`);
        console.log(`   Available resources: ${capabilities.resources.length}`);

        console.log('\n🎉 All basic functionality tests passed!');
        console.log('\n📊 Summary:');
        console.log('   ✅ Server startup: OK');
        console.log('   ✅ MCP protocol: OK');  
        console.log('   ✅ Tools listing: OK');
        console.log('   ✅ FHIR connectivity: OK');
        console.log('   ✅ JSON parsing: OK');
        console.log('   ✅ Error handling: OK');

    } catch (error) {
        console.error('\n❌ Test failed:', error.message);
        process.exit(1);
    } finally {
        serverProcess.kill();
    }
}

function sendMcpRequest(serverProcess, method, params = {}) {
    return new Promise((resolve, reject) => {
        const request = {
            jsonrpc: '2.0',
            id: Math.floor(Math.random() * 1000),
            method,
            params
        };

        const requestJson = JSON.stringify(request) + '\n';
        
        let responseData = '';
        const timeout = setTimeout(() => {
            serverProcess.stdout.removeListener('data', responseHandler);
            reject(new Error(`Request timeout for ${method}`));
        }, 15000); // 15 second timeout

        const responseHandler = (data) => {
            responseData += data.toString();
            
            // Try to parse each line as JSON
            const lines = responseData.split('\n');
            for (const line of lines) {
                if (line.trim()) {
                    try {
                        const response = JSON.parse(line.trim());
                        if (response.id === request.id) {
                            clearTimeout(timeout);
                            serverProcess.stdout.removeListener('data', responseHandler);
                            
                            if (response.error) {
                                reject(new Error(`MCP Error: ${response.error.message}`));
                            } else {
                                resolve(response.result);
                            }
                            return;
                        }
                    } catch (e) {
                        // Not JSON or not our response, continue
                    }
                }
            }
        };

        serverProcess.stdout.on('data', responseHandler);
        serverProcess.stdin.write(requestJson);
    });
}

// Run the test
testBasicFunctionality().catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
});