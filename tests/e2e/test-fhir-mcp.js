#!/usr/bin/env node

/**
 * E2E Test Script for FhirMCP Server
 * Tests against HAPI FHIR server and public terminology service
 */

const { spawn } = require('child_process');
const path = require('path');

class FhirMcpTester {
  constructor() {
    this.serverProcess = null;
    this.testResults = [];
  }

  async runTest() {
    console.log('🚀 Starting FhirMCP E2E Tests\n');
    
    try {
      await this.startServer();
      await this.runTestSuite();
      this.displayResults();
    } catch (error) {
      console.error('❌ Test suite failed:', error.message);
      process.exit(1);
    } finally {
      if (this.serverProcess) {
        this.serverProcess.kill();
      }
    }
  }

  async startServer() {
    console.log('📦 Building server...');
    const buildProcess = spawn('npm', ['run', 'build'], {
      cwd: path.join(__dirname, '../../packages/mcp-fhir-server'),
      stdio: 'inherit'
    });

    await new Promise((resolve, reject) => {
      buildProcess.on('close', (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Build failed with code ${code}`));
        }
      });
    });

    console.log('🌟 Starting FhirMCP server...');
    this.serverProcess = spawn('node', ['dist/index.js'], {
      cwd: path.join(__dirname, '../../packages/mcp-fhir-server'),
      stdio: ['pipe', 'pipe', 'inherit'],
      env: {
        ...process.env,
        FHIR_BASE_URL: 'https://hapi.fhir.org/baseR4',
        TERMINOLOGY_BASE_URL: 'https://tx.fhir.org/r4',
        PHI_MODE: 'safe',
        ENABLE_AUDIT: 'true'
      }
    });

    // Give server time to start
    await new Promise(resolve => setTimeout(resolve, 2000));
  }

  async runTestSuite() {
    const tests = [
      { name: 'List Tools', test: this.testListTools.bind(this) },
      { name: 'FHIR Capabilities', test: this.testFhirCapabilities.bind(this) },
      { name: 'Patient Search', test: this.testPatientSearch.bind(this) },
      { name: 'Patient Read', test: this.testPatientRead.bind(this) },
      { name: 'Terminology Lookup', test: this.testTerminologyLookup.bind(this) },
      { name: 'ValueSet Expand', test: this.testValueSetExpand.bind(this) }
    ];

    for (const { name, test } of tests) {
      console.log(`🔍 Running test: ${name}`);
      try {
        await test();
        this.testResults.push({ name, status: 'PASS' });
        console.log(`✅ ${name} - PASSED\n`);
      } catch (error) {
        this.testResults.push({ name, status: 'FAIL', error: error.message });
        console.log(`❌ ${name} - FAILED: ${error.message}\n`);
      }
    }
  }

  async sendMcpRequest(method, params = {}) {
    return new Promise((resolve, reject) => {
      const request = {
        jsonrpc: '2.0',
        id: 1,
        method,
        params
      };

      const requestJson = JSON.stringify(request) + '\n';
      
      this.serverProcess.stdin.write(requestJson);
      
      let responseData = '';
      const timeout = setTimeout(() => {
        reject(new Error('Request timeout'));
      }, 10000);

      const responseHandler = (data) => {
        responseData += data.toString();
        try {
          const response = JSON.parse(responseData.trim());
          clearTimeout(timeout);
          this.serverProcess.stdout.removeListener('data', responseHandler);
          
          if (response.error) {
            reject(new Error(response.error.message));
          } else {
            resolve(response.result);
          }
        } catch (e) {
          // Still receiving data, continue
        }
      };

      this.serverProcess.stdout.on('data', responseHandler);
    });
  }

  async testListTools() {
    const result = await this.sendMcpRequest('tools/list');
    
    if (!result.tools || !Array.isArray(result.tools)) {
      throw new Error('Expected tools array in response');
    }

    const expectedTools = [
      'fhir.capabilities',
      'fhir.search',
      'fhir.read',
      'fhir.create',
      'fhir.update',
      'terminology.expand',
      'terminology.lookup',
      'terminology.translate'
    ];

    const toolNames = result.tools.map(t => t.name);
    
    for (const expectedTool of expectedTools) {
      if (!toolNames.includes(expectedTool)) {
        throw new Error(`Missing expected tool: ${expectedTool}`);
      }
    }
  }

  async testFhirCapabilities() {
    const result = await this.sendMcpRequest('tools/call', {
      name: 'fhir.capabilities',
      arguments: {}
    });

    if (!result.content || !result.content[0] || !result.content[0].text) {
      throw new Error('Expected content with text in response');
    }

    const capabilities = JSON.parse(result.content[0].text);
    
    if (!capabilities.fhirVersion) {
      throw new Error('Expected fhirVersion in capabilities');
    }

    if (!capabilities.resources || !Array.isArray(capabilities.resources)) {
      throw new Error('Expected resources array in capabilities');
    }
  }

  async testPatientSearch() {
    const result = await this.sendMcpRequest('tools/call', {
      name: 'fhir.search',
      arguments: {
        resourceType: 'Patient',
        params: {
          _count: '3'
        },
        elements: ['id', 'name', 'gender']
      }
    });

    if (!result.content || !result.content[0]) {
      throw new Error('Expected content in response');
    }

    const searchResult = JSON.parse(result.content[0].text);
    
    if (!searchResult.entries || !Array.isArray(searchResult.entries)) {
      throw new Error('Expected entries array in search result');
    }
  }

  async testPatientRead() {
    // First search for a patient to get an ID
    const searchResult = await this.sendMcpRequest('tools/call', {
      name: 'fhir.search',
      arguments: {
        resourceType: 'Patient',
        params: { _count: '1' },
        elements: ['id']
      }
    });

    const searchData = JSON.parse(searchResult.content[0].text);
    
    if (!searchData.entries || searchData.entries.length === 0) {
      throw new Error('No patients found for read test');
    }

    const patientId = searchData.entries[0].id;
    
    // Now read the specific patient
    const result = await this.sendMcpRequest('tools/call', {
      name: 'fhir.read',
      arguments: {
        resourceType: 'Patient',
        id: patientId,
        elements: ['id', 'name', 'gender']
      }
    });

    const readResult = JSON.parse(result.content[0].text);
    
    if (!readResult.resource || !readResult.resource.id) {
      throw new Error('Expected resource with id in read result');
    }
  }

  async testTerminologyLookup() {
    const result = await this.sendMcpRequest('tools/call', {
      name: 'terminology.lookup',
      arguments: {
        system: 'http://loinc.org',
        code: '29463-7'
      }
    });

    const lookupResult = JSON.parse(result.content[0].text);
    
    if (typeof lookupResult.valid !== 'boolean') {
      throw new Error('Expected valid boolean in lookup result');
    }
  }

  async testValueSetExpand() {
    const result = await this.sendMcpRequest('tools/call', {
      name: 'terminology.expand',
      arguments: {
        url: 'http://hl7.org/fhir/ValueSet/administrative-gender',
        count: 10
      }
    });

    const expandResult = JSON.parse(result.content[0].text);
    
    if (!expandResult.expansion || !expandResult.expansion.contains) {
      throw new Error('Expected expansion with contains array');
    }
  }

  displayResults() {
    console.log('\n📊 TEST RESULTS SUMMARY');
    console.log('========================');
    
    const passed = this.testResults.filter(r => r.status === 'PASS').length;
    const failed = this.testResults.filter(r => r.status === 'FAIL').length;
    
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`📊 Total: ${this.testResults.length}\n`);

    this.testResults.forEach(result => {
      const icon = result.status === 'PASS' ? '✅' : '❌';
      console.log(`${icon} ${result.name}`);
      if (result.error) {
        console.log(`   Error: ${result.error}`);
      }
    });

    if (failed > 0) {
      console.log('\n❌ Some tests failed!');
      process.exit(1);
    } else {
      console.log('\n🎉 All tests passed!');
    }
  }
}

// Run the tests
const tester = new FhirMcpTester();
tester.runTest().catch(console.error);