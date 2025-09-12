#!/usr/bin/env node

/**
 * Specific test for Audit Logger to investigate the redaction issue
 */

const path = require('path');

// Test the audit logger redaction functionality
function testAuditLoggerRedaction() {
  console.log('🔍 Testing Audit Logger Redaction in Detail...\n');
  
  try {
    const { AuditLogger } = require('./packages/mcp-fhir-server/dist/security/audit-logger.js');
    
    const logger = new AuditLogger(true);
    
    console.log('✅ AuditLogger imported successfully');
    
    // Test data with sensitive information
    const testMetadata = {
      token: 'secret-token-123',
      authorization: 'Bearer xyz-token',
      password: 'my-secret-password',
      normalField: 'normal-value',
      birthDate: '1980-01-01',
      ssn: '123-45-6789',
      secretKey: 'another-secret'
    };
    
    console.log('📝 Original metadata:', testMetadata);
    
    // Capture console.log output
    const originalConsoleLog = console.log;
    let capturedOutput = null;
    
    console.log = (data) => {
      if (typeof data === 'string' && data.startsWith('{')) {
        try {
          capturedOutput = JSON.parse(data);
        } catch (e) {
          capturedOutput = data;
        }
      }
    };
    
    // Log an event with sensitive metadata
    logger.log({
      operation: 'test-operation',
      success: true,
      metadata: testMetadata
    });
    
    // Restore console.log
    console.log = originalConsoleLog;
    
    if (capturedOutput) {
      console.log('📊 Captured audit log:', JSON.stringify(capturedOutput, null, 2));
      
      // Check redaction
      const metadata = capturedOutput.metadata || {};
      
      console.log('\n🔍 Redaction Analysis:');
      console.log('======================');
      
      const checks = {
        'token redacted': metadata.token === '***REDACTED***',
        'authorization redacted': metadata.authorization === '***REDACTED***',
        'password redacted': metadata.password === '***REDACTED***',
        'birthDate redacted': metadata.birthDate === '***REDACTED***',
        'ssn redacted': metadata.ssn === '***REDACTED***',
        'secretKey redacted': metadata.secretKey === '***REDACTED***',
        'normalField preserved': metadata.normalField === 'normal-value'
      };
      
      Object.entries(checks).forEach(([check, passed]) => {
        const icon = passed ? '✅' : '❌';
        console.log(`${icon} ${check}: ${passed}`);
        if (!passed && metadata[check.split(' ')[0]]) {
          console.log(`   Expected: ***REDACTED***, Got: ${metadata[check.split(' ')[0]]}`);
        }
      });
      
      const allChecksPassed = Object.values(checks).every(check => check);
      console.log(`\n🎯 Overall redaction result: ${allChecksPassed ? 'PASS' : 'FAIL'}`);
      
    } else {
      console.log('❌ Failed to capture audit log output');
    }
    
  } catch (error) {
    console.log('❌ Error testing audit logger:', error.message);
    console.log('Stack trace:', error.stack);
  }
}

// Also test the redaction method directly if possible
function testRedactionLogic() {
  console.log('\n🔧 Testing Redaction Logic Directly...\n');
  
  try {
    // Try to access the private method logic
    const sensitiveFields = ['token', 'authorization', 'password', 'secret', 'ssn', 'birthDate'];
    
    const testData = {
      token: 'secret-token',
      authorization: 'Bearer xyz',
      password: 'my-password',
      secretKey: 'secret-value',
      normalField: 'normal',
      birthDate: '1990-01-01',
      ssn: '123-45-6789'
    };
    
    // Simulate the redaction logic
    const redacted = { ...testData };
    
    Object.keys(redacted).forEach(key => {
      const lowerKey = key.toLowerCase();
      if (sensitiveFields.some(field => lowerKey.includes(field))) {
        redacted[key] = '***REDACTED***';
      }
    });
    
    console.log('🔒 Manual redaction simulation:');
    console.log('Original:', testData);
    console.log('Redacted:', redacted);
    
    const expectedRedactions = ['token', 'authorization', 'password', 'secretKey', 'birthDate', 'ssn'];
    const correctlyRedacted = expectedRedactions.every(field => redacted[field] === '***REDACTED***');
    const normalFieldPreserved = redacted.normalField === 'normal';
    
    console.log(`\n✅ Expected redactions work: ${correctlyRedacted}`);
    console.log(`✅ Normal fields preserved: ${normalFieldPreserved}`);
    
  } catch (error) {
    console.log('❌ Error in manual redaction test:', error.message);
  }
}

console.log('🧪 AUDIT LOGGER DETAILED TESTING');
console.log('=================================\n');

testAuditLoggerRedaction();
testRedactionLogic();

console.log('\n🎯 AUDIT LOGGER TEST COMPLETE');