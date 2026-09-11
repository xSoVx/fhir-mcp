import { describe, test, expect, beforeEach, jest } from '@jest/globals';
import { InputValidator } from '../security/input-validator.js';
import { RateLimiter } from '../security/rate-limiter.js';
import { SecurityHeadersManager } from '../security/security-headers.js';
import { SecurityMiddleware } from '../security/security-middleware.js';
import { AuditLogger } from '../security/audit-logger.js';
import { PHILevel } from '../types/phi-types.js';

describe('Security Integration Tests', () => {
  let inputValidator: InputValidator;
  let rateLimiter: RateLimiter;
  let securityHeaders: SecurityHeadersManager;
  let securityMiddleware: SecurityMiddleware;
  let auditLogger: AuditLogger;

  beforeEach(() => {
    inputValidator = new InputValidator();
    rateLimiter = new RateLimiter();
    securityHeaders = new SecurityHeadersManager({ healthcareCompliant: true });
    auditLogger = new AuditLogger(true);
    securityMiddleware = new SecurityMiddleware({
      healthcareCompliant: true,
      enableInputValidation: true,
      enableRateLimiting: true,
      enableSecurityHeaders: true,
      enableAuditLogging: true
    }, auditLogger);
  });

  describe('Input Validation', () => {
    test('should validate FHIR search parameters correctly', () => {
      const validParams = {
        resourceType: 'Patient',
        params: {
          given: 'John',
          family: 'Doe'
        }
      };

      const result = inputValidator.validateSearchParams(validParams.resourceType, validParams.params);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    test('should reject invalid resource types', () => {
      const invalidParams = {
        resourceType: 'InvalidResourceType',
        params: {}
      };

      const result = inputValidator.validateSearchParams(invalidParams.resourceType, invalidParams.params);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid or missing resourceType');
    });

    test('should sanitize potentially harmful input', () => {
      const maliciousResource = {
        resourceType: 'Patient',
        name: [{
          given: ['<script>alert("xss")</script>'],
          family: 'Doe'
        }]
      };

      const result = inputValidator.validateFhirResource(maliciousResource);
      expect(result.valid).toBe(true);
      expect(result.sanitizedData?.name[0].given[0]).not.toContain('<script>');
    });

    test('should detect SQL injection attempts', () => {
      const sqlInjectionAttempt = {
        resourceType: 'Patient',
        params: {
          name: "'; DROP TABLE patients; --"
        }
      };

      const result = inputValidator.validateSearchParams(sqlInjectionAttempt.resourceType, sqlInjectionAttempt.params);
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Invalid value for parameter: name');
    });

    test('should enforce field length limits', () => {
      const longFieldResource = {
        resourceType: 'Patient',
        name: [{
          given: ['A'.repeat(20000)], // Extremely long name
          family: 'Doe'
        }]
      };

      const result = inputValidator.validateFhirResource(longFieldResource);
      expect(result.sanitizedData?.name[0].given[0]).toHaveLength(10000); // Should be truncated
    });
  });

  describe('Rate Limiting', () => {
    test('should allow requests within rate limits', () => {
      const request = {
        userId: 'user-123',
        sessionId: 'session-123',
        operation: 'fhir.search',
        resourceType: 'Patient',
        phiLevel: PHILevel.IDENTIFIABLE
      };

      const result = rateLimiter.checkRateLimit(request);
      expect(result.allowed).toBe(true);
      expect(result.remainingRequests).toBeGreaterThan(0);
    });

    test('should block excessive requests', () => {
      const request = {
        userId: 'user-excessive',
        sessionId: 'session-excessive',
        operation: 'fhir.search',
        resourceType: 'Patient',
        phiLevel: PHILevel.IDENTIFIABLE
      };

      // Make requests up to the limit (20 for PHI access)
      let lastResult;
      for (let i = 0; i < 25; i++) {
        lastResult = rateLimiter.checkRateLimit(request);
      }

      expect(lastResult?.allowed).toBe(false);
      expect(lastResult?.reason).toBe('RATE_LIMIT_EXCEEDED');
    });

    test('should apply different limits for different operations', () => {
      const searchRequest = {
        userId: 'user-limits',
        sessionId: 'session-limits',
        operation: 'fhir.search',
        resourceType: 'ValueSet',
        phiLevel: PHILevel.NONE
      };

      const writeRequest = {
        userId: 'user-limits',
        sessionId: 'session-limits',
        operation: 'fhir.create',
        resourceType: 'Patient',
        phiLevel: PHILevel.IDENTIFIABLE
      };

      const searchResult = rateLimiter.checkRateLimit(searchRequest);
      const writeResult = rateLimiter.checkRateLimit(writeRequest);

      expect(searchResult.remainingRequests).toBeGreaterThan(writeResult.remainingRequests);
    });

    test('should detect suspicious rapid-fire requests', () => {
      const rapidRequests = Array.from({ length: 10 }, () => ({
        userId: 'rapid-user',
        sessionId: 'rapid-session',
        operation: 'fhir.search',
        resourceType: 'Patient',
        phiLevel: PHILevel.IDENTIFIABLE
      }));

      // Send requests in rapid succession
      const results = rapidRequests.map(req => rateLimiter.checkRateLimit(req));
      
      // Should eventually be blocked due to suspicious activity
      const blockedResults = results.filter(r => !r.allowed);
      expect(blockedResults.length).toBeGreaterThan(0);
    });
  });

  describe('Security Headers', () => {
    test('should generate healthcare-compliant security headers', () => {
      const headers = securityHeaders.generateHeaders();

      expect(headers['Content-Security-Policy']).toBeDefined();
      expect(headers['Strict-Transport-Security']).toBeDefined();
      expect(headers['X-Frame-Options']).toBe('DENY');
      expect(headers['X-Content-Type-Options']).toBe('nosniff');
      expect(headers['Referrer-Policy']).toBe('no-referrer'); // Strictest for healthcare
      expect(headers['X-Healthcare-Compliant']).toBe('true');
    });

    test('should include PHI protection headers', () => {
      const headers = securityHeaders.generateHeaders();

      expect(headers['X-PHI-Protection']).toBe('enabled');
      expect(headers['Cache-Control']).toContain('no-store');
      expect(headers['Cache-Control']).toContain('no-cache');
    });

    test('should generate restrictive CORS headers for healthcare', () => {
      const corsHeaders = securityHeaders.generateCORSHeaders();

      expect(corsHeaders['Access-Control-Allow-Origin']).toBe('null');
      expect(corsHeaders['Access-Control-Allow-Credentials']).toBe('false');
      expect(corsHeaders['Access-Control-Max-Age']).toBe('300'); // Short cache time
    });

    test('should validate request security requirements', () => {
      const secureRequest = {
        headers: {
          'user-agent': 'Mozilla/5.0 (legitimate browser)',
          'authorization': 'Bearer valid-token'
        },
        method: 'GET',
        url: 'https://api.example.com/Patient/123',
        userAgent: 'Mozilla/5.0 (legitimate browser)'
      };

      const result = securityHeaders.validateRequest(secureRequest);
      expect(result.valid).toBe(true);
      expect(result.riskLevel).toBe('low');
    });

    test('should detect suspicious requests', () => {
      const suspiciousRequest = {
        headers: {
          'user-agent': 'bot/1.0'
        },
        method: 'GET',
        url: 'https://api.example.com/Patient/123',
        userAgent: 'bot/1.0'
      };

      const result = securityHeaders.validateRequest(suspiciousRequest);
      expect(result.valid).toBe(false);
      expect(result.violations).toContain('Suspicious User-Agent detected');
      expect(result.riskLevel).toBe('medium');
    });
  });

  describe('Security Middleware Integration', () => {
    test('should process secure requests successfully', async () => {
      const securityContext = {
        sessionId: 'test-session-123',
        operation: 'fhir.search',
        resourceType: 'ValueSet',
        phiLevel: PHILevel.NONE
      };

      const requestData = {
        resourceType: 'ValueSet',
        params: { status: 'active' }
      };

      const result = await securityMiddleware.processRequest(securityContext, requestData);

      expect(result.allowed).toBe(true);
      expect(result.validatedInput).toBeDefined();
      expect(result.headers).toBeDefined();
      expect(result.rateLimitInfo?.allowed).toBe(true);
    });

    test('should block PHI access without proper authorization', async () => {
      const securityContext = {
        sessionId: 'unauthorized-session',
        operation: 'fhir.search',
        resourceType: 'Patient',
        phiLevel: PHILevel.IDENTIFIABLE
      };

      const requestData = {
        resourceType: 'Patient',
        params: { given: 'John' }
      };

      const result = await securityMiddleware.processRequest(securityContext, requestData);

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('HEALTHCARE_COMPLIANCE_VIOLATION');
      expect(result.riskLevel).toBe('high');
    });

    test('should handle emergency access properly', async () => {
      const securityContext = {
        userId: 'emergency-user',
        sessionId: 'emergency-session',
        operation: 'fhir.read',
        resourceType: 'Patient',
        phiLevel: PHILevel.IDENTIFIABLE,
        isEmergencyAccess: true
      };

      const emergencyResult = await securityMiddleware.handleEmergencyBypass(
        securityContext,
        'Critical patient emergency - immediate access needed for life-threatening condition'
      );

      expect(emergencyResult.allowed).toBe(true);
      expect(emergencyResult.reason).toBe('EMERGENCY_BYPASS_GRANTED');
      expect(emergencyResult.headers?.['X-Emergency-Access']).toBe('true');
    });

    test('should validate input and reject malicious content', async () => {
      const securityContext = {
        sessionId: 'malicious-session',
        operation: 'fhir.create',
        resourceType: 'Patient',
        phiLevel: PHILevel.IDENTIFIABLE
      };

      const maliciousData = {
        resourceType: 'Patient',
        resource: {
          name: [{
            given: ["<script>alert('xss')</script>"],
            family: "'; DROP TABLE patients; --"
          }]
        }
      };

      const result = await securityMiddleware.processRequest(securityContext, maliciousData);

      if (result.allowed) {
        // If allowed (after proper auth), should be sanitized
        expect(result.validatedInput?.resource.name[0].given[0]).not.toContain('<script>');
      } else {
        // Or should be blocked entirely
        expect(result.reason).toBe('INPUT_VALIDATION_FAILED');
      }
    });

    test('should enforce rate limits across middleware', async () => {
      const baseContext = {
        userId: 'rate-limit-test-user',
        sessionId: 'rate-limit-session',
        operation: 'fhir.search',
        resourceType: 'Patient',
        phiLevel: PHILevel.IDENTIFIABLE
      };

      const requestData = {
        resourceType: 'Patient',
        params: { status: 'active' }
      };

      // Send many requests rapidly
      const results = [];
      for (let i = 0; i < 25; i++) {
        const context = { ...baseContext, sessionId: `${baseContext.sessionId}-${i}` };
        results.push(await securityMiddleware.processRequest(context, requestData));
      }

      // Should have some blocked requests due to rate limiting
      const blockedCount = results.filter(r => !r.allowed && r.reason?.includes('RATE_LIMIT')).length;
      expect(blockedCount).toBeGreaterThan(0);
    });
  });

  describe('Performance and Scalability', () => {
    test('should process security checks within performance thresholds', async () => {
      const securityContext = {
        sessionId: 'performance-test',
        operation: 'fhir.search',
        resourceType: 'ValueSet',
        phiLevel: PHILevel.NONE
      };

      const requestData = {
        resourceType: 'ValueSet',
        params: { status: 'active' }
      };

      const startTime = Date.now();
      const result = await securityMiddleware.processRequest(securityContext, requestData);
      const duration = Date.now() - startTime;

      expect(result.allowed).toBe(true);
      expect(duration).toBeLessThan(100); // Should complete within 100ms
    });

    test('should handle concurrent requests efficiently', async () => {
      const promises = Array.from({ length: 50 }, (_, i) => {
        const securityContext = {
          sessionId: `concurrent-${i}`,
          operation: 'fhir.search',
          resourceType: 'ValueSet',
          phiLevel: PHILevel.NONE
        };

        const requestData = {
          resourceType: 'ValueSet',
          params: { status: 'active' }
        };

        return securityMiddleware.processRequest(securityContext, requestData);
      });

      const startTime = Date.now();
      const results = await Promise.all(promises);
      const duration = Date.now() - startTime;

      expect(results).toHaveLength(50);
      expect(results.filter(r => r.allowed)).toHaveLength(50);
      expect(duration).toBeLessThan(2000); // Should complete within 2 seconds
    });
  });

  describe('Audit and Compliance', () => {
    test('should log all security events properly', async () => {
      // Mock console.log to capture audit logs
      const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});

      const securityContext = {
        userId: 'audit-test-user',
        sessionId: 'audit-session',
        operation: 'fhir.read',
        resourceType: 'Patient',
        phiLevel: PHILevel.IDENTIFIABLE
      };

      await securityMiddleware.processRequest(securityContext, {
        resourceType: 'Patient',
        id: 'test-patient'
      });

      // Should have logged security events
      expect(logSpy).toHaveBeenCalled();
      
      const auditLogs = logSpy.mock.calls
        .map(call => call[0])
        .filter(log => typeof log === 'string' && log.includes('security.'));

      expect(auditLogs.length).toBeGreaterThan(0);

      logSpy.mockRestore();
    });

    test('should provide comprehensive security statistics', () => {
      const stats = securityMiddleware.getStats();

      expect(stats).toHaveProperty('inputValidation');
      expect(stats).toHaveProperty('rateLimiting');
      expect(stats).toHaveProperty('securityHeaders');
      expect(stats.securityHeaders).toHaveProperty('complianceLevel');
      expect(stats.securityHeaders.complianceLevel).toBe('healthcare');
    });

    test('should generate security compliance report', () => {
      const report = securityHeaders.generateSecurityReport();

      expect(report.complianceLevel).toBe('healthcare');
      expect(report.configuration.healthcareCompliant).toBe(true);
      expect(report.headers['X-Healthcare-Compliant']).toBe('true');
      expect(report.headers['X-PHI-Protection']).toBe('enabled');
      expect(report.recommendations).toBeInstanceOf(Array);
    });
  });
});