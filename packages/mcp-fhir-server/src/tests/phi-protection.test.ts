import { describe, test, expect, beforeEach } from '@jest/globals';
import { PHIClassifier } from '../security/phi-classifier.js';
import { PHIMaskingEngine } from '../security/phi-masking-engine.js';
import { PHIAuthorizationEngine } from '../security/phi-authorization-engine.js';
import { AuditLogger } from '../security/audit-logger.js';
import {
  PHILevel,
  PHIProtectionConfig,
  User,
  MaskingRule
} from '../types/phi-types.js';

describe('PHI Protection System', () => {
  let phiClassifier: PHIClassifier;
  let maskingEngine: PHIMaskingEngine;
  let authEngine: PHIAuthorizationEngine;
  let auditLogger: AuditLogger;
  let phiConfig: PHIProtectionConfig;

  beforeEach(() => {
    phiClassifier = new PHIClassifier();
    maskingEngine = new PHIMaskingEngine();
    auditLogger = new AuditLogger(true);
    
    phiConfig = {
      enabled: true,
      mode: 'strict',
      allowEmergencyAccess: true,
      emergencyAccessDurationMinutes: 30,
      auditAllAccess: true,
      defaultMaskingRules: [],
      resourceOverrides: {}
    };
    
    authEngine = new PHIAuthorizationEngine(phiConfig, auditLogger);
  });

  describe('PHI Classification', () => {
    test('should classify Patient resource as IDENTIFIABLE', () => {
      const patientResource = {
        resourceType: 'Patient',
        id: 'patient-123',
        name: [{
          family: 'Doe',
          given: ['John']
        }],
        birthDate: '1980-01-01',
        identifier: [{
          system: 'http://hospital.smarthealthit.org',
          value: 'MRN123456'
        }]
      };

      const classification = phiClassifier.classifyResource(patientResource);
      expect(classification.phiLevel).toBe(PHILevel.IDENTIFIABLE);
      expect(classification.identifiableFields.length).toBeGreaterThan(0);
      expect(classification.resourceType).toBe('Patient');
    });

    test('should classify ValueSet resource as NONE', () => {
      const valueSetResource = {
        resourceType: 'ValueSet',
        id: 'example-valueset',
        url: 'http://hl7.org/fhir/ValueSet/example',
        name: 'ExampleValueSet',
        status: 'active'
      };

      const classification = phiClassifier.classifyResource(valueSetResource);
      expect(classification.phiLevel).toBe(PHILevel.NONE);
      expect(classification.allowedOperations).toContain('read');
    });

    test('should classify Organization resource as MINIMAL', () => {
      const orgResource = {
        resourceType: 'Organization',
        id: 'org-123',
        name: 'Test Hospital',
        type: [{
          coding: [{
            system: 'http://terminology.hl7.org/CodeSystem/organization-type',
            code: 'prov'
          }]
        }]
      };

      const classification = phiClassifier.classifyResource(orgResource);
      expect(classification.phiLevel).toBe(PHILevel.MINIMAL);
      expect(classification.requiredMasking.length).toBeGreaterThan(0);
    });
  });

  describe('PHI Masking Engine', () => {
    test('should remove fields correctly', () => {
      const resource = {
        resourceType: 'Patient',
        name: 'John Doe',
        birthDate: '1980-01-01',
        address: 'Secret Location'
      };

      const maskingRules: MaskingRule[] = [
        { field: 'birthDate', maskingType: 'remove' },
        { field: 'address', maskingType: 'remove' }
      ];

      const masked = maskingEngine.applyMasking(resource, maskingRules);
      expect(masked.birthDate).toBeUndefined();
      expect(masked.address).toBeUndefined();
      expect(masked.name).toBe('John Doe'); // Unchanged
    });

    test('should replace fields with masked values', () => {
      const resource = {
        resourceType: 'Patient',
        name: 'John Doe',
        ssn: '123-45-6789'
      };

      const maskingRules: MaskingRule[] = [
        { field: 'name', maskingType: 'replace', replacement: '***' },
        { field: 'ssn', maskingType: 'replace', replacement: 'MASKED' }
      ];

      const masked = maskingEngine.applyMasking(resource, maskingRules);
      expect(masked.name).toBe('***');
      expect(masked.ssn).toBe('MASKED');
    });

    test('should hash fields consistently', () => {
      const resource = {
        resourceType: 'Patient',
        identifier: 'patient-123'
      };

      const maskingRules: MaskingRule[] = [
        { field: 'identifier', maskingType: 'hash' }
      ];

      const masked1 = maskingEngine.applyMasking(resource, maskingRules);
      const masked2 = maskingEngine.applyMasking(resource, maskingRules);
      
      expect(masked1.identifier).toBe(masked2.identifier);
      expect(masked1.identifier).not.toBe('patient-123');
      expect(typeof masked1.identifier).toBe('string');
    });

    test('should apply partial masking preserving format', () => {
      const resource = {
        resourceType: 'Patient',
        email: 'john.doe@example.com',
        phone: '555-123-4567'
      };

      const maskingRules: MaskingRule[] = [
        { field: 'email', maskingType: 'partial', preserveFormat: true },
        { field: 'phone', maskingType: 'partial', preserveFormat: true }
      ];

      const masked = maskingEngine.applyMasking(resource, maskingRules);
      expect(masked.email).toContain('@example.com');
      expect(masked.email).toContain('j***');
      expect(masked.phone).toMatch(/555-\*+-4567/);
    });
  });

  describe('PHI Authorization Engine', () => {
    test('should block access to identifiable resources in strict mode', async () => {
      const patientResource = {
        resourceType: 'Patient',
        id: 'patient-123',
        name: [{ family: 'Doe', given: ['John'] }]
      };

      const result = await authEngine.authorizeResourceAccess(
        undefined, // No user
        patientResource,
        'read',
        'test-session'
      );

      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('PHI_PROTECTION_ENABLED');
    });

    test('should allow access to non-PHI resources', async () => {
      const valueSetResource = {
        resourceType: 'ValueSet',
        id: 'example-valueset',
        url: 'http://hl7.org/fhir/ValueSet/example'
      };

      const result = await authEngine.authorizeResourceAccess(
        undefined,
        valueSetResource,
        'read',
        'test-session'
      );

      expect(result.allowed).toBe(true);
    });

    test('should allow masked access to minimal PHI resources', async () => {
      const orgResource = {
        resourceType: 'Organization',
        id: 'org-123',
        name: 'Test Hospital'
      };

      const result = await authEngine.authorizeResourceAccess(
        undefined,
        orgResource,
        'read',
        'test-session'
      );

      expect(result.allowed).toBe(true);
      expect(result.requiresMasking).toBe(true);
      expect(result.maskingRules?.length).toBeGreaterThan(0);
    });

    test('should allow access for users with patient-level permissions', async () => {
      const user: User = {
        id: 'clinician-123',
        roles: ['clinician'],
        permissions: ['patient:read'],
        phiAccessLevel: PHILevel.IDENTIFIABLE
      };

      const patientResource = {
        resourceType: 'Patient',
        id: 'patient-123',
        name: [{ family: 'Doe', given: ['John'] }]
      };

      const result = await authEngine.authorizeResourceAccess(
        user,
        patientResource,
        'read',
        'test-session'
      );

      expect(result.allowed).toBe(true);
    });

    test('should handle emergency access requests', async () => {
      const user: User = {
        id: 'doctor-123',
        roles: ['physician'],
        permissions: ['emergency:access'],
        emergencyAccessEnabled: true
      };

      const grant = await authEngine.requestEmergencyAccess(
        user,
        'Patient',
        'patient-123',
        'Emergency cardiac event - immediate patient access needed for life-threatening situation'
      );

      expect(grant.userId).toBe(user.id);
      expect(grant.resourceType).toBe('Patient');
      expect(grant.resourceId).toBe('patient-123');
      expect(grant.justification).toContain('Emergency');
      expect(grant.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    test('should reject invalid emergency access requests', async () => {
      const user: User = {
        id: 'user-123',
        roles: ['user'],
        permissions: [],
        emergencyAccessEnabled: false
      };

      await expect(
        authEngine.requestEmergencyAccess(
          user,
          'Patient',
          'patient-123',
          'I want to see this patient'
        )
      ).rejects.toThrow('User does not have emergency access permissions');
    });
  });

  describe('Integration Tests', () => {
    test('should provide complete PHI protection workflow', async () => {
      // Test patient resource
      const patientResource = {
        resourceType: 'Patient',
        id: 'patient-123',
        name: [{
          family: 'Smith',
          given: ['Jane']
        }],
        birthDate: '1975-05-15',
        address: [{
          line: ['123 Main St'],
          city: 'Anytown',
          state: 'CA',
          postalCode: '12345'
        }],
        telecom: [{
          system: 'phone',
          value: '+1-555-123-4567'
        }]
      };

      // 1. Classification
      const classification = phiClassifier.classifyResource(patientResource);
      expect(classification.phiLevel).toBe(PHILevel.IDENTIFIABLE);

      // 2. Authorization (should be denied without proper user)
      const authResult = await authEngine.authorizeResourceAccess(
        undefined,
        patientResource,
        'read',
        'integration-test'
      );
      expect(authResult.allowed).toBe(false);

      // 3. Authorization with proper user
      const authorizedUser: User = {
        id: 'doctor-456',
        roles: ['clinician'],
        permissions: ['patient:read'],
        phiAccessLevel: PHILevel.IDENTIFIABLE
      };

      const authorizedResult = await authEngine.authorizeResourceAccess(
        authorizedUser,
        patientResource,
        'read',
        'integration-test-authorized'
      );
      expect(authorizedResult.allowed).toBe(true);

      // 4. Masking is MANDATORY for an identifiable resource, not conditional.
      //    This block used to sit behind
      //    `if (authorizedResult.requiresMasking && authorizedResult.maskingRules)`.
      //    Before the authorization-engine fix, strict mode returned
      //    { allowed: true } with NEITHER field set for a privileged user, so the
      //    guard was always false and these assertions never executed once. The
      //    test passed by never running its own body. The conditional is removed
      //    so it cannot go vacuous again.
      expect(authorizedResult.requiresMasking).toBe(true);
      expect(authorizedResult.maskingRules?.length ?? 0).toBeGreaterThan(0);

      const maskedResource = authEngine.applyMasking(patientResource, authorizedResult);
      // { field: 'name', maskingType: 'replace', replacement: '***' } replaces
      // the whole `name` element, not `name[0].family`.
      expect(maskedResource.name).toBe('***');
      expect(maskedResource.address).toBeUndefined();
      expect(maskedResource.telecom).toBeUndefined();
      expect(JSON.stringify(maskedResource)).not.toContain('Smith');
    });

    test('should handle mixed resource bundles correctly', async () => {
      const resources = [
        { resourceType: 'Patient', id: 'p1', name: [{ family: 'Doe' }] },
        { resourceType: 'ValueSet', id: 'vs1', url: 'http://example.com/vs1' },
        { resourceType: 'Organization', id: 'org1', name: 'Hospital' }
      ];

      const results = [];
      for (const resource of resources) {
        const authResult = await authEngine.authorizeResourceAccess(
          undefined,
          resource,
          'read',
          'bundle-test'
        );
        
        if (authResult.allowed) {
          const finalResource = authResult.requiresMasking 
            ? authEngine.applyMasking(resource, authResult)
            : resource;
          results.push(finalResource);
        }
      }

      // Should only include ValueSet (allowed) and Organization (masked)
      expect(results.length).toBe(2);
      expect(results.find(r => r.resourceType === 'Patient')).toBeUndefined();
      expect(results.find(r => r.resourceType === 'ValueSet')).toBeDefined();
      expect(results.find(r => r.resourceType === 'Organization')).toBeDefined();
    });
  });

  describe('Performance Tests', () => {
    test('should classify resources within performance threshold', () => {
      const patientResource = {
        resourceType: 'Patient',
        id: 'perf-test',
        name: [{ family: 'TestPatient' }]
      };

      const startTime = Date.now();
      
      // Classify 100 resources
      for (let i = 0; i < 100; i++) {
        phiClassifier.classifyResource({
          ...patientResource,
          id: `perf-test-${i}`
        });
      }
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(500); // Should complete within 500ms
    });

    test('should authorize resources within performance threshold', async () => {
      const valueSetResource = {
        resourceType: 'ValueSet',
        id: 'perf-test-vs'
      };

      const startTime = Date.now();
      
      // Authorize 50 resources
      const promises = [];
      for (let i = 0; i < 50; i++) {
        promises.push(
          authEngine.authorizeResourceAccess(
            undefined,
            { ...valueSetResource, id: `perf-test-vs-${i}` },
            'read',
            `perf-session-${i}`
          )
        );
      }
      
      await Promise.all(promises);
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(1000); // Should complete within 1000ms
    });
  });
});
