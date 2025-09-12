import {
  PHILevel,
  PHIClassificationResult,
  AuthorizationResult,
  User,
  PHIProtectionConfig,
  PHIProtectionError,
  EmergencyAccessGrant,
  AuditMetadata,
  RESOURCE_PHI_MATRIX
} from '../types/phi-types.js';
import { PHIClassifier } from './phi-classifier.js';
import { PHIMaskingEngine } from './phi-masking-engine.js';
import { AuditLogger } from './audit-logger.js';

/**
 * PHI Authorization Engine
 * Core component that enforces PHI protection policies and access controls
 */
export class PHIAuthorizationEngine {
  private phiClassifier: PHIClassifier;
  private maskingEngine: PHIMaskingEngine;
  private auditLogger: AuditLogger;
  private emergencyGrants = new Map<string, EmergencyAccessGrant>();
  private config: PHIProtectionConfig;

  constructor(
    config: PHIProtectionConfig,
    auditLogger: AuditLogger
  ) {
    this.config = config;
    this.phiClassifier = new PHIClassifier();
    this.maskingEngine = new PHIMaskingEngine();
    this.auditLogger = auditLogger;

    // Clean up expired emergency grants every 5 minutes
    setInterval(() => this.cleanupExpiredGrants(), 5 * 60 * 1000);
  }

  /**
   * Main authorization check for resource access
   */
  public async authorizeResourceAccess(
    user: User | undefined,
    resource: any,
    operation: string,
    sessionId: string = 'unknown'
  ): Promise<AuthorizationResult> {
    const startTime = Date.now();
    
    try {
      // Classify the resource
      const classification = this.phiClassifier.classifyResource(resource);
      
      // Create audit metadata
      const auditMetadata: AuditMetadata = {
        timestamp: new Date(),
        userId: user?.id,
        sessionId,
        resourceType: resource.resourceType,
        resourceId: resource.id,
        operation,
        phiLevel: classification.phiLevel,
        accessGranted: false // Will be updated based on decision
      };

      // Check if PHI protection is disabled
      if (!this.config.enabled) {
        auditMetadata.accessGranted = true;
        await this.auditLogger.log({
          operation: `phi_authorization_${operation}`,
          success: true,
          duration: Date.now() - startTime,
          metadata: auditMetadata
        });
        
        return {
          allowed: true,
          auditMetadata
        };
      }

      // Check for emergency access override
      const emergencyGrant = this.checkEmergencyAccess(user, resource, operation);
      if (emergencyGrant) {
        auditMetadata.accessGranted = true;
        auditMetadata.emergencyAccess = true;
        auditMetadata.justification = emergencyGrant.justification;
        
        await this.auditLogger.log({
          operation: `phi_emergency_access_${operation}`,
          success: true,
          duration: Date.now() - startTime,
          metadata: auditMetadata
        });

        return {
          allowed: true,
          auditMetadata,
          reason: 'EMERGENCY_ACCESS_GRANTED'
        };
      }

      // Apply PHI protection rules
      const authResult = await this.applyPHIProtectionRules(
        user,
        resource,
        operation,
        classification,
        auditMetadata
      );

      // Log the authorization decision
      await this.auditLogger.log({
        operation: `phi_authorization_${operation}`,
        success: authResult.allowed,
        duration: Date.now() - startTime,
        metadata: auditMetadata,
        error: authResult.allowed ? undefined : authResult.reason
      });

      return authResult;

    } catch (error) {
      // Log authorization errors
      await this.auditLogger.log({
        operation: `phi_authorization_${operation}`,
        success: false,
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      throw error;
    }
  }

  /**
   * Apply PHI protection rules based on classification
   */
  private async applyPHIProtectionRules(
    user: User | undefined,
    resource: any,
    operation: string,
    classification: PHIClassificationResult,
    auditMetadata: AuditMetadata
  ): Promise<AuthorizationResult> {
    
    // Handle different PHI levels
    switch (classification.phiLevel) {
      case PHILevel.NONE:
        // Always allow access to non-PHI resources
        auditMetadata.accessGranted = true;
        return {
          allowed: true,
          auditMetadata
        };

      case PHILevel.MINIMAL:
        // Allow with masking for minimal PHI
        auditMetadata.accessGranted = true;
        return {
          allowed: true,
          requiresMasking: true,
          maskingRules: classification.requiredMasking,
          auditMetadata
        };

      case PHILevel.IDENTIFIABLE:
        return await this.handleIdentifiableResource(
          user,
          resource,
          operation,
          classification,
          auditMetadata
        );

      case PHILevel.RESTRICTED:
        return await this.handleRestrictedResource(
          user,
          resource,
          operation,
          classification,
          auditMetadata
        );

      default:
        auditMetadata.accessGranted = false;
        return {
          allowed: false,
          reason: 'UNKNOWN_PHI_LEVEL',
          message: `Unknown PHI level: ${classification.phiLevel}`,
          auditMetadata
        };
    }
  }

  /**
   * Handle access to patient-identifiable resources
   */
  private async handleIdentifiableResource(
    user: User | undefined,
    resource: any,
    operation: string,
    classification: PHIClassificationResult,
    auditMetadata: AuditMetadata
  ): Promise<AuthorizationResult> {
    
    // Block access in strict mode unless user has special permissions
    if (this.config.mode === 'strict') {
      if (!this.hasPatientLevelAccess(user)) {
        auditMetadata.accessGranted = false;
        return {
          allowed: false,
          reason: 'PHI_PROTECTION_ENABLED',
          message: 'Access to patient-identifiable resources blocked in PHI protection mode',
          auditMetadata
        };
      }
    }

    // In permissive mode, allow with heavy masking
    if (this.config.mode === 'permissive') {
      auditMetadata.accessGranted = true;
      return {
        allowed: true,
        requiresMasking: true,
        maskingRules: classification.requiredMasking,
        auditMetadata
      };
    }

    // In audit-only mode, allow but log everything
    if (this.config.mode === 'audit-only') {
      auditMetadata.accessGranted = true;
      return {
        allowed: true,
        auditMetadata
      };
    }

    // Default: require special permissions
    if (!this.hasPatientLevelAccess(user)) {
      auditMetadata.accessGranted = false;
      return {
        allowed: false,
        reason: 'INSUFFICIENT_PERMISSIONS',
        message: 'Patient-level access permissions required',
        auditMetadata
      };
    }

    auditMetadata.accessGranted = true;
    return {
      allowed: true,
      auditMetadata
    };
  }

  /**
   * Handle access to restricted resources
   */
  private async handleRestrictedResource(
    user: User | undefined,
    resource: any,
    operation: string,
    classification: PHIClassificationResult,
    auditMetadata: AuditMetadata
  ): Promise<AuthorizationResult> {
    
    // Always require special permissions for restricted resources
    if (!this.hasRestrictedAccess(user)) {
      auditMetadata.accessGranted = false;
      return {
        allowed: false,
        reason: 'RESTRICTED_RESOURCE',
        message: 'Special permissions required for restricted resources',
        auditMetadata
      };
    }

    auditMetadata.accessGranted = true;
    return {
      allowed: true,
      requiresMasking: true,
      maskingRules: classification.requiredMasking,
      auditMetadata
    };
  }

  /**
   * Check if user has patient-level access permissions
   */
  private hasPatientLevelAccess(user: User | undefined): boolean {
    if (!user) return false;
    
    return user.permissions.includes('patient:read') ||
           user.permissions.includes('patient:*') ||
           user.roles.includes('clinician') ||
           user.roles.includes('admin') ||
           user.phiAccessLevel === PHILevel.IDENTIFIABLE;
  }

  /**
   * Check if user has restricted resource access
   */
  private hasRestrictedAccess(user: User | undefined): boolean {
    if (!user) return false;
    
    return user.permissions.includes('restricted:read') ||
           user.permissions.includes('admin:*') ||
           user.roles.includes('admin') ||
           user.phiAccessLevel === PHILevel.RESTRICTED;
  }

  /**
   * Request emergency access to PHI resources
   */
  public async requestEmergencyAccess(
    user: User,
    resourceType: string,
    resourceId: string,
    justification: string
  ): Promise<EmergencyAccessGrant> {
    
    if (!this.config.allowEmergencyAccess) {
      throw new PHIProtectionError(
        'Emergency access is not enabled',
        PHILevel.IDENTIFIABLE,
        resourceType,
        'emergency_access'
      );
    }

    if (!user.emergencyAccessEnabled) {
      throw new PHIProtectionError(
        'User does not have emergency access permissions',
        PHILevel.IDENTIFIABLE,
        resourceType,
        'emergency_access'
      );
    }

    // Validate emergency justification
    if (!this.validateEmergencyJustification(justification)) {
      throw new PHIProtectionError(
        'Invalid emergency access justification',
        PHILevel.IDENTIFIABLE,
        resourceType,
        'emergency_access'
      );
    }

    // Create emergency access grant
    const grant: EmergencyAccessGrant = {
      grantId: this.generateGrantId(),
      userId: user.id,
      resourceId,
      resourceType,
      grantedAt: new Date(),
      expiresAt: new Date(Date.now() + this.config.emergencyAccessDurationMinutes * 60 * 1000),
      justification,
      auditTrail: true
    };

    // Store the grant
    this.emergencyGrants.set(grant.grantId, grant);

    // Log emergency access request
    await this.auditLogger.log({
      operation: 'phi_emergency_access_granted',
      success: true,
      metadata: {
        userId: user.id,
        resourceType,
        resourceId,
        grantId: grant.grantId,
        justification,
        expiresAt: grant.expiresAt
      }
    });

    return grant;
  }

  /**
   * Check for emergency access override
   */
  private checkEmergencyAccess(
    user: User | undefined,
    resource: any,
    operation: string
  ): EmergencyAccessGrant | null {
    
    if (!user || !this.config.allowEmergencyAccess) {
      return null;
    }

    // Find active emergency grants for this user and resource
    for (const grant of this.emergencyGrants.values()) {
      if (grant.userId === user.id &&
          grant.resourceType === resource.resourceType &&
          (grant.resourceId === resource.id || grant.resourceId === '*') &&
          grant.expiresAt > new Date()) {
        return grant;
      }
    }

    return null;
  }

  /**
   * Validate emergency access justification
   */
  private validateEmergencyJustification(justification: string): boolean {
    if (!justification || justification.length < 10) {
      return false;
    }

    // Check for valid emergency keywords
    const emergencyKeywords = [
      'emergency',
      'urgent',
      'critical',
      'life-threatening',
      'immediate care',
      'patient safety'
    ];

    const lowerJustification = justification.toLowerCase();
    return emergencyKeywords.some(keyword => 
      lowerJustification.includes(keyword)
    );
  }

  /**
   * Generate unique grant ID
   */
  private generateGrantId(): string {
    return `phi_grant_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Clean up expired emergency grants
   */
  private cleanupExpiredGrants(): void {
    const now = new Date();
    for (const [grantId, grant] of this.emergencyGrants.entries()) {
      if (grant.expiresAt <= now) {
        this.emergencyGrants.delete(grantId);
      }
    }
  }

  /**
   * Apply masking to resource based on authorization result
   */
  public applyMasking(resource: any, authResult: AuthorizationResult): any {
    if (!authResult.requiresMasking || !authResult.maskingRules) {
      return resource;
    }

    return this.maskingEngine.applyMasking(resource, authResult.maskingRules);
  }

  /**
   * Update PHI protection configuration
   */
  public updateConfig(newConfig: Partial<PHIProtectionConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Get current PHI protection status
   */
  public getStatus(): {
    enabled: boolean;
    mode: string;
    activeEmergencyGrants: number;
    classificationCacheSize: number;
  } {
    return {
      enabled: this.config.enabled,
      mode: this.config.mode,
      activeEmergencyGrants: this.emergencyGrants.size,
      classificationCacheSize: this.phiClassifier.getCacheStats().size
    };
  }

  /**
   * Clear all caches and reset state
   */
  public reset(): void {
    this.phiClassifier.clearCache();
    this.maskingEngine.clearCache();
    this.emergencyGrants.clear();
  }
}