// PHI-aware authorization system types and interfaces

export enum PHILevel {
  NONE = 'none',           // No patient identifiers
  MINIMAL = 'minimal',     // Aggregated/anonymized data
  IDENTIFIABLE = 'identifiable', // Contains patient identifiers
  RESTRICTED = 'restricted' // Highly sensitive PHI
}

export interface PHIClassificationResult {
  resourceType: string;
  phiLevel: PHILevel;
  identifiableFields: string[];
  sensitiveFields: string[];
  allowedOperations: string[];
  requiredMasking: MaskingRule[];
  riskScore: number;
}

export interface MaskingRule {
  field: string;
  maskingType: 'remove' | 'hash' | 'partial' | 'aggregate' | 'replace';
  preserveFormat?: boolean;
  replacement?: string;
  condition?: string;
}

export interface AuthorizationResult {
  allowed: boolean;
  reason?: string;
  message?: string;
  requiresMasking?: boolean;
  maskingRules?: MaskingRule[];
  auditMetadata?: AuditMetadata;
}

export interface AuditMetadata {
  timestamp: Date;
  userId?: string;
  sessionId: string;
  resourceType: string;
  resourceId?: string;
  operation: string;
  phiLevel: PHILevel;
  accessGranted: boolean;
  emergencyAccess?: boolean;
  justification?: string;
  [key: string]: any; // Index signature for additional properties
}

export interface EmergencyAccessGrant {
  userId: string;
  resourceId: string;
  resourceType: string;
  grantedAt: Date;
  expiresAt: Date;
  justification: string;
  auditTrail: boolean;
  grantId: string;
}

export interface User {
  id: string;
  roles: string[];
  permissions: string[];
  emergencyAccessEnabled?: boolean;
  phiAccessLevel?: PHILevel;
}

export interface PHIProtectionConfig {
  enabled: boolean;
  mode: 'strict' | 'permissive' | 'audit-only';
  allowEmergencyAccess: boolean;
  emergencyAccessDurationMinutes: number;
  auditAllAccess: boolean;
  defaultMaskingRules: MaskingRule[];
  resourceOverrides: Record<string, PHIClassificationResult>;
}

export class PHIProtectionError extends Error {
  constructor(
    message: string,
    public phiLevel: PHILevel,
    public resourceType: string,
    public operation: string
  ) {
    super(message);
    this.name = 'PHIProtectionError';
  }
}

// Resource PHI Classification Matrix
export const RESOURCE_PHI_MATRIX: Record<string, PHILevel> = {
  // Patient-identifiable resources (BLOCKED when PHI protection enabled)
  'Patient': PHILevel.IDENTIFIABLE,
  'Observation': PHILevel.IDENTIFIABLE,
  'Condition': PHILevel.IDENTIFIABLE,
  'MedicationRequest': PHILevel.IDENTIFIABLE,
  'MedicationDispense': PHILevel.IDENTIFIABLE,
  'MedicationStatement': PHILevel.IDENTIFIABLE,
  'Encounter': PHILevel.IDENTIFIABLE,
  'AllergyIntolerance': PHILevel.IDENTIFIABLE,
  'Procedure': PHILevel.IDENTIFIABLE,
  'DiagnosticReport': PHILevel.IDENTIFIABLE,
  'DocumentReference': PHILevel.IDENTIFIABLE,
  'CarePlan': PHILevel.IDENTIFIABLE,
  'CareTeam': PHILevel.IDENTIFIABLE,
  'Goal': PHILevel.IDENTIFIABLE,
  'ImmunizationRecommendation': PHILevel.IDENTIFIABLE,
  'ServiceRequest': PHILevel.IDENTIFIABLE,
  
  // Organizational resources (MASKED when PHI protection enabled)
  'Organization': PHILevel.MINIMAL,
  'Location': PHILevel.MINIMAL,
  'Practitioner': PHILevel.MINIMAL,
  'PractitionerRole': PHILevel.MINIMAL,
  'Device': PHILevel.MINIMAL,
  'HealthcareService': PHILevel.MINIMAL,
  
  // Public/metadata resources (ALWAYS ALLOWED)
  'ValueSet': PHILevel.NONE,
  'CodeSystem': PHILevel.NONE,
  'StructureDefinition': PHILevel.NONE,
  'CapabilityStatement': PHILevel.NONE,
  'ImplementationGuide': PHILevel.NONE,
  'SearchParameter': PHILevel.NONE,
  'CompartmentDefinition': PHILevel.NONE,
  'OperationDefinition': PHILevel.NONE,
  'ConceptMap': PHILevel.NONE,
  'NamingSystem': PHILevel.NONE,
  
  // Financial/administrative (RESTRICTED - requires specific permissions)
  'Coverage': PHILevel.RESTRICTED,
  'ExplanationOfBenefit': PHILevel.RESTRICTED,
  'Claim': PHILevel.RESTRICTED,
  'ClaimResponse': PHILevel.RESTRICTED,
  'PaymentNotice': PHILevel.RESTRICTED,
  'PaymentReconciliation': PHILevel.RESTRICTED,

  // Resource types that were previously ABSENT from this matrix and therefore
  // fell through to the `|| PHILevel.RESTRICTED` default at phi-classifier.ts:34.
  // Listing them explicitly is a no-op at runtime; it records that RESTRICTED is
  // intended for them rather than accidental.
  // RelatedPerson carries the SAME IL-Core national-ID slice as Patient.
  'RelatedPerson': PHILevel.RESTRICTED,
  'Person': PHILevel.RESTRICTED,
  'Media': PHILevel.RESTRICTED,
  'Binary': PHILevel.RESTRICTED,
  
  // Research/quality (MINIMAL - aggregated data allowed)
  'ResearchStudy': PHILevel.MINIMAL,
  'ResearchSubject': PHILevel.IDENTIFIABLE, // Contains patient references
  'Measure': PHILevel.NONE,
  'MeasureReport': PHILevel.MINIMAL,
  'Library': PHILevel.NONE,
  'PlanDefinition': PHILevel.NONE
};

// Default masking rules by PHI level
export const DEFAULT_MASKING_RULES: Record<PHILevel, MaskingRule[]> = {
  [PHILevel.NONE]: [],
  [PHILevel.MINIMAL]: [
    { field: 'id', maskingType: 'hash' },
    { field: 'identifier', maskingType: 'partial' },
    { field: 'contact', maskingType: 'remove' },
    { field: 'telecom', maskingType: 'remove' }
  ],
  [PHILevel.IDENTIFIABLE]: [
    { field: 'name', maskingType: 'replace', replacement: '***' },
    { field: 'identifier', maskingType: 'hash' },
    { field: 'birthDate', maskingType: 'remove' },
    { field: 'address', maskingType: 'remove' },
    { field: 'telecom', maskingType: 'remove' },
    { field: 'contact', maskingType: 'remove' },
    { field: 'communication', maskingType: 'remove' }
  ],
  [PHILevel.RESTRICTED]: [
    { field: '*', maskingType: 'remove' } // Remove all fields except resourceType
  ]
};

// Sensitive field patterns for dynamic detection
export const SENSITIVE_FIELD_PATTERNS = [
  /name/i,
  /identifier/i,
  /birth/i,
  /address/i,
  /phone/i,
  /email/i,
  /ssn/i,
  /social/i,
  /contact/i,
  /telecom/i,
  /photo/i,
  /image/i
];

export interface PHIAuditEvent {
  eventId: string;
  timestamp: Date;
  userId?: string;
  sessionId: string;
  operation: string;
  resourceType: string;
  resourceId?: string;
  phiLevel: PHILevel;
  accessDecision: 'granted' | 'denied' | 'masked';
  reason?: string;
  emergencyAccess?: boolean;
  maskingApplied?: boolean;
  riskScore?: number;
  userAgent?: string;
  ipAddress?: string;
  requestId?: string;
}

// ---------------------------------------------------------------------------
// Global (resource-type-independent) masking rules
// ---------------------------------------------------------------------------
//
// These exist so that a newly-supported resource type cannot silently omit a
// rule for a field that is identifying on every resource that carries it.
// `PHIClassifier.getResourceSpecificMaskingRules()` prepends them to whatever
// the per-type `switch` produces, so a resource type with no `case` at all
// still receives them.

/**
 * `identifier` is the single most identifying element a FHIR resource carries.
 * In Israel it holds the national ID (tudat zehut) under
 * `http://fhir.health.gov.il/identifier/il-national-id`.
 *
 * `DEFAULT_MASKING_RULES[IDENTIFIABLE]` already hashes it, but that is one line
 * in one branch of one lookup table. This rule makes the guarantee independent
 * of the PHI level and of the per-type `switch`.
 */
export const GLOBAL_IDENTIFIER_MASKING_RULES: readonly MaskingRule[] = [
  { field: 'identifier', maskingType: 'hash' }
];
