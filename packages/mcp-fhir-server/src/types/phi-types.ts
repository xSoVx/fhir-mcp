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

  // `Bundle` is a CONTAINER. It has no PHI of its own; everything identifying
  // inside it lives in `entry[].resource`. It is listed here as RESTRICTED
  // DELIBERATELY, and the consequence is that the `{ field: '*' }` rule strips
  // `entry` wholesale before PHIMaskingEngine.maskNested()'s per-entry
  // recursion can matter.
  //
  // That recursion is therefore unreachable through PhiGuard. This was
  // measured, not assumed: fhir-tools.ts (searchResources) de-structures the
  // search Bundle itself and submits one `entry.resource` at a time, so no
  // production caller ever hands PhiGuard a Bundle. Reclassifying Bundle as
  // IDENTIFIABLE to reach the recursion would therefore restore NO
  // functionality, while relaxing the fail-closed default for the Bundles that
  // do arrive by other routes ($everything, transaction responses, a Bundle
  // nested in contained[]). Keeping the strip is the stronger of two safe
  // options and the cheaper of two changes.
  //
  // The recursion is NOT deleted: it still runs for `contained[]`, and it is
  // the correct behaviour the moment this line changes. See maskNested().
  'Bundle': PHILevel.RESTRICTED,
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
 * Narrative (`DomainResource.text`) handling policy.
 *
 * - `'remove'` — drop `text` entirely. This is the default, and the correct
 *   default: the narrative is derived, never authoritative, and no clinical
 *   decision should depend on it.
 * - `'scrub'`  — keep a narrative, but rebuild `text.div` from decoded,
 *   tag-stripped, PHI-redacted text and set `text.status = 'generated'`.
 */
export type NarrativePolicy = 'remove' | 'scrub';

export interface PHIClassifierOptions {
  /** Defaults to `'remove'`. Anything other than `'scrub'` is treated as `'remove'`. */
  narrativePolicy?: NarrativePolicy;
}

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

/**
 * Every `DomainResource` carries a `Narrative` whose XHTML `div` routinely
 * inlines the full patient banner: name, national ID, date of birth, HMO,
 * address. IL-Core constrains `Patient.identifier` with a check-digit
 * invariant and constrains the narrative not at all.
 *
 * A resource whose structured fields are fully masked can still return the
 * patient's name and ID in plain text — worse than not masking, because the
 * output *looks* de-identified.
 */
export const GLOBAL_NARRATIVE_MASKING_RULES: readonly MaskingRule[] = [
  { field: 'text', maskingType: 'remove' }
];

/**
 * `Attachment.data` carries base64 blobs — usually PDFs or scans, which is
 * where Israeli clinical documents actually live. A masked FHIR resource with
 * an unmasked attached PDF is not de-identified.
 *
 * `data` and `url` are both removed. `contentType`, `size`, `hash` and
 * `creation` survive, so the model is still told that a document exists.
 *
 * `url` JOINED THIS LIST because stripping `data` while keeping `url` is not
 * de-identification, it is indirection: `Attachment.url` may address the very
 * blob `data` carried inline, so a consumer that follows it retrieves exactly
 * what was just removed, and the URL path itself routinely embeds the resource
 * id it was fetched by. Removed rather than hashed -- a de-identified consumer
 * has no use for a retrieval handle that would justify keeping one.
 *
 * `title` LEFT the surviving set for the reason recorded on
 * GLOBAL_FREE_TEXT_MASKING_RULES: it is free prose, and
 * `DiagnosticReport.presentedForm[].title` was observed carrying the canary.
 * `contentType`, `size`, `hash` and `creation` already carry the whole of the
 * "a document exists" signal that `title` was being kept for.
 *
 * Paths that do not exist on a given resource are no-ops in the masking
 * engine, so this list is applied unconditionally rather than per resource
 * type — same defence-in-depth argument as the identifier rule.
 */
export const GLOBAL_ATTACHMENT_MASKING_RULES: readonly MaskingRule[] = [
  { field: 'data', maskingType: 'remove' },                          // Binary.data
  { field: 'content.attachment.data', maskingType: 'remove' },       // DocumentReference.content[].attachment
  { field: 'content.data', maskingType: 'remove' },                  // Media.content
  { field: 'presentedForm.data', maskingType: 'remove' },            // DiagnosticReport.presentedForm[]
  { field: 'photo.data', maskingType: 'remove' },                    // Patient/Practitioner/RelatedPerson.photo[]
  { field: 'attachment.data', maskingType: 'remove' },               // generic single-level nesting
  { field: 'contentAttachment.data', maskingType: 'remove' },        // Communication.payload[] choice element
  { field: 'payload.contentAttachment.data', maskingType: 'remove' },
  { field: 'valueAttachment.data', maskingType: 'remove' },          // Observation.valueAttachment
  { field: 'form.data', maskingType: 'remove' },                     // Claim/Coverage form attachments

  // The same paths again for `url`. See the docstring: a stripped `data` with a
  // live `url` beside it is the same blob behind one redirect.
  // NB: deliberately NO root-level `{ field: 'url' }`. ValueSet, CodeSystem and
  // every other canonical resource carry their IDENTITY in a top-level `url`,
  // and these rules reach those types too; removing it would corrupt terminology
  // without protecting anyone. Attachment never sits at a resource root, so the
  // omission costs nothing.
  { field: 'content.attachment.url', maskingType: 'remove' },
  { field: 'content.url', maskingType: 'remove' },
  { field: 'presentedForm.url', maskingType: 'remove' },
  { field: 'photo.url', maskingType: 'remove' },
  { field: 'attachment.url', maskingType: 'remove' },
  { field: 'contentAttachment.url', maskingType: 'remove' },
  { field: 'payload.contentAttachment.url', maskingType: 'remove' },
  { field: 'valueAttachment.url', maskingType: 'remove' },
  { field: 'form.url', maskingType: 'remove' }
];

/**
 * `Meta` is present on EVERY resource, sits outside every resource-specific
 * rule set, and carries three surfaces that nothing in FHIR constrains.
 *
 * - `security[].display` and `tag[].display` are the human-readable label on a
 *   `Coding`. `subject 000000018` is a perfectly legal display string, and
 *   export pipelines routinely copy the patient banner into one. Both are
 *   removed. The `system` + `code` pair is left INTACT on purpose: that is the
 *   machine-readable confidentiality label, and deleting it would tell a
 *   downstream consumer less about how carefully to handle the resource --
 *   masking that makes the output look less sensitive than it is.
 * - `meta.source` is a `uri` naming where the resource came from. Pipelines
 *   build it from the record they extracted (`.../export/Patient/<id>`), so it
 *   is removed outright rather than hashed; a provenance URL has no value to a
 *   de-identified consumer that would justify keeping a handle on it.
 *
 * `versionId`, `lastUpdated` and `profile` survive: the first two are server
 * bookkeeping and the third is a canonical StructureDefinition URL.
 *
 * KNOWN RESIDUAL: `meta.tag[].code` is unbound, so a site COULD put an MRN in
 * it. It is preserved because tags drive real workflow routing and the code is
 * at least nominally a coded value. If that trade stops being acceptable, drop
 * the whole `meta.tag` element -- do not widen this list one sub-field at a
 * time, which is how `meta.security[].display` came to be missed in the first
 * place.
 */
export const GLOBAL_META_MASKING_RULES: readonly MaskingRule[] = [
  { field: 'meta.security.display', maskingType: 'remove' },
  { field: 'meta.tag.display', maskingType: 'remove' },
  { field: 'meta.source', maskingType: 'remove' }
];

/**
 * FREE-TEXT elements: human-authored prose, on every resource type that has any.
 *
 * WHY THIS LIST EXISTS
 * --------------------
 * `PHIClassifier.getResourceSpecificMaskingRules()` had NO `case` arm at all for
 * Condition, MedicationRequest, Procedure or CarePlan, so those types received
 * only the global layer -- and the global layer had nothing for free text. Every
 * one of them was confirmed leaking through the real tool surface at
 * `phiLevel: "identifiable"`:
 *
 *   Condition          note[].text, code.text
 *   MedicationRequest  note[].text, dosageInstruction[].text
 *   Procedure          note[].text, report[].display
 *   CarePlan           note[].text, description
 *   DiagnosticReport   presentedForm[].title, presentedForm[].url
 *
 * The shape of the defect is the point. Observation DID have
 * `{ note: remove }` and Encounter is clean, so this was never uniform absence
 * -- it was INCONSISTENCY BETWEEN RULE SETS, which is the same defect that
 * produced the `identifier`, `extension` and `subject` findings before it. A
 * per-type enumeration cannot fix that class: it fixes the four types someone
 * listed and misses the fifth type someone adds next quarter.
 *
 * So free text is treated as a CATEGORY. The category is recognisable by
 * element name, because FHIR names it consistently: `note[].text` (Annotation),
 * `X.text` (CodeableConcept, Dosage, HumanName, Address), `description`,
 * `title`, and `Reference.display`. Nothing in FHIR constrains any of them, and
 * export pipelines routinely copy the patient banner into all of them.
 *
 * WHY THIS IS NOT THE WHOLE FIX -- the same two-layer split as
 * GLOBAL_REFERENCE_MASKING_RULES, for the same reason. `MaskingRule.field` is a
 * fixed dot-path, and free text appears at paths no finite list enumerates
 * (`stage[].summary.text`, `activity[].detail.description`, a CodeableConcept
 * inside a contained resource, an element added by a future FHIR release). This
 * list is the DECLARED layer, useful because it is inspectable and testable;
 * `PHIMaskingEngine.scrubFreeText()` is the STRUCTURAL layer that actually
 * closes the surface by walking the whole graph.
 *
 * Removal, not hashing: prose has no correlating value worth a token, and a
 * pseudonym in place of a sentence tells a reader less than its absence does.
 */
export const GLOBAL_FREE_TEXT_MASKING_RULES: readonly MaskingRule[] = [
  // Annotation[]. Removing the whole element takes `text` with it, and
  // `author` and `time` alongside -- both of which identify people too.
  { field: 'note', maskingType: 'remove' },

  // Free-prose elements in their own right.
  { field: 'description', maskingType: 'remove' },
  { field: 'title', maskingType: 'remove' },
  { field: 'comment', maskingType: 'remove' },

  // `X.text` at the paths the audit actually caught. The structural pass covers
  // the rest; these are here so a reader can see the finding in the rule set.
  { field: 'code.text', maskingType: 'remove' },
  { field: 'dosageInstruction.text', maskingType: 'remove' },
  { field: 'presentedForm.title', maskingType: 'remove' },

  // `Reference.display` is a human label for the referenced record, and for a
  // Patient reference that label IS the patient's name. Note this is
  // Reference.display ONLY -- Coding.display is a terminology label
  // ("Hemoglobin") and removing it would destroy clinical meaning while
  // protecting nobody. A dot-path cannot tell the two apart, which is exactly
  // why the structural pass keys on the SHAPE of the containing object; these
  // paths are the subset where the shape is known in advance.
  { field: 'report.display', maskingType: 'remove' },
  { field: 'subject.display', maskingType: 'remove' },
  { field: 'patient.display', maskingType: 'remove' },
  { field: 'performer.display', maskingType: 'remove' },
  { field: 'requester.display', maskingType: 'remove' }
];

/**
 * Reference-valued elements that point at a PERSON, applied to every resource
 * type regardless of whether the per-type `switch` in
 * `PHIClassifier.getResourceSpecificMaskingRules()` has a `case` for it.
 *
 * WHY THIS LIST EXISTS AT ALL
 * --------------------------
 * A live runtime audit against HAPI found that reference exposure was
 * TYPE-DEPENDENT, which nobody had documented:
 *
 *   Observation.subject, Encounter.subject, DiagnosticReport.subject,
 *   DocumentReference.subject        -> had a `{ subject: hash }` rule
 *   Condition.subject, Procedure.subject,
 *   MedicationRequest.subject        -> had NO rule, so `Patient/<id>`
 *                                       survived RAW into masked output
 *
 * That is the same shape of defect as the `identifier` and `extension`
 * findings before it: a guarantee expressed once per resource type is a
 * guarantee that is missing for every resource type nobody got to. So the rule
 * is hoisted out of the `switch` and applied unconditionally. Paths that do not
 * exist on a given resource are no-ops in the masking engine, so listing
 * `beneficiary` on an Observation costs nothing.
 *
 * WHY THIS IS NOT THE WHOLE FIX
 * -----------------------------
 * `MaskingRule.field` is a fixed dot-path, and a `Reference` - exactly like an
 * `Extension` - can appear at a path no finite list enumerates (`basedOn`,
 * `partOf`, `link[].other`, `insurance[].coverage`, a Reference inside a
 * contained resource, a Reference added by a future FHIR release). This list is
 * therefore the DECLARED layer; `PHIMaskingEngine.pseudonymiseReferences()` is
 * the STRUCTURAL layer that actually closes the surface, walking the whole
 * graph and rewriting every `Reference.reference` it finds.
 *
 * Both layers derive their token from the same
 * `PHIMaskingEngine.tokenForSubject()`, so they cannot disagree: applying this
 * rule to a reference the structural pass has already rewritten is a no-op
 * (the engine recognises its own token and returns it unchanged). That
 * idempotence is the property that makes running both safe, and it is the
 * reason the per-type `subject` rules below could be left in place rather than
 * deleted.
 */
export const GLOBAL_REFERENCE_MASKING_RULES: readonly MaskingRule[] = [
  { field: 'subject', maskingType: 'hash' },
  { field: 'patient', maskingType: 'hash' },
  { field: 'beneficiary', maskingType: 'hash' },
  { field: 'subscriber', maskingType: 'hash' },
  { field: 'policyHolder', maskingType: 'hash' },
  { field: 'recorder', maskingType: 'hash' },
  { field: 'asserter', maskingType: 'hash' }
];

/**
 * DELIBERATELY NOT IN THE LIST ABOVE -- and this is a correctness constraint,
 * not an oversight, so do not "complete" the list:
 *
 *   context, performer, author, recipient, sender, actor, individual,
 *   requester, participant, payor, encounter
 *
 * Each of these names a BackboneElement rather than a Reference on at least one
 * resource type. `DocumentReference.context` holds `encounter[]`, `period`,
 * `facilityType` and `practiceSetting`; `MedicationDispense.performer` holds
 * `function` and `actor`; `Encounter.participant` holds `type`, `period` and
 * `individual`. A `hash` rule aimed at one of those collapses the ENTIRE
 * element to a single opaque token and destroys the non-identifying clinical
 * metadata alongside the id.
 *
 * A dot-path rule cannot distinguish the two cases, because the distinction is
 * in the VALUE, not the path. `PHIMaskingEngine.pseudonymiseReferences()` keys
 * on the presence of a string `reference` and therefore handles both correctly:
 * it rewrites `context.encounter[0].reference` and leaves `context.period`
 * alone. It already reaches every path in the graph, so nothing is lost by
 * omitting these -- only the risk of deleting data is.
 */

/**
 * How a resource's own logical `id` is treated.
 *
 * - `'tokenize'` (the default, and the decision recorded at lane I): replace
 *   `Resource.id` with the SAME pseudonym token the resource's own
 *   `Reference`s resolve to, so one patient yields one token everywhere in a
 *   session.
 * - `'remove'`: drop `id` entirely.
 *
 * `'remove'` is NOT the safer option in the way it first appears, which is why
 * it is not the default. See `PHIMaskingEngine.pseudonymiseLogicalIds()` for
 * the full argument; in short, references are rewritten to `Patient/PT_xxx`,
 * and removing `id` leaves every one of those tokens pointing at a resource
 * that no longer declares it - a dangling handle, which is the "silently wrong
 * linkage" failure mode in its other direction.
 */
export type LogicalIdPolicy = 'tokenize' | 'remove';
