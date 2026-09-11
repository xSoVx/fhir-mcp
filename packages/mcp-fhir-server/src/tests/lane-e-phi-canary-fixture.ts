import { PHILevel, User } from '../types/phi-types.js';

/**
 * A valid Israeli national ID (tehudat zehut) with leading zeros, taken from
 * the IL-Core specification's own Patient example. Leading zeros are valid:
 * any detector or regex that demands a non-zero first digit will miss it.
 *
 * Exported from exactly one module. Never inline the literal elsewhere.
 */
export const CANARY = '000000018';

export const IL_NATIONAL_ID_SYSTEM = 'http://fhir.health.gov.il/identifier/il-national-id';

/** A Patient carrying the canary in its most identifying structured field. */
export function canaryPatient(id = 'p-canary'): Record<string, any> {
  return {
    resourceType: 'Patient',
    id,
    identifier: [{ system: IL_NATIONAL_ID_SYSTEM, value: CANARY }],
    name: [{ family: 'Cohen', given: ['Tamar'] }],
    birthDate: '1980-04-17',
    gender: 'female',
    telecom: [{ system: 'phone', value: '+972-50-0000018' }],
    address: [{ city: 'Haifa', line: ['1 Example St'] }]
  };
}

/* ---------------------------------------------------------------------------
 * The input domain of PHIAuthorizationEngine.
 * ------------------------------------------------------------------------ */

export interface UserProfile {
  readonly label: string;
  readonly user: User | undefined;
  /** Satisfies hasPatientLevelAccess() */
  readonly patientLevel: boolean;
  /** Satisfies hasRestrictedAccess() */
  readonly restricted: boolean;
}

/**
 * Every disjunct of hasPatientLevelAccess() and hasRestrictedAccess(), plus
 * the absent-user and no-privilege cases, plus a user holding both.
 */
export const USER_PROFILES: readonly UserProfile[] = [
  { label: 'no user (undefined)', user: undefined, patientLevel: false, restricted: false },
  { label: 'anonymous (no roles, no permissions)', user: { id: 'u-anon', roles: [], permissions: [] }, patientLevel: false, restricted: false },
  { label: 'unrelated role + permission', user: { id: 'u-other', roles: ['billing'], permissions: ['observation:read'] }, patientLevel: false, restricted: false },
  { label: 'permission patient:read', user: { id: 'u-pr', roles: [], permissions: ['patient:read'] }, patientLevel: true, restricted: false },
  { label: 'permission patient:*', user: { id: 'u-pw', roles: [], permissions: ['patient:*'] }, patientLevel: true, restricted: false },
  { label: 'role clinician', user: { id: 'u-clin', roles: ['clinician'], permissions: [] }, patientLevel: true, restricted: false },
  { label: 'phiAccessLevel IDENTIFIABLE', user: { id: 'u-pid', roles: [], permissions: [], phiAccessLevel: PHILevel.IDENTIFIABLE }, patientLevel: true, restricted: false },
  { label: 'permission restricted:read', user: { id: 'u-rr', roles: [], permissions: ['restricted:read'] }, patientLevel: false, restricted: true },
  { label: 'permission admin:*', user: { id: 'u-aw', roles: [], permissions: ['admin:*'] }, patientLevel: false, restricted: true },
  { label: 'phiAccessLevel RESTRICTED', user: { id: 'u-prs', roles: [], permissions: [], phiAccessLevel: PHILevel.RESTRICTED }, patientLevel: false, restricted: true },
  { label: 'role admin', user: { id: 'u-adm', roles: ['admin'], permissions: [] }, patientLevel: true, restricted: true },
  { label: 'clinician + restricted:read', user: { id: 'u-both', roles: ['clinician'], permissions: ['restricted:read'] }, patientLevel: true, restricted: true }
];

/** The three modes the engine recognises. */
export const VALID_MODES = ['strict', 'permissive', 'audit-only'] as const;

/**
 * Mode strings a real deployment can actually produce: env-var typos, casing
 * mistakes, the PhiGuard vocabulary leaking through, an unset variable, and
 * non-string values arriving through an `as` cast.
 */
export const INVALID_MODES: readonly unknown[] = [
  '', 'saef', 'Strict', 'STRICT', 'Safe', 'safe', 'trusted', 'none',
  'audit only', 'auditonly', 'permissive ', undefined, null, 0, 42, {}, []
];

export interface ResourceCase {
  readonly label: string;
  readonly expectedLevel: PHILevel;
  make(id: string): Record<string, any>;
}

/** One resource per PHI level, each carrying the canary where it can. */
export const RESOURCE_CASES: readonly ResourceCase[] = [
  {
    label: 'ValueSet (NONE)',
    expectedLevel: PHILevel.NONE,
    make: (id) => ({ resourceType: 'ValueSet', id, url: 'http://example.org/vs', status: 'active', note: CANARY })
  },
  {
    // MINIMAL is only reachable for a resource carrying neither `id` nor
    // `identifier`: phi-classifier.ts:89 sets hasDirectIdentifiers on either
    // key, and determineFinalPHILevel then upgrades MINIMAL -> IDENTIFIABLE.
    label: 'Organization (MINIMAL - no id, no identifier)',
    expectedLevel: PHILevel.MINIMAL,
    make: (id) => ({ resourceType: 'Organization', active: true, alias: [`clinic-${id}`], telecom: [{ system: 'phone', value: CANARY }] })
  },
  {
    label: 'Organization (IDENTIFIABLE - upgraded by id/identifier)',
    expectedLevel: PHILevel.IDENTIFIABLE,
    make: (id) => ({ resourceType: 'Organization', id, identifier: [{ value: CANARY }], name: 'Example Clinic', telecom: [{ system: 'phone', value: CANARY }] })
  },
  {
    label: 'Patient (IDENTIFIABLE)',
    expectedLevel: PHILevel.IDENTIFIABLE,
    make: (id) => canaryPatient(id)
  },
  {
    label: 'Observation (IDENTIFIABLE)',
    expectedLevel: PHILevel.IDENTIFIABLE,
    make: (id) => ({ resourceType: 'Observation', id, status: 'final', subject: { reference: `Patient/${CANARY}` }, identifier: [{ value: CANARY }], note: [{ text: `patient ${CANARY}` }] })
  },
  {
    label: 'Coverage (RESTRICTED)',
    expectedLevel: PHILevel.RESTRICTED,
    make: (id) => ({ resourceType: 'Coverage', id, status: 'active', subscriberId: CANARY, identifier: [{ value: CANARY }] })
  },
  {
    label: 'UnknownResourceType (RESTRICTED by default)',
    expectedLevel: PHILevel.RESTRICTED,
    make: (id) => ({ resourceType: 'LaneEUnknownThing', id, identifier: [{ value: CANARY }], payload: CANARY })
  }
];
