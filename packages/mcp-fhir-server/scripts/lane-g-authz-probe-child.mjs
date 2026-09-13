/**
 * Child half of the lane-G authz probe. Runs against dist/, prints audit output
 * to whichever console sink the built AuditLogger chooses. The parent captures
 * stdout and stderr SEPARATELY, so this also measures the channel question.
 */
import { PHIAuthorizationEngine } from '../dist/security/phi-authorization-engine.js';
import { AuditLogger } from '../dist/security/audit-logger.js';
import { CANARY } from '../dist/tests/fixtures/canary.js';

const CANARY_FAMILY = 'Cohen';

const config = {
  enabled: true,
  mode: 'permissive',
  allowEmergencyAccess: false,
  emergencyAccessDurationMinutes: 30,
  auditAllAccess: true,
  defaultMaskingRules: [],
  resourceOverrides: {}
};

const CLINICIAN = { id: 'u-clin', roles: ['clinician'], permissions: [] };

function canaryPatient() {
  return {
    resourceType: 'Patient',
    // The RAW id is the canary. On the authorized path this lands in
    // auditMetadata.resourceId, which is NESTED inside metadata -- where
    // AuditLogger.log()'s top-level resourceId hashing never reached.
    id: CANARY,
    identifier: [{ value: CANARY }],
    name: [{ family: CANARY_FAMILY, given: ['Tamar'] }]
  };
}

const engine = new PHIAuthorizationEngine(config, new AuditLogger(true));

// PROBE A -- leak 3. Authorized read of a Patient whose id is the canary.
try {
  await engine.authorizeResourceAccess(CLINICIAN, canaryPatient(), 'read', 'probe-session');
} catch (e) {
  console.error(JSON.stringify({ probe: 'A', unexpectedThrow: e && e.name }));
}

// PROBE B -- leak 2. Force a throw from inside authorizeResourceAccess whose
// MESSAGE carries PHI, which is exactly the hazard: the message is written by
// whoever threw, and here that is a layer holding the resource.
const broken = new PHIAuthorizationEngine(config, new AuditLogger(true));
broken.phiClassifier = {
  classifyResource: () => {
    throw new Error(
      'boom for patient ' + CANARY_FAMILY + ' MRN ' + CANARY
    );
  }
};
try {
  await broken.authorizeResourceAccess(CLINICIAN, canaryPatient(), 'read', 'probe-session');
} catch {
  // Expected: the engine rethrows after logging. The log is the artifact.
}

process.exit(0);