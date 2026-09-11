import crypto from 'crypto';

/**
 * The canary value used by every PHI regression test.
 *
 * `000000018` is a VALID Israeli ID - note the LEADING ZEROS. Any regex that
 * assumes a non-zero first digit will silently miss it, which is exactly why
 * this value was chosen. Do not "normalise", trim, or re-generate it.
 *
 * Per the remediation plan this literal must live in exactly one module. If
 * another lane adds a canary fixture (plan task T0.3), that module should
 * import CANARY from here rather than inline the literal again.
 */
export const CANARY = '000000018';

/**
 * What the PRE-FIX engine emitted for the canary: an unsalted, unkeyed
 * sha256 truncated to 16 hex characters.
 *
 * Computed rather than hard-coded, so this constant tracks the actual attack
 * instead of a copy of it. The Israeli ID space is ~10^8 after the check
 * digit, so a complete rainbow table over these values is minutes of GPU time
 * - the output below is therefore equivalent to publishing the ID.
 *
 * No masked output may ever contain this string again.
 */
export const LEGACY_UNSALTED_SHA256 = crypto
  .createHash('sha256')
  .update(CANARY)
  .digest('hex')
  .substring(0, 16);

/** An Observation whose `contained[]` Patient carries the canary (finding 5). */
export function observationWithContainedPatient(canary: string = CANARY): any {
  return {
    resourceType: 'Observation',
    id: 'obs-1',
    status: 'final',
    subject: { reference: '#p1' },
    contained: [
      {
        resourceType: 'Patient',
        id: 'p1',
        identifier: [{ system: 'http://example.org/il-id', value: canary }],
        name: [{ family: 'Cohen', given: ['Dana'] }],
        birthDate: '1980-01-01'
      }
    ]
  };
}

/** A Bundle carrying the canary inside `entry[].resource` (finding 5). */
export function bundleWithPatientEntry(canary: string = CANARY): any {
  return {
    resourceType: 'Bundle',
    type: 'searchset',
    entry: [
      {
        fullUrl: 'http://example.org/Patient/p1',
        resource: {
          resourceType: 'Patient',
          id: 'p1',
          identifier: [{ system: 'http://example.org/il-id', value: canary }],
          name: [{ family: 'Cohen' }]
        }
      },
      {
        fullUrl: 'http://example.org/Observation/obs-1',
        resource: observationWithContainedPatient(canary)
      }
    ]
  };
}
