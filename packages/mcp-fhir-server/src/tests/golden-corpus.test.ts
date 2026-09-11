import { describe, test, expect } from '@jest/globals';
import { readdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CANARY, CANARY_BASE64, CANARY_NUMERIC_ENTITIES } from './fixtures/canary.js';
import {
  clinician,
  expectMaskingEngineRan,
  maskViaEngine,
  maskViaGuard,
  restrictedAccessUser,
  type MaskingOutcome
} from './fixtures/masking-harness.js';

/**
 * ============================================================================
 *  GOLDEN-FILE CORPUS
 * ============================================================================
 *
 * Every resource shape that has ever surprised us, with its expected masked
 * output, replayed on every push. A detection system without one regresses
 * silently with each rule change, and no amount of unit testing substitutes
 * for it.
 *
 * Layout -- one directory per case under src/tests/golden/:
 *   case.json      what the case is, which path/user/mode to run it through,
 *                  and which leak surfaces it exercises
 *   input.json     the FHIR resource, verbatim
 *   expected.json  the masked output, plus a recorded leak status
 *
 * READ THIS BEFORE REGENERATING
 * -----------------------------
 * The expected files record CURRENT, STILL-LEAKY behaviour on purpose. Several
 * of them contain the canary. That is the design: when a remediation lane
 * changes a masking rule, the change shows up as an explicit, reviewable diff
 * in a checked-in file rather than as silence.
 *
 * So a red golden case is not automatically a bug. It means output changed,
 * and someone has to look at the diff and say whether the change was intended.
 * Regenerate with `npm run golden:update -w @fhir-mcp/server`, then read the
 * diff line by line before committing it. Never regenerate in CI.
 *
 * HASH STABILITY
 * --------------
 * Hashed values are stored as the placeholder "<<HASH>>", never as a literal
 * digest. Two reasons. Today's hash is an unsalted sha256 prefix, so writing
 * it down would bake a rainbow-table-able digest of a real identifier into the
 * repo. And T2.2 replaces it with an HMAC under a per-session key, at which
 * point literal digests stop being reproducible at all and the whole corpus
 * would need regenerating for a change that is not about any of these cases.
 * The placeholder matches both the current 16-hex form and the planned
 * PT_xxxxxxxxxxxx form, so T2.2 lands without touching these files.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDEN_DIR = join(HERE, 'golden');
const UPDATE = process.env.GOLDEN_UPDATE === '1';

/** Matches the current unsalted-sha256 form and the planned HMAC token form. */
const HASH_SHAPES = [/^[0-9a-f]{16}$/, /^PT_[A-Za-z0-9_-]{12}$/];

interface GoldenCase {
  description: string;
  path: 'guard' | 'engine';
  user: 'none' | 'clinician' | 'restricted';
  mode: string;
  surfaces: string[];
}

function readJson(file: string): any {
  return JSON.parse(readFileSync(file, 'utf8'));
}

/**
 * Serialise the way the MCP tool path does.
 *
 * Load-bearing: maskingType 'remove' sets a field to `undefined` instead of
 * deleting the key (phi-masking-engine.ts:116) and relies on the caller
 * serialising it away. Comparing object graphs instead of their JSON would see
 * `undefined` keys that no real consumer ever sees.
 */
function normalise(value: unknown): any {
  return JSON.parse(JSON.stringify(value ?? null));
}

/**
 * Replace every value that looks like a pseudonym hash with "<<HASH>>", so the
 * corpus is stable across hashing-scheme changes.
 */
function placeholderiseHashes(value: any): any {
  if (typeof value === 'string') {
    return HASH_SHAPES.some((re) => re.test(value)) ? '<<HASH>>' : value;
  }
  if (Array.isArray(value)) return value.map(placeholderiseHashes);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, placeholderiseHashes(v)])
    );
  }
  return value;
}

async function runCase(name: string, def: GoldenCase, input: unknown): Promise<MaskingOutcome> {
  const user =
    def.user === 'clinician'
      ? clinician()
      : def.user === 'restricted'
        ? restrictedAccessUser()
        : undefined;

  if (def.path === 'guard') {
    return maskViaGuard(input, { user, mode: def.mode as 'safe' | 'trusted' });
  }
  return maskViaEngine(input, { user, mode: def.mode as never });
}

/** Which canary encodings survive into the output, recorded per case. */
function leakReport(masked: unknown): Record<string, boolean> {
  const blob = JSON.stringify(masked ?? null);
  return {
    plaintext: blob.includes(CANARY),
    numericEntities: blob.includes(CANARY_NUMERIC_ENTITIES),
    base64: blob.includes(CANARY_BASE64)
  };
}

const caseNames = existsSync(GOLDEN_DIR)
  ? readdirSync(GOLDEN_DIR, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort()
  : [];

describe('golden corpus', () => {
  test('the corpus is not empty', () => {
    // Guards against the corpus silently evaporating -- a directory rename or
    // a bad glob would otherwise turn every check below into zero checks, and
    // an empty suite passes.
    expect(caseNames.length).toBeGreaterThanOrEqual(6);
  });

  test('it is hermetic', () => {
    // Unlike test-basic-functionality.js -- the only test CI ran before this
    // work -- the corpus must never touch the network. Every input is a
    // checked-in JSON file; nothing here resolves a host.
    for (const name of caseNames) {
      const raw = readFileSync(join(GOLDEN_DIR, name, 'input.json'), 'utf8');
      // Reference *identifiers* like "Patient/000000018" are fine; a URL that
      // would be dereferenced is not. The only http(s) strings permitted are
      // FHIR system/canonical URIs, which are opaque identifiers, never
      // fetched.
      expect(raw).not.toMatch(/"(fullUrl|url)"\s*:\s*"https?:\/\/(?!fhir\.health\.gov\.il|loinc\.org|example\.org|www\.w3\.org)/);
    }
  });

  describe.each(caseNames)('%s', (name) => {
    const dir = join(GOLDEN_DIR, name);
    const def: GoldenCase = readJson(join(dir, 'case.json'));
    const input = readJson(join(dir, 'input.json'));
    const expectedPath = join(dir, 'expected.json');

    test(def.description.split('.')[0], async () => {
      const outcome = await runCase(name, def, input);

      // Anti-vacuity: a golden file recorded from a BLOCKED call would be a
      // snapshot of nothing, and would keep matching forever no matter what
      // the masking rules did.
      expectMaskingEngineRan(outcome);

      const actual = {
        masked: placeholderiseHashes(normalise(outcome.maskedResource)),
        canaryLeaks: leakReport(outcome.maskedResource)
      };

      if (UPDATE) {
        writeFileSync(expectedPath, JSON.stringify(actual, null, 2) + '\n', 'utf8');
        return;
      }

      expect(existsSync(expectedPath)).toBe(true);
      const expected = readJson(expectedPath);

      // Compared separately so a failure says WHICH of the two changed: the
      // masked output, or whether the canary still leaks.
      expect(actual.canaryLeaks).toEqual(expected.canaryLeaks);
      expect(actual.masked).toEqual(expected.masked);
    });
  });
});