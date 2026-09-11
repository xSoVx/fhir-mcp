import { describe, test, expect } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import util from 'util';
import { PHIMaskingEngine, PSEUDONYM_TOKEN_PATTERN } from '../security/phi-masking-engine.js';
import { MaskingRule } from '../types/phi-types.js';
import { CANARY } from './fixtures/canary.js';

/**
 * Finding 8 - `hashCache` was unbounded.
 *
 * After finding 4 the cache maps REAL identifier values to tokens, so the
 * cache itself is PHI. It must be bounded by size and age, cleared when the
 * session key rotates, held in memory only, and excluded from every
 * serialisation surface.
 */
const HASH_ID: MaskingRule[] = [{ field: 'identifier', maskingType: 'hash' }];

function hash(engine: PHIMaskingEngine, value: string): string {
  return engine.applyMasking({ resourceType: 'Patient', identifier: value }, HASH_ID).identifier;
}

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

describe('PHIMaskingEngine - cache is bounded by size (finding 8)', () => {
  test('never exceeds the configured maximum', () => {
    const engine = new PHIMaskingEngine({ cacheMaxEntries: 100 });

    for (let i = 0; i < 1000; i++) {
      hash(engine, 'id-' + i);
    }

    expect(engine.getStats().cacheSize).toBeLessThanOrEqual(100);
    expect(engine.getStats().cacheMaxEntries).toBe(100);
  });

  test('holds at the 50k default across a 60k-insert loop', () => {
    const engine = new PHIMaskingEngine();

    for (let i = 0; i < 60_000; i++) {
      hash(engine, 'bulk-' + i);
    }

    expect(engine.getStats().cacheSize).toBeLessThanOrEqual(50_000);
  });

  test('evicts oldest-first, and eviction does not change the token', () => {
    const engine = new PHIMaskingEngine({ cacheMaxEntries: 3 });

    const firstToken = hash(engine, 'a');
    hash(engine, 'b');
    hash(engine, 'c');
    hash(engine, 'd');   // forces 'a' out

    expect(engine.getStats().cacheSize).toBeLessThanOrEqual(3);

    // The token is derived from the session key, not remembered by the cache,
    // so evicting an entry must not break in-session join-ability.
    expect(hash(engine, 'a')).toBe(firstToken);
  });
});

describe('PHIMaskingEngine - cache is bounded by age (finding 8)', () => {
  test('expires entries past the TTL', async () => {
    const engine = new PHIMaskingEngine({ cacheTtlMs: 20, cacheMaxEntries: 3 });

    hash(engine, 'v1');
    hash(engine, 'v2');
    hash(engine, 'v3');
    expect(engine.getStats().cacheSize).toBe(3);

    await sleep(40);

    // Inserting while full triggers the age sweep; all three are now stale.
    hash(engine, 'v4');
    expect(engine.getStats().cacheSize).toBe(1);
  });

  test('a stale entry is not served from cache', async () => {
    const engine = new PHIMaskingEngine({ cacheTtlMs: 20 });

    const before = hash(engine, 'v1');
    expect(engine.getStats().cacheSize).toBe(1);

    await sleep(40);

    // Re-derived rather than served stale - same key, so same token, but the
    // cache must not have grown a duplicate entry.
    const after = hash(engine, 'v1');
    expect(after).toBe(before);
    expect(engine.getStats().cacheSize).toBe(1);
  });
});

describe('PHIMaskingEngine - cache lifecycle (finding 8)', () => {
  test('clearCache empties it', () => {
    const engine = new PHIMaskingEngine();
    hash(engine, CANARY);
    expect(engine.getStats().cacheSize).toBe(1);

    engine.clearCache();
    expect(engine.getStats().cacheSize).toBe(0);
  });

  test('rotating the session key clears the cache AND changes tokens', () => {
    const engine = new PHIMaskingEngine();
    const before = hash(engine, CANARY);
    expect(engine.getStats().cacheSize).toBe(1);

    engine.rotateSessionKey();

    expect(engine.getStats().cacheSize).toBe(0);

    const after = hash(engine, CANARY);
    expect(after).toMatch(PSEUDONYM_TOKEN_PATTERN);
    expect(after).not.toBe(before);
  });

  test('rotateSessionKey rejects an empty key', () => {
    const engine = new PHIMaskingEngine();
    expect(() => engine.rotateSessionKey(Buffer.alloc(0))).toThrow();
  });
});

describe('PHIMaskingEngine - the cache is PHI and must not escape (finding 8)', () => {
  test('cache contents are absent from every serialisation surface', () => {
    const engine = new PHIMaskingEngine();
    hash(engine, CANARY);

    const surfaces = [
      JSON.stringify(engine),
      JSON.stringify({ engine }),
      JSON.stringify({ ...engine }),
      util.inspect(engine, { depth: 10 }),
      String(engine),
      Object.keys(engine).join(','),
      JSON.stringify(engine.getStats())
    ];

    for (const surface of surfaces) {
      expect(surface).not.toContain(CANARY);
    }
  });

  test('an error carrying the engine does not serialise the cache', () => {
    const engine = new PHIMaskingEngine();
    hash(engine, CANARY);

    const error: any = new Error('masking failed');
    error.engine = engine;

    expect(JSON.stringify({
      message: error.message,
      engine: error.engine
    })).not.toContain(CANARY);
  });

  test('getStats exposes counts only, never keys or values', () => {
    const engine = new PHIMaskingEngine();
    hash(engine, CANARY);

    const stats = engine.getStats();
    expect(Object.values(stats).every(v => typeof v === 'number')).toBe(true);
    expect(JSON.stringify(stats)).not.toContain(CANARY);
  });

  test('the engine source contains no filesystem usage - the cache is memory only', () => {
    const candidates = [
      path.resolve(process.cwd(), 'src/security/phi-masking-engine.ts'),
      path.resolve(process.cwd(), 'packages/mcp-fhir-server/src/security/phi-masking-engine.ts')
    ];
    const found = candidates.find(p => fs.existsSync(p));

    // Fail loudly rather than silently pass if the file cannot be located.
    expect(found).toBeDefined();

    const source = fs.readFileSync(found as string, 'utf8');
    expect(source).not.toMatch(/from ['"]fs['"]/);
    expect(source).not.toMatch(/from ['"]node:fs['"]/);
    expect(source).not.toMatch(/require\(['"]fs['"]\)/);
    expect(source).not.toMatch(/writeFile|appendFile|createWriteStream|localStorage/);
  });
});
