import crypto from 'crypto';
import {
  MaskingRule,
  PHILevel,
  DEFAULT_MASKING_RULES,
  RESOURCE_PHI_MATRIX
} from '../types/phi-types.js';

/**
 * Pseudonym token format.
 *
 * Tokens are deliberately prefixed so a human or a downstream system can tell
 * at a glance that the value is NOT a real identifier. Never widen this
 * pattern without re-reading finding 4.
 */
export const PSEUDONYM_PREFIX = 'PT_';
export const PSEUDONYM_TOKEN_LENGTH = 12;
export const PSEUDONYM_TOKEN_PATTERN = /^PT_[A-Za-z0-9_-]{12}$/;

/**
 * Resolves the masking rules that apply to a NESTED resource, based on that
 * resource's own `resourceType`.
 *
 * Why this interface lives here (finding 5 / the classifier seam):
 * `PHIMaskingEngine` must classify `contained[]` and `Bundle.entry[].resource`
 * independently of the outer resource. The natural owner of that decision is
 * `PHIClassifier`, but it exposes no public rule-selection API today
 * (`getMaskingRules` is private, and the engine holds no classifier
 * reference). Rather than reach into another module's internals - or block on
 * a change to a file this lane does not own - the engine declares the seam it
 * needs and ships a conservative default. When the classifier grows a public
 * equivalent, inject it with `setRuleResolver()`; nothing here changes.
 */
export interface NestedMaskingRuleResolver {
  getRulesFor(resource: any): MaskingRule[];
}

/**
 * Default resolver.
 *
 * Mirrors `PHIClassifier`'s own base-level selection exactly -
 * `RESOURCE_PHI_MATRIX[resourceType] || PHILevel.RESTRICTED` - then takes the
 * corresponding entry from the shared `DEFAULT_MASKING_RULES` table. Both are
 * imported constants, so this stays in step with the classifier without
 * depending on it.
 *
 * Unknown or malformed nested resources fall through to RESTRICTED: fail
 * closed, never fail open.
 */
export class DefaultNestedMaskingRuleResolver implements NestedMaskingRuleResolver {
  public getRulesFor(resource: any): MaskingRule[] {
    const resourceType = resource?.resourceType;

    if (typeof resourceType !== 'string' || resourceType.length === 0) {
      return [...DEFAULT_MASKING_RULES[PHILevel.RESTRICTED]];
    }

    const level = RESOURCE_PHI_MATRIX[resourceType] || PHILevel.RESTRICTED;
    return [...DEFAULT_MASKING_RULES[level]];
  }
}

export interface PHIMaskingEngineOptions {
  /**
   * 32 random bytes by default. Never persisted, never logged, never
   * serialised. Injectable so tests and golden-file corpora can pin a key and
   * get reproducible tokens.
   */
  sessionKey?: Buffer;
  ruleResolver?: NestedMaskingRuleResolver;
  cacheTtlMs?: number;
  cacheMaxEntries?: number;
  maxNestingDepth?: number;
}

interface HashCacheEntry {
  token: string;
  ts: number;
}

const DEFAULT_CACHE_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours
const DEFAULT_CACHE_MAX_ENTRIES = 50_000;
const DEFAULT_MAX_NESTING_DEPTH = 20;

/**
 * The two element names that can hold an `Extension[]` anywhere in FHIR.
 *
 * `modifierExtension` is included deliberately. It has exactly the same
 * free-form `value[x]` payload as `extension`, and differs only in that a
 * consumer is FORBIDDEN from ignoring it -- which makes leaving it unmasked
 * strictly worse than leaving `extension` unmasked, not safer.
 */
const EXTENSION_ELEMENTS: readonly string[] = ['extension', 'modifierExtension'];

/**
 * A mutable JSON object. Deliberately NOT `any`: the extension scrubber below
 * is new code, and the repo's lint baseline is a fixed warning count.
 */
type MutableJson = Record<string, unknown>;

/**
 * PHI Masking Engine
 * Applies various masking strategies to protect sensitive health information
 */
export class PHIMaskingEngine {
  /**
   * Per-session HMAC key. Declared as an ECMAScript private field (`#`) rather
   * than a TypeScript `private`, so it is genuinely unreachable from
   * `Object.keys`, `JSON.stringify`, spread and `util.inspect`. TypeScript's
   * `private` is erased at runtime and would leak the key into any accidental
   * serialisation of the engine.
   */
  #sessionKey: Buffer;

  /**
   * Maps raw identifier value -> pseudonym token. This cache holds REAL PHI
   * values (finding 8), so it is an ECMAScript private field too, is bounded
   * by size and age, lives only in memory, and is never written to disk or
   * included in any serialisation.
   */
  #hashCache = new Map<string, HashCacheEntry>();

  private ruleResolver: NestedMaskingRuleResolver;
  private readonly cacheTtlMs: number;
  private readonly cacheMaxEntries: number;
  private readonly maxNestingDepth: number;
  private maskingOperations = 0;

  /** Accepts either an options bag or a bare session-key `Buffer`. */
  constructor(options: PHIMaskingEngineOptions | Buffer = {}) {
    const opts: PHIMaskingEngineOptions = Buffer.isBuffer(options)
      ? { sessionKey: options }
      : options;

    this.#sessionKey = opts.sessionKey ?? crypto.randomBytes(32);
    this.ruleResolver = opts.ruleResolver ?? new DefaultNestedMaskingRuleResolver();
    this.cacheTtlMs = opts.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.cacheMaxEntries = opts.cacheMaxEntries ?? DEFAULT_CACHE_MAX_ENTRIES;
    this.maxNestingDepth = opts.maxNestingDepth ?? DEFAULT_MAX_NESTING_DEPTH;
  }

  /** Inject a rule resolver (e.g. a classifier-backed one) after construction. */
  public setRuleResolver(resolver: NestedMaskingRuleResolver): void {
    if (!resolver || typeof resolver.getRulesFor !== 'function') {
      throw new Error('setRuleResolver requires an object with a getRulesFor(resource) method');
    }
    this.ruleResolver = resolver;
  }

  /**
   * Replace the session key and drop every pseudonym derived from the old one.
   *
   * Rotating without clearing would let a stale cache keep emitting tokens
   * from the previous key, silently restoring cross-session linkability.
   */
  public rotateSessionKey(newKey: Buffer = crypto.randomBytes(32)): void {
    if (!Buffer.isBuffer(newKey) || newKey.length === 0) {
      throw new Error('rotateSessionKey requires a non-empty Buffer');
    }
    this.#sessionKey = newKey;
    this.#hashCache.clear();
  }

  /**
   * Apply masking rules to a resource.
   *
   * Nested resources (`contained[]`, `Bundle.entry[].resource`) are classified
   * and masked by their OWN resourceType BEFORE the outer rules run.
   */
  public applyMasking(resource: any, rules: MaskingRule[]): any {
    if (!resource || typeof resource !== 'object') {
      return resource;
    }

    // NOTE: the pre-fix code returned early when `rules.length === 0`. That is
    // no longer safe - a Bundle can carry zero outer rules and still contain
    // entries that need masking (finding 5).

    const maskedResource = this.deepClone(resource);
    this.scrubExtensions(maskedResource, new Set<unknown>());
    this.maskNested(maskedResource, 0, new Set<any>());
    this.applyOwnRules(maskedResource, rules);

    this.maskingOperations++;
    return maskedResource;
  }

  /** Apply a rule list to one resource, without recursing into nested ones. */
  private applyOwnRules(resource: any, rules: MaskingRule[]): void {
    if (!Array.isArray(rules) || rules.length === 0) {
      return;
    }
    rules.forEach(rule => {
      this.applyMaskingRule(resource, rule);
    });
  }

  /**
   * Recurse into `contained[]` and `Bundle.entry[].resource`, masking each
   * nested resource with rules chosen from its own resourceType.
   *
   * Depth is capped and already-visited nodes are detected; in both cases the
   * nested resource is replaced by a bare `{ resourceType }` stub rather than
   * passed through, so malicious or malformed nesting fails closed.
   */
  private maskNested(resource: any, depth: number, seen: Set<any>): void {
    if (!resource || typeof resource !== 'object') {
      return;
    }

    if (Array.isArray(resource.contained)) {
      resource.contained = resource.contained.map((child: any) =>
        this.maskNestedResource(child, depth + 1, seen)
      );
    }

    // REACHABILITY (recorded at lane F, do not delete this branch):
    // `Bundle` is RESTRICTED in RESOURCE_PHI_MATRIX, so when a Bundle is masked
    // as the OUTER resource this recursion runs and its result is then thrown
    // away by the `{ field: '*' }` wildcard in applyOwnRules. That is the
    // deliberate choice documented on the matrix entry -- fhir-tools.ts never
    // submits a Bundle to PhiGuard in the first place, so making it reachable
    // buys nothing and costs the fail-closed default.
    //
    // The branch stays because it is NOT dead: it is the correct behaviour the
    // moment Bundle is reclassified, and it already fires today for any nested
    // resource inside contained[] that carries an `entry` array of its own.
    if (Array.isArray(resource.entry)) {
      resource.entry = resource.entry.map((entry: any) => {
        if (!entry || typeof entry !== 'object') {
          return entry;
        }
        if (!entry.resource || typeof entry.resource.resourceType !== 'string') {
          // Not a Bundle-style entry (e.g. List.entry holds a Reference).
          return entry;
        }
        return {
          ...entry,
          resource: this.maskNestedResource(entry.resource, depth + 1, seen)
        };
      });
    }
  }

  private maskNestedResource(child: any, depth: number, seen: Set<any>): any {
    if (!child || typeof child !== 'object') {
      return child;
    }

    if (depth > this.maxNestingDepth || seen.has(child)) {
      return this.redactedStub(child);
    }

    seen.add(child);
    try {
      this.maskNested(child, depth, seen);
      this.applyOwnRules(child, this.resolveNestedRules(child));
      return child;
    } finally {
      seen.delete(child);
    }
  }

  /**
   * A nested resource we refuse to descend into is reduced to its type. Never
   * return it untouched - that is precisely the finding-5 bug.
   */
  private redactedStub(child: any): any {
    const stub: any = {};
    if (typeof child.resourceType === 'string') {
      stub.resourceType = child.resourceType;
    }
    return stub;
  }

  /**
   * Structurally redact every `extension` / `modifierExtension` array in the
   * graph -- at ANY depth, on ANY element, on ANY resource type.
   *
   * WHY THIS IS NOT A MASKING RULE
   * ------------------------------
   * `MaskingRule.field` is a fixed dot-path. Extensions are the one FHIR
   * construct with no fixed path: a resource may carry one on itself, on any
   * backbone element, on any datatype, nested arbitrarily deep inside another
   * extension, and -- the surface that has no dot-path at all -- on a PRIMITIVE
   * via its `_field` sibling (`_birthDate.extension[]`). No finite list of
   * paths covers that, so the guarantee has to be structural or it is not a
   * guarantee. That is also why this runs unconditionally rather than being
   * selected per PHI level: a rule you can forget to select is a rule that gets
   * forgotten.
   *
   * WHY A WHITELIST, NOT A LIST OF `value[x]` NAMES
   * ----------------------------------------------
   * An extension's payload is `value[x]`, where `[x]` ranges over every FHIR
   * datatype: `valueString`, `valueIdentifier`, `valueHumanName`,
   * `valueAddress`, `valueAttachment`, `valueReference` and ~50 more, with new
   * ones added every release. Enumerating them -- or matching /^value[A-Z]/ --
   * closes only the shapes someone thought of, and closes nothing at all for a
   * non-conformant extension that hangs PHI off some other key.
   *
   * So each extension is REBUILT from a whitelist rather than filtered by a
   * blacklist. `url` survives, so the consumer is still told WHICH extension was
   * present -- the same bargain Attachment.data strikes with contentType. Nested
   * `extension` arrays are recursed into. Every other key, conformant value[x]
   * or not, is dropped. A choice type that does not exist yet is already
   * handled.
   */
  private scrubExtensions(node: unknown, seen: Set<unknown>): void {
    if (!node || typeof node !== 'object' || seen.has(node)) {
      return;
    }
    // Visited-once, never un-marked: deepClone preserves shared references, so
    // a node reachable twice has already been scrubbed the first time. This
    // also terminates on the cyclic graphs deepClone is built to survive.
    seen.add(node);

    if (Array.isArray(node)) {
      node.forEach(item => this.scrubExtensions(item, seen));
      return;
    }

    const record = node as MutableJson;
    for (const key of Object.keys(record)) {
      if (EXTENSION_ELEMENTS.includes(key)) {
        record[key] = this.redactExtensionArray(record[key], 1);
        continue;
      }
      this.scrubExtensions(record[key], seen);
    }
  }

  /** Rebuild an `Extension[]`. Anything that is not one is dropped, not kept. */
  private redactExtensionArray(
    value: unknown,
    depth: number
  ): MutableJson[] | undefined {
    if (!Array.isArray(value) || depth > this.maxNestingDepth) {
      return undefined;
    }
    // Entries that are not extensions at all are DROPPED, not kept as holes.
    return value
      .map(extension => this.redactExtension(extension, depth))
      .filter((extension): extension is MutableJson => extension !== undefined);
  }

  /** Rebuild ONE extension from `{ url, extension, modifierExtension }`. */
  private redactExtension(extension: unknown, depth: number): MutableJson | undefined {
    if (!extension || typeof extension !== 'object' || Array.isArray(extension)) {
      return undefined;
    }

    const source = extension as MutableJson;
    const kept: MutableJson = {};
    if (typeof source.url === 'string') {
      kept.url = source.url;
    }
    for (const element of EXTENSION_ELEMENTS) {
      if (Object.prototype.hasOwnProperty.call(source, element)) {
        const nested = this.redactExtensionArray(source[element], depth + 1);
        if (nested !== undefined) {
          kept[element] = nested;
        }
      }
    }
    return kept;
  }

  private resolveNestedRules(child: any): MaskingRule[] {
    try {
      const rules = this.ruleResolver.getRulesFor(child);
      if (Array.isArray(rules) && rules.length > 0) {
        return rules;
      }
      // An empty rule set for a nested resource is treated as a resolver
      // failure, not as "nothing to mask".
      return [...DEFAULT_MASKING_RULES[PHILevel.RESTRICTED]];
    } catch {
      // Never let a resolver error become an unmasked nested resource. The
      // error object is deliberately dropped - it may quote PHI.
      return [...DEFAULT_MASKING_RULES[PHILevel.RESTRICTED]];
    }
  }

  /**
   * Apply a single masking rule
   */
  private applyMaskingRule(resource: any, rule: MaskingRule): void {
    const { field, maskingType, preserveFormat, replacement, condition } = rule;

    // Handle wildcard masking (remove all fields except resourceType)
    if (field === '*') {
      Object.keys(resource).forEach(key => {
        if (key !== 'resourceType' && key !== 'id') {
          delete resource[key];
        }
      });
      return;
    }

    // Apply field-specific masking
    this.applyFieldMasking(resource, field, maskingType, {
      preserveFormat,
      replacement,
      condition
    });
  }

  /**
   * Apply masking to specific fields
   */
  private applyFieldMasking(
    obj: any, 
    fieldPath: string, 
    maskingType: MaskingRule['maskingType'],
    options: {
      preserveFormat?: boolean;
      replacement?: string;
      condition?: string;
    } = {}
  ): void {
    if (!obj || typeof obj !== 'object') return;

    // Handle array indices in field path
    const pathParts = fieldPath.split('.');
    const currentField = pathParts[0];
    const remainingPath = pathParts.slice(1).join('.');

    // If this is the target field, apply masking
    if (pathParts.length === 1) {
      if (Object.prototype.hasOwnProperty.call(obj, currentField)) {
        obj[currentField] = this.maskValue(obj[currentField], maskingType, options);
      }
      return;
    }

    // Navigate deeper into the object structure
    if (obj[currentField]) {
      if (Array.isArray(obj[currentField])) {
        // Handle array fields
        obj[currentField].forEach((item: any) => {
          if (typeof item === 'object') {
            this.applyFieldMasking(item, remainingPath, maskingType, options);
          }
        });
      } else if (typeof obj[currentField] === 'object') {
        // Handle nested objects
        this.applyFieldMasking(obj[currentField], remainingPath, maskingType, options);
      }
    }
  }

  /**
   * Mask a specific value based on masking type
   */
  private maskValue(
    value: any, 
    maskingType: MaskingRule['maskingType'],
    options: {
      preserveFormat?: boolean;
      replacement?: string;
      condition?: string;
    } = {}
  ): any {
    if (value === null || value === undefined) {
      return value;
    }

    switch (maskingType) {
      case 'remove':
        return undefined; // Will be deleted by JSON.stringify

      case 'replace':
        return options.replacement || '***';

      case 'hash':
        return this.hashValue(value);

      case 'partial':
        return this.partialMask(value, options.preserveFormat);

      case 'aggregate':
        return this.aggregateValue(value);

      default:
        return value;
    }
  }

  /**
   * Derive a pseudonym token for a value.
   *
   * HMAC-SHA256 under a per-session key, not a bare digest (finding 4). A bare
   * `sha256(value)` is invertible for any low-entropy identifier: the valid
   * Israeli ID space is ~10^8 once the check digit is accounted for, so a
   * complete rainbow table is seconds of GPU time and fits on disk. Keying the
   * digest removes that attack, and making the key per-session also destroys
   * cross-session and cross-tenant linkability - two exports months apart no
   * longer share a mapping. Consistency WITHIN a session is preserved on
   * purpose, so a model can still join a subject across resources.
   */
  private hashValue(value: any): string {
    const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
    const now = Date.now();

    const cached = this.#hashCache.get(stringValue);
    if (cached) {
      if (now - cached.ts < this.cacheTtlMs) {
        return cached.token;
      }
      this.#hashCache.delete(stringValue);
    }

    const digest = crypto
      .createHmac('sha256', this.#sessionKey)
      .update(stringValue)
      .digest('base64url')
      .slice(0, PSEUDONYM_TOKEN_LENGTH);

    const token = PSEUDONYM_PREFIX + digest;

    this.cacheSet(stringValue, token, now);

    return token;
  }

  /**
   * Insert into the bounded cache, evicting by age first and then by insertion
   * order.
   *
   * Entry timestamps are set once at insertion and never refreshed, so Map
   * insertion order is age order - the first key is always the oldest.
   */
  private cacheSet(key: string, token: string, now: number): void {
    if (this.#hashCache.size >= this.cacheMaxEntries) {
      // Because insertion order IS age order, the cache can only contain an
      // expired entry if its FIRST entry is expired. That check is O(1), so a
      // full cache does not pay for a scan on every insert.
      const first = this.#hashCache.entries().next();
      if (!first.done && now - first.value[1].ts >= this.cacheTtlMs) {
        this.evictExpired(now);
      }
    }

    while (this.#hashCache.size >= this.cacheMaxEntries) {
      const oldest = this.#hashCache.keys().next();
      if (oldest.done) break;
      this.#hashCache.delete(oldest.value);
    }

    this.#hashCache.set(key, { token, ts: now });
  }

  /**
   * Drop every entry older than the TTL. Stops at the first live entry - age
   * order again - so this costs only what it actually evicts.
   */
  private evictExpired(now: number): void {
    for (const [key, entry] of this.#hashCache) {
      if (now - entry.ts < this.cacheTtlMs) {
        break;
      }
      this.#hashCache.delete(key);
    }
  }

  /**
   * Apply partial masking to preserve some information
   */
  private partialMask(value: any, preserveFormat: boolean = false): string {
    const stringValue = String(value);

    if (stringValue.length <= 2) {
      return '*'.repeat(stringValue.length);
    }

    // Handle different value types
    if (preserveFormat) {
      // Preserve format for structured data
      if (stringValue.includes('@')) {
        // Email: show first letter and domain
        const [local, domain] = stringValue.split('@');
        return `${local[0]}***@${domain}`;
      }
      
      if (stringValue.includes('-')) {
        // Phone/ID numbers: mask middle parts
        const parts = stringValue.split('-');
        return parts.map((part, index) => 
          index === 0 || index === parts.length - 1 
            ? part 
            : '*'.repeat(part.length)
        ).join('-');
      }
    }

    // Default partial masking: show first and last character
    if (stringValue.length <= 4) {
      return stringValue[0] + '*'.repeat(stringValue.length - 2) + stringValue.slice(-1);
    }

    return stringValue.substring(0, 2) + 
           '*'.repeat(stringValue.length - 4) + 
           stringValue.slice(-2);
  }

  /**
   * Aggregate value for statistical use
   */
  private aggregateValue(value: any): string {
    if (typeof value === 'number') {
      // Round numbers to ranges
      if (value < 10) return '<10';
      if (value < 100) return `${Math.floor(value / 10) * 10}-${Math.floor(value / 10) * 10 + 9}`;
      return `${Math.floor(value / 100) * 100}+`;
    }

    if (typeof value === 'string') {
      // Categorize strings
      if (/\d{4}-\d{2}-\d{2}/.test(value)) {
        // Date: show year only
        return value.substring(0, 4);
      }
      
      if (value.length < 5) return 'short';
      if (value.length < 20) return 'medium';
      return 'long';
    }

    return 'aggregated';
  }

  /**
   * Deep clone an object.
   *
   * Cycle-aware: a self-referencing `contained[]` would otherwise recurse until
   * the stack blows.
   */
  private deepClone(obj: any, seen: WeakMap<object, any> = new WeakMap()): any {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }

    if (obj instanceof Date) {
      return new Date(obj.getTime());
    }

    const existing = seen.get(obj);
    if (existing) {
      return existing;
    }

    if (Array.isArray(obj)) {
      const clonedArray: any[] = [];
      seen.set(obj, clonedArray);
      obj.forEach(item => clonedArray.push(this.deepClone(item, seen)));
      return clonedArray;
    }

    const cloned: any = {};
    seen.set(obj, cloned);
    Object.keys(obj).forEach(key => {
      cloned[key] = this.deepClone(obj[key], seen);
    });

    return cloned;
  }

  /**
   * Validate that masking was applied correctly
   */
  public validateMasking(original: any, masked: any, rules: MaskingRule[]): {
    valid: boolean;
    violations: string[];
  } {
    const violations: string[] = [];

    rules.forEach(rule => {
      const originalValue = this.getFieldValue(original, rule.field);
      const maskedValue = this.getFieldValue(masked, rule.field);

      // Check that sensitive data was properly masked
      if (rule.maskingType === 'remove' && maskedValue !== undefined) {
        violations.push(`Field ${rule.field} should have been removed`);
      }

      if (rule.maskingType === 'replace' && maskedValue === originalValue) {
        violations.push(`Field ${rule.field} should have been replaced`);
      }

      if (rule.maskingType === 'hash' && maskedValue === originalValue) {
        violations.push(`Field ${rule.field} should have been hashed`);
      }
    });

    return {
      valid: violations.length === 0,
      violations
    };
  }

  /**
   * Get field value using dot notation path
   */
  private getFieldValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => {
      return current && current[key] !== undefined ? current[key] : undefined;
    }, obj);
  }

  /** Clear the pseudonym cache. */
  public clearCache(): void {
    this.#hashCache.clear();
  }

  /**
   * Get masking engine statistics.
   *
   * Counts only. This must never expose cache keys (raw identifier values),
   * cache values (tokens), or the session key.
   */
  public getStats(): {
    cacheSize: number;
    cacheMaxEntries: number;
    cacheTtlMs: number;
    maxNestingDepth: number;
    totalMaskingOperations: number;
  } {
    return {
      cacheSize: this.#hashCache.size,
      cacheMaxEntries: this.cacheMaxEntries,
      cacheTtlMs: this.cacheTtlMs,
      maxNestingDepth: this.maxNestingDepth,
      totalMaskingOperations: this.maskingOperations
    };
  }

  /**
   * Belt and braces on top of the `#` fields: anything that serialises or
   * inspects the engine gets a safe summary, never key material or cache
   * contents.
   */
  public toJSON(): Record<string, unknown> {
    return {
      engine: 'PHIMaskingEngine',
      sessionKey: '[redacted]',
      hashCache: '[redacted]',
      ...this.getStats()
    };
  }

  public [Symbol.for('nodejs.util.inspect.custom')](): Record<string, unknown> {
    return this.toJSON();
  }
}
