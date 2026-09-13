import { createHmac, randomBytes } from 'node:crypto';
import { RESOURCE_PHI_MATRIX } from '../types/phi-types.js';


/**
 * Cap on the nesting audit metadata is walked to. Audit metadata is flat by
 * construction; an unbounded walk over caller-supplied structures is a
 * denial-of-service surface, and a cycle is a hang.
 */
const AUDIT_MAX_DEPTH = 4;

/** Cap on the length of any single string written to an audit record. */
const AUDIT_MAX_STRING = 200;

/**
 * THE ALLOWLIST: metadata keys that may be written to the audit log verbatim.
 *
 * Every entry here is an operational fact about the request -- who asked, what
 * they asked for by type, what the control decided, how long it took. None of
 * them is a field of a FHIR resource.
 *
 * Adding a key to this list is a privacy decision. The question to answer is
 * not "is this key useful" but "can a caller put a patient's data in it". If
 * the answer is yes or maybe, it belongs in AUDIT_HASHED_KEYS or nowhere.
 */
const AUDIT_SAFE_KEYS: ReadonlySet<string> = new Set([
  // Who and which request.
  'userId',
  'sessionId',
  'traceId',
  'requestId',
  'ipAddress',
  'userAgent',

  // What was attempted, by class only.
  'operation',
  // `resourceType` is DELIBERATELY ABSENT from this list and must stay absent.
  // It is caller-controlled free text that reaches the audit stream with no
  // credentials, so it is CONSTRAINED rather than allowlisted -- see
  // AuditLogger.safeResourceType(), which sanitizeMetadata() applies before this
  // allowlist is ever consulted. Putting the key back here would restore the
  // leak; if that branch is ever deleted instead, absence from this list means
  // the field is DROPPED, which is the correct direction to fail.
  'phiLevel',
  'accessGranted',
  'accessDenied',
  'stage',
  'reason',
  'denialReason',
  'errorName',
  'errorClass',
  'decision',
  'bypass',
  'phiMaskingBypass',
  'emergencyAccess',

  // Validation outcome, as classes rather than the offending input.
  'validationFailures',
  'failureCount',
  'failureClasses',
  'path',
  'field',
  'code',

  // Timing, counts and risk scoring.
  'timestamp',
  'accessTime',
  'hour',
  'duration',
  'processingTime',
  'riskLevel',
  'violationsDetected',
  'remainingRequests',
  'retryAfter',
  'resultCount',
  'suppressedCount',
  'resourceCount',
  'maskedFieldCount',
  'returned',
  'total',

  // Server lifecycle. Found by RUNNING the built server rather than by reading
  // it: startup emits an audit record describing its own configuration, and an
  // allowlist that had not been shown this record would have silently gutted
  // it. That is the allowlist's cost, and this is what paying it looks like --
  // once, visibly, by whoever adds the field.
  'phiMode',
  'auditEnabled',
  'securityFeaturesEnabled',
  'inputValidation',
  'rateLimiting',
  'securityHeaders',
  'healthcareCompliant',
  'phiAuthorization',
  'version',

  // Terminology operations: concept codes and canonical URLs, not PHI.
  'fhirVersion',
  'system',
  'url',
  'filter',
  'found'
]);

/**
 * Keys that name a DIRECT IDENTIFIER: hashed, not dropped.
 *
 * An audit trail that cannot say which record was touched is not much of an
 * audit trail (HIPAA 164.312(b) expects exactly that), so these keep their
 * correlating power and lose their content. A hashed id is emitted under
 * `<key>Hash` so no reader can mistake it for the raw value.
 */
const AUDIT_HASHED_KEYS: ReadonlySet<string> = new Set([
  'resourceId',
  'id',
  'identifier',
  'patientId',
  'subjectId',
  'mrn',
  'reference'
]);
/**
 * Per-process key for audit identifier hashing.
 *
 * WHY A KEY AT ALL
 * ----------------
 * What was here was `sha256(value).substring(0, 16)` under a docstring
 * claiming it was "not a reversible identifier on its own". That claim was
 * false, and its falsity was demonstrated rather than argued: a live patient id
 * was recovered from an audit line by direct comparison, because the logged
 * `05ed50b66d21a25a` IS `sha256('137230016')[0..15]`. An unkeyed digest of a
 * low-entropy identifier is an ENCODING of that identifier, not a protection of
 * it -- the Israeli national ID space is ~10^8 once the check digit is
 * accounted for, so the complete table is minutes of GPU time.
 *
 * This repo already knew that. `tests/fixtures/canary.ts` computes the
 * byte-identical value, names it LEGACY_UNSALTED_SHA256, and documents it as
 * "equivalent to publishing the ID". Two parts of one codebase held opposite
 * beliefs about the same expression, and the comment is what let the wrong one
 * survive review -- which is why the docstring below now states the property
 * the code actually has, and no more than that.
 *
 * The construction is now HMAC-SHA256, which is what
 * `PHIMaskingEngine.hashValue()` already does for pseudonym tokens. That part
 * is reuse rather than reinvention.
 *
 * THE KEY IS DELIBERATELY NOT PHIMaskingEngine's SESSION KEY
 * ---------------------------------------------------------
 * Sharing it is tempting, and the argument for it is real: an auditor holding a
 * masked export and an audit line could then join them on subject identity,
 * since both tokens would derive from one secret. It is still the wrong choice,
 * for three reasons that all reduce to the two streams having different
 * LIFETIMES:
 *
 *   1. RETENTION. The masking key is ephemeral on purpose -- fresh random bytes
 *      per construction, never persisted, rotatable, precisely so that two
 *      exports months apart share no mapping (see hashValue()). Audit records
 *      are retained for years (HIPAA 164.316(b)(2) says six) and are the one
 *      artefact expected to stay correlatable across that whole window. A key
 *      whose lifetime is one process cannot serve a record whose lifetime is
 *      six years: every restart would emit a different hash for the same
 *      patient, and the trail would lose exactly the correlating power
 *      AUDIT_HASHED_KEYS exists to preserve.
 *   2. ROTATION COUPLING. `rotateSessionKey()` clears the pseudonym cache.
 *      That is correct for masking and silent corruption for auditing: a
 *      rotation mid-run would re-key the audit stream in place, so one log file
 *      would hold two different hashes for one patient with nothing recording
 *      that the scheme changed underneath it. Misleading a reviewer is worse
 *      than telling them less.
 *   3. BLAST RADIUS. Audit logs are shipped off-box, to a SIEM with a different
 *      operator and a different threat model; masked resources go to a model.
 *      One key for both means a compromise of either context de-anonymises both
 *      streams at once.
 *
 * The correlation argument also has a better answer than key-sharing.
 * `traceId` is already on every record, already per-request, and is the correct
 * join key between an audit line and the response it describes. Joining the two
 * streams on SUBJECT identity is a re-identification capability, not a feature
 * to design for.
 *
 * DURABILITY, AND WHY THE DEFAULT IS STILL RANDOM
 * ----------------------------------------------
 * Set AUDIT_HASH_KEY (>= 32 bytes, hex or base64) to make hashes stable across
 * restarts, which is what a deployment that actually reviews its audit trail
 * wants. Unset, the key is random per process, so correlation is scoped to one
 * process lifetime. That is a loss of UTILITY and not of SAFETY -- an ephemeral
 * key is still non-invertible -- so it is the right direction for the default to
 * fail, and there is deliberately no startup requirement to supply one.
 */
let auditHashKey: Buffer | undefined;

/** Minimum accepted audit key length, and the size of a minted one. */
const AUDIT_HASH_KEY_MIN_BYTES = 32;

/** Resolve AUDIT_HASH_KEY, or mint an ephemeral key. See the block above. */
function resolveAuditHashKey(): Buffer {
  if (auditHashKey !== undefined) return auditHashKey;

  const configured = process.env.AUDIT_HASH_KEY;
  if (configured !== undefined && configured !== '') {
    const looksHex = /^[0-9a-fA-F]+$/.test(configured) && configured.length % 2 === 0;
    const decoded = looksHex
      ? Buffer.from(configured, 'hex')
      : Buffer.from(configured, 'base64');
    // A key too short to be worth having is REJECTED, not stretched. Silently
    // accepting a four-byte secret would put a brute-forceable hash back behind
    // a config option whose name reads as though it had secured something.
    if (decoded.length < AUDIT_HASH_KEY_MIN_BYTES) {
      throw new Error(
        `AUDIT_HASH_KEY must decode to at least ${AUDIT_HASH_KEY_MIN_BYTES} bytes (hex or base64)`
      );
    }
    auditHashKey = decoded;
    return auditHashKey;
  }

  auditHashKey = randomBytes(AUDIT_HASH_KEY_MIN_BYTES);
  return auditHashKey;
}

/**
 * Prefix on every audit identifier hash.
 *
 * Distinct from PHIMaskingEngine's `PT_` on purpose. The two token namespaces
 * come from DIFFERENT KEYS and must never be joined, so a reader needs to tell
 * at a glance which namespace a token belongs to -- otherwise `AH_x` failing to
 * match `PT_y` reads as "two different patients" when it actually means "two
 * different keys".
 */
export const AUDIT_HASH_PREFIX = 'AH_';

/** Digest characters kept after the prefix. 16 base64url chars is ~96 bits. */
const AUDIT_HASH_LENGTH = 16;

/**
 * Shape of an audit identifier hash, for gates and log consumers.
 *
 * Exported so an assertion does not have to re-derive the regex at a call site
 * where it would drift away from the producer.
 */
export const AUDIT_HASH_PATTERN = /^AH_[A-Za-z0-9_-]{16}$/;

/**
 * Emitted in place of a `resourceType` that is not in RESOURCE_PHI_MATRIX.
 *
 * Parenthesised and lower-case so it cannot collide with a real FHIR type name,
 * and so a reader can tell "we rejected what the caller sent" apart from "the
 * producer had nothing to send" (RESOURCE_TYPE_UNKNOWN).
 */
export const RESOURCE_TYPE_UNRECOGNISED = '(unrecognised)';

/** The producers' placeholder for "no resource type available". */
export const RESOURCE_TYPE_UNKNOWN = 'unknown';

export interface AuditEvent {
  timestamp: string;
  traceId: string;
  operation: string;
  resourceType?: string;
  resourceId?: string;
  resourceIdHash?: string;
  userId?: string;
  success: boolean;
  error?: string;
  duration?: number;
  metadata?: Record<string, unknown>;
}

export class AuditLogger {
  private enableAudit: boolean;

  constructor(enableAudit: boolean = true) {
    this.enableAudit = enableAudit;
  }

  log(event: Omit<AuditEvent, 'timestamp' | 'traceId'>) {
    if (!this.enableAudit) return;

    const auditEvent: AuditEvent = {
      ...event,
      timestamp: new Date().toISOString(),
      traceId: this.generateTraceId()
    };

    // Structural allowlist over metadata -- see sanitizeMetadata. What used to
    // be here was a keyword denylist, and it leaked.
    if (auditEvent.metadata) {
      auditEvent.metadata = this.sanitizeMetadata(auditEvent.metadata);
    }

    // A FHIR resource id is a direct identifier on the PHI path (fhir.read is
    // called with the caller's raw id). It was previously emitted verbatim as
    // a sibling of the redacted metadata. Replace it with a stable hash so the
    // audit trail stays correlatable without becoming a PHI store.
    if (auditEvent.resourceId !== undefined) {
      auditEvent.resourceIdHash = AuditLogger.hashIdentifier(auditEvent.resourceId);
      delete auditEvent.resourceId;
    }

    // `resourceType` is caller-controlled on every tool entry point: the tool
    // handlers build their SecurityContext from the RAW args (fhir-tools.ts
    // handleSearch/handleRead/handleCreate/handleUpdate all read
    // `args.resourceType` before validation), so a record describing a
    // validation FAILURE is populated from the value that failed. Constrained
    // here, at the single choke point, rather than at the producers -- a
    // guarantee expressed once per call site is a guarantee missing from every
    // call site nobody got to, which is the defect shape this file already
    // documents twice.
    if (auditEvent.resourceType !== undefined) {
      auditEvent.resourceType = AuditLogger.safeResourceType(auditEvent.resourceType);
    }

    // `error` is a failure CLASS, never a message: a thrown error routinely
    // quotes the resource that broke it. Producers pass
    // AuditLogger.errorClass(e). The bound below is only a blast-radius limit
    // for a producer not yet converted -- it cannot make a short PHI-bearing
    // message safe, which is why the contract lives at the producers.
    if (typeof auditEvent.error === 'string') {
      auditEvent.error = AuditLogger.boundString(auditEvent.error);
    }

    AuditLogger.emit(JSON.stringify(auditEvent));
  }

  logFhirOperation(
    operation: string,
    resourceType: string,
    resourceId?: string,
    success: boolean = true,
    error?: string,
    metadata?: Record<string, unknown>
  ) {
    this.log({
      operation: `fhir.${operation}`,
      resourceType,
      resourceId,
      success,
      error,
      metadata
    });
  }

  logTerminologyOperation(
    operation: string,
    success: boolean = true,
    error?: string,
    metadata?: Record<string, unknown>
  ) {
    this.log({
      operation: `terminology.${operation}`,
      success,
      error,
      metadata
    });
  }

  /**
   * Record a PHI masking/authorization failure.
   *
   * Records the *class* of failure only: resource type, a hashed resource id
   * and the error name. The error object itself is never accepted here, and
   * never logged, because a thrown error routinely carries the offending
   * resource directly or in a stack frame.
   */
  logMaskingFailure(failure: {
    resourceType?: string;
    resourceId?: string;
    errorName?: string;
    stage?: string;
  }) {
    this.log({
      operation: 'phi.masking_failure',
      resourceType: failure.resourceType ?? 'unknown',
      resourceId: failure.resourceId,
      success: false,
      error: failure.errorName ?? 'unknown',
      metadata: {
        stage: failure.stage ?? 'unknown'
      }
    });
  }

  /**
   * KEYED one-way hash of a direct identifier, for correlation without
   * exposure.
   *
   * HMAC-SHA256 under the process audit key (see the AUDIT_HASH_KEY block
   * above, which also records why that key is not PHIMaskingEngine's),
   * truncated to AUDIT_HASH_LENGTH base64url characters and prefixed `AH_`.
   *
   * The truncation bounds log size; it is NOT what provides the security
   * property. The KEY is. Stating it that way round matters, because the
   * previous docstring credited the truncation -- "truncated to 16 hex chars:
   * ... not a reversible identifier on its own" -- and that sentence is how a
   * plainly invertible construction survived review for as long as it did. An
   * unkeyed digest is invertible by enumeration at ANY truncation; a shorter
   * prefix makes it more collision-prone, not less reversible.
   *
   * Do not "simplify" this back to a bare digest. A regression test asserts the
   * output is not `sha256(value).substring(0, 16)`.
   */
  static hashIdentifier(value: string): string {
    if (value === '') return 'empty';
    const digest = createHmac('sha256', resolveAuditHashKey())
      .update(value)
      .digest('base64url')
      .slice(0, AUDIT_HASH_LENGTH);
    return AUDIT_HASH_PREFIX + digest;
  }

  /**
   * Replace the process audit hash key.
   *
   * Mirrors `PHIMaskingEngine.rotateSessionKey()`. There is no cache to clear
   * here because hashIdentifier is pure, but note what rotation costs a reader:
   * one log file would then hold two hashes for one subject. A rotation belongs
   * at a log boundary, not in the middle of one.
   */
  static rotateHashKey(newKey: Buffer = randomBytes(AUDIT_HASH_KEY_MIN_BYTES)): void {
    if (!Buffer.isBuffer(newKey) || newKey.length < AUDIT_HASH_KEY_MIN_BYTES) {
      throw new Error(
        `rotateHashKey requires a Buffer of at least ${AUDIT_HASH_KEY_MIN_BYTES} bytes`
      );
    }
    auditHashKey = newKey;
  }
  private generateTraceId(): string {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }

  /**
   * Structural allowlist over audit metadata.
   *
   * What was here before was a keyword DENYLIST --
   * `token|authorization|password|secret|ssn|birthdate` -- applied to the top
   * level of `metadata` only. Both halves of that were wrong, and both were
   * observed leaking in a live run against a real FHIR server:
   *
   *   - It is a denylist. A `fhir.search` on Patient wrote given and family
   *     names and a nine-digit national ID into the log in clear text, because
   *     `name`, `identifier` and `id` were not on the list. `birthdate` WAS
   *     redacted, which is precisely what made the control look like it was
   *     working. Adding the three missing keys moves the next miss rather than
   *     removing it: the set of PHI-bearing key names in FHIR is not
   *     enumerable, and callers nest arbitrary resource fragments here.
   *   - It was shallow. Anything one level down was never inspected at all.
   *
   * An allowlist inverts the failure mode. A key nobody anticipated is dropped
   * instead of published, which is the only direction a data-loss-prevention
   * control is allowed to fail in. The cost is that a genuinely useful new
   * field is silently missing until someone adds it to AUDIT_SAFE_KEYS -- paid
   * once, visibly, by whoever adds the field, instead of continuously and
   * invisibly by patients.
   */
  private sanitizeMetadata(
    data: Record<string, unknown>,
    depth: number = 0
  ): Record<string, unknown> {
    const clean: Record<string, unknown> = {};
    const dropped: string[] = [];

    for (const [key, value] of Object.entries(data)) {
      // Constrained, not allowlisted. This is the SECOND of the two places the
      // raw resourceType reached an audit record; the first is in log() above.
      if (key === 'resourceType') {
        clean.resourceType = AuditLogger.safeResourceType(value);
        continue;
      }

      if (AUDIT_HASHED_KEYS.has(key)) {
        if (typeof value === 'string') {
          clean[`${key}Hash`] = AuditLogger.hashIdentifier(value);
        } else if (value !== undefined && value !== null) {
          // An identifier that is not a string is not something this function
          // can hash without guessing. Drop it.
          dropped.push(key);
        }
        continue;
      }

      if (!AUDIT_SAFE_KEYS.has(key)) {
        dropped.push(key);
        continue;
      }

      clean[key] = this.sanitizeValue(value, depth);
    }

    // Record THAT something was withheld. An audit record that silently
    // shrinks is indistinguishable from one that was never populated, and a
    // reviewer needs to be able to tell those apart.
    if (depth === 0 && dropped.length > 0) {
      clean.redactedFields = dropped.map((name) => AuditLogger.safeKeyName(name));
    }

    return clean;
  }

  /**
   * Sanitize a value belonging to an allowlisted key.
   *
   * Structures are re-entered under the same allowlist, so an allowlisted
   * container cannot smuggle a denied key through its children.
   */
  private sanitizeValue(value: unknown, depth: number): unknown {
    if (value === null || value === undefined) return value;

    if (value instanceof Date) return value.toISOString();

    if (Array.isArray(value)) {
      if (depth >= AUDIT_MAX_DEPTH) return '[depth-capped]';
      return value.map((item) => this.sanitizeValue(item, depth + 1));
    }

    if (typeof value === 'object') {
      if (depth >= AUDIT_MAX_DEPTH) return '[depth-capped]';
      return this.sanitizeMetadata(value as Record<string, unknown>, depth + 1);
    }

    if (typeof value === 'string') return AuditLogger.boundString(value);

    return value;
  }

  /**
   * Allowlisted keys hold codes, classes and enum values, not prose. A long
   * string in one means a caller put something unexpected into an expected
   * key; truncate rather than publish it whole.
   */
  private static boundString(value: string): string {
    return value.length > AUDIT_MAX_STRING
      ? `${value.substring(0, AUDIT_MAX_STRING)}...[truncated]`
      : value;
  }

  /**
   * Constrain `resourceType` to the vocabulary this server actually knows.
   *
   * WHAT WAS WRONG
   * --------------
   * `resourceType` was on AUDIT_SAFE_KEYS, so it was written verbatim -- at the
   * top level of the record AND again inside `metadata` (security-middleware.ts
   * auditSecurityDenial() populates both). A resourceType of
   * `"Patient000000018"` therefore appeared in plaintext twice in one audit
   * record, reached with no credentials, on a request that FAILED validation.
   * That is narrower than the `originalInput` leak it outlived -- one field, and
   * only on the rejection path -- but it is still attacker-controlled free text
   * written verbatim into the audit stream: a log-injection and PHI-smuggling
   * channel that happens to be spelled as a type name.
   *
   * WHY CONSTRAIN RATHER THAN HASH OR DROP
   * --------------------------------------
   * `id` and `params` were already handled correctly and differently, and the
   * difference is the DOMAIN of the field, not the field's importance:
   *
   *   - `id` has an OPEN domain (any string), so it is HASHED: the value cannot
   *     be checked against anything, but correlation is worth keeping.
   *   - `params` has UNBOUNDED content, so it is DROPPED: nothing about it can
   *     be salvaged safely.
   *   - `resourceType` has a CLOSED, KNOWN domain -- it is a FHIR type name --
   *     so a third option is available that is strictly better than either.
   *     Check it against the vocabulary and emit it only if it is a member.
   *
   * Hashing would be actively wrong here, and wrong in exactly the way finding A
   * was: a hash over a ~50-element domain is reversible by enumeration on sight,
   * so it would look protected while protecting nothing. Dropping would work but
   * costs the operational fact -- which resource CLASS was touched -- on every
   * record, including the overwhelming majority that are legitimate.
   *
   * An unrecognised type becomes RESOURCE_TYPE_UNRECOGNISED. That is the
   * allowlist's usual cost, paid the usual way: a resource type this server
   * genuinely starts supporting is invisible in the audit trail until it is added
   * to RESOURCE_PHI_MATRIX -- once, visibly, by whoever adds it -- rather than
   * every unrecognised string being published forever. Note the matrix is
   * consulted with hasOwnProperty, not `in` or a truthy lookup: otherwise
   * `resourceType: "constructor"` would pass by inheriting from Object.
   */
  static safeResourceType(value: unknown): string {
    if (typeof value !== 'string' || value === '') return RESOURCE_TYPE_UNKNOWN;
    // The producers' own placeholder for "no type available" (fhir-tools.ts and
    // phi-authorization-engine.ts both pass it literally). Reserved so an
    // internal 'unknown' is not reported as a rejected caller value.
    if (value === RESOURCE_TYPE_UNKNOWN) return RESOURCE_TYPE_UNKNOWN;
    return Object.prototype.hasOwnProperty.call(RESOURCE_PHI_MATRIX, value)
      ? value
      : RESOURCE_TYPE_UNRECOGNISED;
  }

  /**
   * Audit metadata key names come from this codebase, not from callers. This
   * is belt and braces for the day that stops being true: a key name is not
   * allowed to become a smuggling channel for a value.
   */
  private static safeKeyName(name: string): string {
    return /^[A-Za-z0-9_]{1,40}$/.test(name) ? name : '(unnamed)';
  }

  /**
   * The CLASS of an error, for the `error` field of an audit record.
   *
   * Never `error.message`. A message is written by whoever threw, and in this
   * codebase that routinely means it quotes the resource: a forced throw during
   * a PHI authorization produced `error: "boom for patient <name> MRN <id>"` in
   * the audit stream. The class says what went wrong without saying who it
   * went wrong to.
   */
  static errorClass(error: unknown): string {
    if (error instanceof Error) {
      return error.name || error.constructor?.name || 'Error';
    }
    if (error === null || error === undefined) return 'UnknownError';
    if (typeof error === 'object') {
      return (error as { constructor?: { name?: string } }).constructor?.name ?? 'UnknownError';
    }
    return typeof error;
  }

  /**
   * Where audit records go: stderr, NOT stdout.
   *
   * This server speaks JSON-RPC over stdio (index.ts, StdioServerTransport),
   * so stdout is the protocol channel. Every record written with console.log
   * was interleaved with protocol frames on the same stream -- a correctness
   * bug for any client that parses the stream strictly, as much as a privacy
   * one, since the audit trail then lands wherever the client happens to pipe
   * the protocol rather than in a log the covered entity controls. The rest of
   * the server already writes diagnostics to stderr (index.ts uses
   * console.error for its whole startup banner), so stderr is both correct and
   * consistent.
   *
   * AUDIT_SINK=stdout restores the previous behaviour for a deployment that is
   * scraping audit records off stdout today.
   */
  private static emit(line: string): void {
    if (process.env.AUDIT_SINK === 'stdout') {
      console.log(line);
      return;
    }
    console.error(line);
  }
}