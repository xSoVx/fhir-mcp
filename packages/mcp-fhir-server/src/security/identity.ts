/**
 * Caller identity for the MCP tool surface.
 * ---------------------------------------------------------------------------
 * WHY THIS FILE EXISTS
 *
 * `PHIAuthorizationEngine.hasPatientLevelAccess()` and
 * `SecurityMiddleware.performComplianceChecks()` both gate on a caller
 * identity, and nothing in the tool layer ever produced one: `fhir-tools.ts`
 * built its `SecurityContext` without `userId` and passed a literal
 * `undefined` user to `PhiGuard.authorizeAndMaskResource()`. The consequence
 * measured against a live FHIR server was that every IDENTIFIABLE resource was
 * SUPPRESSED before masking, so the masking engine never executed in
 * production. This module supplies the missing identity.
 *
 * THE FAIL-CLOSED CONTRACT
 *
 * The behaviour that must not be introduced is "safe-looking but permissive".
 * Therefore:
 *
 *   1. ABSENCE IS DENIAL. `servicePrincipalFromEnv()` returns `undefined` when
 *      no principal is configured. `undefined` flows to exactly the same call
 *      sites that previously received a hard-coded `undefined`, so an
 *      unconfigured deployment behaves bit-for-bit as it does today: denied.
 *      There is no built-in, fallback or anonymous principal anywhere in this
 *      module, and no code path constructs one.
 *
 *   2. MISCONFIGURATION IS A STARTUP ERROR, NOT A DEGRADED MODE. An
 *      unrecognised scope, a malformed id, or an id declared with no scopes
 *      throws. This mirrors `parsePhiGuardMode()`: a DLP control refuses to
 *      start rather than quietly resolve to something weaker.
 *
 *   3. ONE GRANT PATH. Permissions are derived from declared scopes and from
 *      nothing else. `roles` is always `[]` and `phiAccessLevel` is never set,
 *      because both are independent grant routes inside
 *      `PHIAuthorizationEngine` (`roles.includes('admin')`,
 *      `phiAccessLevel === PHILevel.RESTRICTED`). Leaving them unpopulated
 *      means SCOPE_GRANTS below is the complete, auditable statement of what
 *      configuration can grant.
 *
 *   4. BREAK-GLASS STAYS UNREACHABLE FROM CONFIG. `emergencyAccessEnabled` is
 *      pinned `false`. The emergency grant is the only `allow-bypass` route
 *      that returns PHI UNMASKED, and no environment variable may open it.
 *
 * WHAT THIS IS NOT
 *
 * This is not an OAuth2 / SMART-on-FHIR authorization server. The README
 * advertises Authorization Code + PKCE and client credentials; the repository
 * contains only two orphan type declarations for it (`AuthConfig` in
 * types/config.ts, `AuthConfigSchema` in tools/schemas.ts) and no
 * implementation, and README's own roadmap lists OAuth2 flows as unstarted
 * Phase 2 work. Rather than build a parallel identity system, this module
 * defines the seam that a real token issuer plugs into later: anything that
 * can verify a caller produces a `User` and hands it to an `IdentityProvider`.
 * `SCOPE_GRANTS` deliberately uses SMART scope spelling so that an issued
 * access token's `scope` claim maps onto it without translation.
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import { User } from '../types/phi-types.js';

/**
 * The closed set of scopes this server understands, and the engine
 * permissions each one grants. Spelling follows SMART on FHIR
 * `<context>/<resource>.<operation>`.
 *
 * This table is the ENTIRE grant surface. It is intentionally coarse: the
 * authorization engine's own permission vocabulary (`patient:read`,
 * `restricted:read`, ...) is not resource-type-scoped, so a per-type scope
 * would imply a precision the engine cannot enforce. Advertising
 * `system/Patient.read` while the engine grants all-of-IDENTIFIABLE would be
 * exactly the safe-looking-but-permissive failure this lane exists to avoid.
 *
 * `x-restricted/*.read` is a LOCAL extension, not a SMART scope, and is named
 * with an `x-` prefix to say so. SMART has no concept of this project's
 * RESTRICTED tier (Coverage, Claim, ExplanationOfBenefit, Bundle, Binary), so
 * reaching that tier requires opting in to a scope that cannot be confused
 * with a standard one, and never comes along for the ride with a read scope.
 */
export const SCOPE_GRANTS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  'patient/*.read': Object.freeze(['patient:read']),
  'user/*.read': Object.freeze(['patient:read']),
  'system/*.read': Object.freeze(['patient:read']),
  'patient/*.write': Object.freeze(['patient:write']),
  'user/*.write': Object.freeze(['patient:write']),
  'system/*.write': Object.freeze(['patient:write']),
  'x-restricted/*.read': Object.freeze(['restricted:read'])
});

export const SUPPORTED_SCOPES: readonly string[] = Object.freeze(Object.keys(SCOPE_GRANTS));

/**
 * A caller identity resolved from configuration or from a verified request.
 *
 * Extends `User` so it drops straight into `PhiGuard.authorizeAndMaskResource`
 * and `PHIAuthorizationEngine.authorizeResourceAccess` with no adapter.
 */
export interface ServicePrincipal extends User {
  readonly id: string;
  readonly roles: string[];
  readonly permissions: string[];
  readonly emergencyAccessEnabled: false;
  /** The scopes this principal was configured with, retained for audit. */
  readonly scopes: readonly string[];
  /** Where the identity came from. Audit-visible, never a grant input. */
  readonly source: PrincipalSource;
}

export type PrincipalSource = 'configured-service-identity' | 'http-bearer-verified';

/** Principal ids appear in audit records, so keep them boring and bounded. */
const PRINCIPAL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;

export function parsePrincipalId(value: unknown, source: string): string {
  if (typeof value === 'string' && PRINCIPAL_ID_PATTERN.test(value)) {
    return value;
  }
  throw new Error(
    `identity: invalid principal id ${JSON.stringify(value)} (from ${source}). ` +
      'Expected 1-128 characters matching [A-Za-z0-9][A-Za-z0-9._:@-]*. ' +
      'Identity refuses to start rather than admit an unloggable principal.'
  );
}

/**
 * Parse a scope string into the closed set above.
 *
 * Accepts `unknown` for the same reason `parsePhiGuardMode` does: the real
 * failure is an env var that is absent, empty, or a near-miss spelling. Every
 * one of those is a startup error.
 */
export function parseScopes(value: unknown, source: string): string[] {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(
      `identity: no scopes declared (from ${source}). ` +
        'A principal with no scopes grants nothing and almost always means a ' +
        `misconfiguration. Declare one or more of: ${SUPPORTED_SCOPES.join(' | ')}.`
    );
  }

  const tokens = value.split(/[,\s]+/).filter(token => token.length > 0);
  const unknownScopes = tokens.filter(token => !Object.prototype.hasOwnProperty.call(SCOPE_GRANTS, token));

  if (unknownScopes.length > 0) {
    throw new Error(
      `identity: unrecognised scope(s) ${JSON.stringify(unknownScopes)} (from ${source}). ` +
        `Supported: ${SUPPORTED_SCOPES.join(' | ')}. ` +
        'An unrecognised scope is refused rather than ignored, because ignoring ' +
        'it would silently produce a principal weaker or broader than intended.'
    );
  }

  return Array.from(new Set(tokens));
}

/** Map declared scopes onto engine permissions. The only grant computation. */
export function permissionsForScopes(scopes: readonly string[]): string[] {
  const permissions = new Set<string>();
  for (const scope of scopes) {
    for (const permission of SCOPE_GRANTS[scope] ?? []) {
      permissions.add(permission);
    }
  }
  return Array.from(permissions).sort();
}

export function buildPrincipal(
  id: unknown,
  scopes: unknown,
  source: PrincipalSource,
  configSource: string
): ServicePrincipal {
  const parsedId = parsePrincipalId(id, `${configSource}.id`);
  const parsedScopes = parseScopes(scopes, `${configSource}.scopes`);

  return Object.freeze({
    id: parsedId,
    // Always empty. See contract note 3: roles are an independent grant route
    // inside the authorization engine and configuration may not use it.
    roles: [],
    permissions: permissionsForScopes(parsedScopes),
    // Always false. See contract note 4: this is the only unmasked-allow route.
    emergencyAccessEnabled: false as const,
    scopes: Object.freeze([...parsedScopes]),
    source
  });
}

export const PRINCIPAL_ID_ENV = 'MCP_SERVICE_PRINCIPAL_ID';
export const PRINCIPAL_SCOPES_ENV = 'MCP_SERVICE_PRINCIPAL_SCOPES';

/**
 * Build the configured service identity, or `undefined` when none is declared.
 *
 * `undefined` is the DEFAULT and it is not a degraded mode: it reproduces the
 * pre-existing behaviour exactly (every PHI-bearing resource denied). Only an
 * operator explicitly setting `MCP_SERVICE_PRINCIPAL_ID` changes that, and
 * even then the resource comes back MASKED - lane E's invariant guarantees
 * that any `allowed: true` at IDENTIFIABLE or above carries a non-empty rule
 * set.
 */
export function servicePrincipalFromEnv(
  env: NodeJS.ProcessEnv = process.env
): ServicePrincipal | undefined {
  const rawId = env[PRINCIPAL_ID_ENV];
  if (rawId === undefined || rawId.trim() === '') {
    return undefined;
  }
  return buildPrincipal(
    rawId.trim(),
    env[PRINCIPAL_SCOPES_ENV],
    'configured-service-identity',
    `process.env.${PRINCIPAL_ID_ENV}`
  );
}

/**
 * The seam the tool layer depends on. One method, deliberately: the tool layer
 * must not be able to construct, widen or default an identity - only ask for
 * whichever one the transport already established.
 */
export interface IdentityProvider {
  resolvePrincipal(): User | undefined;
}

/** Fixed identity for the lifetime of the process (stdio transport). */
export class StaticIdentityProvider implements IdentityProvider {
  constructor(private readonly principal?: User) {}

  resolvePrincipal(): User | undefined {
    return this.principal;
  }
}

/**
 * Identity bound to the currently-executing request (HTTP transport).
 *
 * The MCP `Server` and its `FhirTools` are singletons shared across SSE
 * sessions, and the `CallToolRequest` handler never sees the `IncomingMessage`
 * - so a per-caller identity cannot be threaded through the SDK's signatures.
 * `AsyncLocalStorage` carries it instead, entered in `http.ts` only after the
 * bearer token has actually been verified.
 *
 * Outside such a scope `getStore()` is `undefined`, which is the denial case.
 * That is the important property: a tool call arriving through any route that
 * did not go through `runWithPrincipal` gets no identity at all.
 */
export class RequestScopedIdentityProvider implements IdentityProvider {
  private readonly storage = new AsyncLocalStorage<User>();

  runWithPrincipal<T>(principal: User | undefined, fn: () => T): T {
    if (!principal) {
      // No verified identity: run OUTSIDE any store so resolvePrincipal()
      // returns undefined. Never inherit an outer request's principal.
      return this.storage.exit(fn);
    }
    return this.storage.run(principal, fn);
  }

  resolvePrincipal(): User | undefined {
    return this.storage.getStore();
  }
}

/** Explicit no-identity provider. Used as the default so that omitting an
 *  IdentityProvider denies rather than grants. */
export const ANONYMOUS_IDENTITY_PROVIDER: IdentityProvider = Object.freeze({
  resolvePrincipal(): User | undefined {
    return undefined;
  }
});

/** Audit-safe one-line description of a principal. Never logs secrets. */
export function describePrincipal(principal: User | undefined): string {
  if (!principal) {
    return 'none (unauthenticated - PHI access will be denied)';
  }
  const scopes = (principal as ServicePrincipal).scopes;
  return `${principal.id} [${(scopes ?? []).join(' ')}] -> ${principal.permissions.join(',')}`;
}