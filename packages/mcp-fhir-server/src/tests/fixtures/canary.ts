/**
 * The single canary identifier used by every PHI regression test.
 *
 * `000000018` is a VALID Israeli national ID (tudat zehut) taken from the
 * IL-Core specification's own example. It has LEADING ZEROS on purpose: any
 * regex that assumes a non-zero first digit will miss it, and that class of
 * bug is exactly what this constant exists to catch.
 *
 * Exported from one module and never inlined, so that a grep for the literal
 * finds only this file.
 */
export const CANARY = '000000018';

/**
 * The same digits as XHTML numeric character references. Valid XHTML, renders
 * identically, and defeats any detector applied to a raw narrative string.
 */
export const CANARY_ENTITY =
  '&#x30;&#x30;&#x30;&#x30;&#x30;&#x30;&#x30;&#x31;&#x38;';

/**
 * Hebrew name used by the IL-Core canonical Patient example ("Tamar Cohen"),
 * written with escapes so the fixture survives any encoding round trip.
 */
export const CANARY_NAME = '\u05EA\u05DE\u05E8 \u05DB\u05D4\u05DF';

/** The same name as numeric character references. */
export const CANARY_NAME_ENTITY = '&#x5EA;&#x5DE;&#x5E8; &#x5DB;&#x5D4;&#x5DF;';

/** First character of CANARY_NAME as an entity -- asserted absent from output. */
export const CANARY_NAME_ENTITY_FRAGMENT = '&#x5EA;';

/** base64 of the canary, as an Attachment.data blob would carry it. */
export const CANARY_BASE64 = Buffer.from(CANARY, 'utf8').toString('base64');
