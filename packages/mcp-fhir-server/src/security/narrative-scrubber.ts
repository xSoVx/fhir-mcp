/**
 * Narrative Scrubber
 *
 * `DomainResource.text.div` is untrusted XHTML, not a field. HIS "human
 * readable" renderers routinely inline the full patient banner into it — name,
 * national ID, date of birth, HMO, address — and the Israeli IL-Core IG
 * constrains the narrative not at all (its own canonical Patient example is a
 * `div` containing the patient's name).
 *
 * The processing order below is load-bearing:
 *
 *   1. decode numeric character references
 *   2. strip tags
 *   3. run the free-text detector over the result
 *
 * Decoding MUST come first. `&#x5EA;&#x5DE;&#x5E8;` is valid XHTML for Hebrew
 * text, and the canary's digits encode the same way (`&#x30;&#x30;&#x30;...`),
 * so any detector applied to the raw string sees no Hebrew and no digits and
 * reports the narrative clean.
 *
 * This module is a *best-effort* scrubber for the non-safe path. It is a
 * heuristic over free text and will never be complete, which is exactly why
 * `NarrativePolicy` defaults to `'remove'`: the narrative is derived, never
 * authoritative, and no clinical decision should depend on it.
 */

export type PhiMatchKind =
  | 'email'
  | 'phone'
  | 'date'
  | 'israeli-national-id'
  | 'long-digit-run'
  | 'hebrew-name';

export interface PhiMatch {
  kind: PhiMatchKind;
  value: string;
}

export interface NarrativeScrubResult {
  /** Rebuilt, escaped XHTML div. Never empty. */
  div: string;
  /** Decoded, tag-stripped plain text, before redaction. */
  plainText: string;
  /** Plain text after redaction. */
  redactedText: string;
  /** What the detector found, in detection order. */
  matches: PhiMatch[];
  /** True when the detector found nothing to redact. */
  clean: boolean;
}

const XHTML_NS = 'http://www.w3.org/1999/xhtml';

/**
 * Decoding is run to a fixpoint, so `&amp;#x30;` (double-encoded) also
 * resolves. That deliberately over-decodes legitimately escaped text — which
 * is the right trade for a *detector*: it may over-report, never under-report.
 * The value written back out is re-escaped, so over-decoding cannot inject
 * markup.
 */
const MAX_DECODE_PASSES = 5;

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' '
};

function decodeOnce(input: string): string {
  return input.replace(
    /&(#[xX][0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]*);/g,
    (whole: string, body: string): string => {
      if (body.charAt(0) === '#') {
        const isHex = body.charAt(1) === 'x' || body.charAt(1) === 'X';
        const digits = isHex ? body.slice(2) : body.slice(1);
        const code = parseInt(digits, isHex ? 16 : 10);
        if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) {
          return whole;
        }
        try {
          return String.fromCodePoint(code);
        } catch {
          return whole;
        }
      }
      const named = NAMED_ENTITIES[body.toLowerCase()];
      return named === undefined ? whole : named;
    }
  );
}

/** Step 1 — decode numeric and named character references. */
export function decodeCharacterReferences(input: string): string {
  let out = input;
  for (let pass = 0; pass < MAX_DECODE_PASSES; pass++) {
    const next = decodeOnce(out);
    if (next === out) {
      return out;
    }
    out = next;
  }
  return out;
}

/**
 * Step 2 — strip tags. Whole tags go, which takes attribute values
 * (`title="..."`, `alt="..."`) with them; attributes carry PHI as readily as
 * element content does.
 */
export function stripTags(input: string): string {
  return input
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Israeli national ID (tudat zehut) check digit.
 *
 * The value is LEFT-PADDED to nine digits, so leading zeros are valid and
 * meaningful: `000000018` is a valid ID and is the IL-Core specification's own
 * example. Nothing here may require a non-zero leading digit.
 */
export function isValidIsraeliNationalId(candidate: string): boolean {
  if (!/^[0-9]{1,9}$/.test(candidate)) {
    return false;
  }
  const padded = candidate.padStart(9, '0');
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    let increment = Number(padded.charAt(i)) * ((i % 2) + 1);
    if (increment > 9) {
      increment -= 9;
    }
    sum += increment;
  }
  return sum % 10 === 0;
}

interface Detector {
  kind: PhiMatchKind;
  pattern: RegExp;
  accept?: (value: string) => boolean;
}

/**
 * Order matters. Dates are consumed first, then a check-digit-valid national
 * ID, then the looser phone and generic digit-run patterns. Every branch here
 * still redacts, so a mis-ordered detector mislabels but never leaks.
 */
const DETECTORS: Detector[] = [
  {
    kind: 'email',
    pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g
  },
  {
    kind: 'date',
    pattern: /\b(?:[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{1,2}[./][0-9]{1,2}[./][0-9]{2,4})\b/g
  },
  {
    kind: 'israeli-national-id',
    pattern: /(?<![0-9])[0-9]{5,9}(?![0-9])/g,
    accept: isValidIsraeliNationalId
  },
  {
    kind: 'phone',
    pattern: /(?:\+972[-\s]?|\b0)(?:[0-9][-\s]?){8,9}\b/g
  },
  {
    // MRNs, account numbers, any other long structured identifier.
    kind: 'long-digit-run',
    pattern: /(?<![0-9])[0-9]{6,}(?![0-9])/g
  },
  {
    // Two or more consecutive Hebrew words: overwhelmingly a person's name in
    // a narrative banner. Deliberately conservative, and deliberately not
    // relied upon — see the module header.
    kind: 'hebrew-name',
    pattern: /[\u0590-\u05FF]{2,}(?:[\s\u00A0]+[\u0590-\u05FF]{2,})+/g
  }
];

function redactionToken(kind: PhiMatchKind): string {
  return '[REDACTED-' + kind.toUpperCase() + ']';
}

/** Step 3 — detect and redact PHI in decoded, tag-free text. */
export function redactFreeText(text: string): { text: string; matches: PhiMatch[] } {
  const matches: PhiMatch[] = [];
  let working = text;

  for (const detector of DETECTORS) {
    // Fresh RegExp per call: the module-level literals carry /g lastIndex state.
    const pattern = new RegExp(detector.pattern.source, detector.pattern.flags);
    working = working.replace(pattern, (value: string): string => {
      if (detector.accept && !detector.accept(value)) {
        return value;
      }
      matches.push({ kind: detector.kind, value });
      return redactionToken(detector.kind);
    });
  }

  return { text: working, matches };
}

function escapeXhtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Scrub a narrative `div`: decode -> strip -> detect -> rebuild.
 *
 * The returned `div` is freshly constructed and escaped, so no markup,
 * attribute, comment or character reference from the input survives into it.
 */
export function scrubNarrative(div: string): NarrativeScrubResult {
  const decoded = decodeCharacterReferences(div ?? '');
  const plainText = stripTags(decoded);
  const { text: redactedText, matches } = redactFreeText(plainText);

  return {
    div: '<div xmlns="' + XHTML_NS + '">' + escapeXhtml(redactedText) + '</div>',
    plainText,
    redactedText,
    matches,
    clean: matches.length === 0
  };
}
