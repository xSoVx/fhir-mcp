import { describe, test, expect, beforeEach } from '@jest/globals';
import { PHIClassifier } from '../security/phi-classifier.js';
import { PHIAuthorizationEngine } from '../security/phi-authorization-engine.js';
import {
  decodeCharacterReferences,
  isValidIsraeliNationalId,
  redactFreeText,
  scrubNarrative,
  stripTags
} from '../security/narrative-scrubber.js';
import {
  CANARY,
  CANARY_ENTITY,
  CANARY_NAME,
  CANARY_NAME_ENTITY,
  CANARY_NAME_ENTITY_FRAGMENT
} from './fixtures/canary.js';
import { authorizeAndMask, createAuthEngine, serialize } from './fixtures/phi-harness.js';

const XHTML = 'http://www.w3.org/1999/xhtml';

function patientWithNarrative(div: string): Record<string, unknown> {
  return {
    resourceType: 'Patient',
    id: 'p1',
    text: { status: 'generated', div },
    identifier: [{ value: CANARY }]
  };
}

describe('Finding 3 - the narrative is not a field, it is untrusted HTML', () => {
  let engine: PHIAuthorizationEngine;

  beforeEach(() => {
    engine = createAuthEngine('permissive');
  });

  describe('safe mode (default policy)', () => {
    test('removes text entirely in safe mode', async () => {
      const resource = patientWithNarrative(
        '<div xmlns="' + XHTML + '">' + CANARY_NAME + ' ' + CANARY + '</div>'
      );

      const outcome = await authorizeAndMask(engine, resource);

      expect(outcome.authorized).toBe(true);
      expect(outcome.maskedResource).toBeDefined();
      expect((outcome.maskedResource as { text?: unknown }).text).toBeUndefined();
    });

    test('does not leak the canary through text.div', async () => {
      const resource = patientWithNarrative(
        '<div xmlns="' + XHTML + '">' + CANARY_NAME + ' ' + CANARY + '</div>'
      );

      const outcome = await authorizeAndMask(engine, resource);

      expect(outcome.authorized).toBe(true);
      expect(outcome.maskedResource).toBeDefined();
      const blob = serialize(outcome.maskedResource);
      expect(blob).not.toContain(CANARY);
      expect(blob).not.toContain(CANARY_NAME);
    });

    test('does not leak the canary as numeric character references', async () => {
      const resource = patientWithNarrative(
        '<div xmlns="' + XHTML + '">' + CANARY_NAME_ENTITY + ' ' + CANARY_ENTITY + '</div>'
      );

      const outcome = await authorizeAndMask(engine, resource);

      expect(outcome.authorized).toBe(true);
      expect(outcome.maskedResource).toBeDefined();
      const blob = serialize(outcome.maskedResource);
      expect(blob).not.toContain(CANARY);
      expect(blob).not.toContain(CANARY_ENTITY);
      expect(blob).not.toContain(CANARY_NAME_ENTITY_FRAGMENT);
    });

    test('the default policy is remove, even when an unknown policy is asked for', () => {
      // Fails closed: anything that is not exactly 'scrub' is 'remove'.
      const unknown = new PHIClassifier({ narrativePolicy: 'lenient' as never });
      expect(unknown.getNarrativePolicy()).toBe('remove');
      expect(new PHIClassifier().getNarrativePolicy()).toBe('remove');
    });

    test('the text rule is attached to a resource type with no case in the switch', () => {
      const classification = new PHIClassifier().classifyResource({
        resourceType: 'Condition',
        id: 'c1',
        text: { status: 'generated', div: '<div>x</div>' }
      });

      expect(
        classification.requiredMasking.some(
          rule => rule.field === 'text' && rule.maskingType === 'remove'
        )
      ).toBe(true);
    });
  });

  describe('scrub policy', () => {
    test('sets text.status to generated when div is replaced', () => {
      const classifier = new PHIClassifier({ narrativePolicy: 'scrub' });
      const classification = classifier.classifyResource(
        patientWithNarrative('<div xmlns="' + XHTML + '">' + CANARY_NAME + '</div>')
      );

      const statusRule = classification.requiredMasking.find(rule => rule.field === 'text.status');
      expect(statusRule).toBeDefined();
      expect(statusRule?.replacement).toBe('generated');
    });

    test('scrubbed narrative carries no canary in either form', () => {
      const classifier = new PHIClassifier({ narrativePolicy: 'scrub' });
      const classification = classifier.classifyResource(
        patientWithNarrative(
          '<div xmlns="' + XHTML + '">' + CANARY_NAME_ENTITY + ' ' + CANARY_ENTITY + '</div>'
        )
      );

      const divRule = classification.requiredMasking.find(rule => rule.field === 'text.div');
      expect(divRule).toBeDefined();
      expect(divRule?.replacement).not.toContain(CANARY);
      expect(divRule?.replacement).not.toContain(CANARY_NAME);
      expect(divRule?.replacement).not.toContain(CANARY_NAME_ENTITY_FRAGMENT);
    });

    test('falls back to removing text when there is no div to scrub', () => {
      const classifier = new PHIClassifier({ narrativePolicy: 'scrub' });
      const classification = classifier.classifyResource({
        resourceType: 'Patient',
        id: 'p9',
        identifier: [{ value: CANARY }]
      });

      expect(
        classification.requiredMasking.some(
          rule => rule.field === 'text' && rule.maskingType === 'remove'
        )
      ).toBe(true);
    });
  });

  describe('scrubber internals', () => {
    test('decode-then-strip order is load-bearing', () => {
      const div = '<div>' + CANARY_ENTITY + '</div>';

      // Correct order: decode first, so the detector sees digits.
      const correct = scrubNarrative(div);
      expect(correct.plainText).toBe(CANARY);
      expect(correct.matches.length).toBeGreaterThan(0);
      expect(correct.div).not.toContain(CANARY);

      // Reversed order: strip first, then detect on the still-encoded string.
      // This is what a naive implementation does, and it finds nothing --
      // which is why this test exists.
      const reversed = redactFreeText(stripTags(div));
      expect(reversed.matches).toHaveLength(0);
      expect(decodeCharacterReferences(reversed.text)).toContain(CANARY);
    });

    test('decodes hex, decimal and named references, and double encoding', () => {
      expect(decodeCharacterReferences('&#x5EA;')).toBe('\u05EA');
      expect(decodeCharacterReferences('&#1514;')).toBe('\u05EA');
      expect(decodeCharacterReferences('&amp;')).toBe('&');
      // Double-encoded: decoding runs to a fixpoint so the detector still sees
      // the digits. Over-decoding for detection is deliberate.
      expect(decodeCharacterReferences('&amp;#x30;')).toBe('0');
      expect(decodeCharacterReferences('plain text')).toBe('plain text');
    });

    test('strips tags, comments and attribute values', () => {
      const div =
        '<div title="' + CANARY + '"><!-- ' + CANARY + ' --><b>ok</b></div>';
      expect(stripTags(div)).toBe('ok');
    });

    test('accepts a valid Israeli ID with leading zeros', () => {
      // The canary. A check that requires a non-zero first digit fails here.
      expect(isValidIsraeliNationalId(CANARY)).toBe(true);
      expect(CANARY.startsWith('0')).toBe(true);
      expect(isValidIsraeliNationalId('000000019')).toBe(false);
      expect(isValidIsraeliNationalId('not-a-number')).toBe(false);
    });

    test('redacts emails, dates, phones and long digit runs', () => {
      const result = redactFreeText(
        'a@b.co 1980-01-01 0501234567 123456789012 ' + CANARY
      );
      expect(result.text).not.toContain('a@b.co');
      expect(result.text).not.toContain('1980-01-01');
      expect(result.text).not.toContain('0501234567');
      expect(result.text).not.toContain('123456789012');
      expect(result.text).not.toContain(CANARY);
    });

    test('rebuilt div is escaped and never carries input markup', () => {
      const result = scrubNarrative('<div><script>alert(1)</script>hello</div>');
      expect(result.div).toBe('<div xmlns="' + XHTML + '">hello</div>');
    });

    test('clean narratives survive scrubbing', () => {
      const result = scrubNarrative('<div>Blood pressure recorded</div>');
      expect(result.clean).toBe(true);
      expect(result.div).toContain('Blood pressure recorded');
    });
  });
});
