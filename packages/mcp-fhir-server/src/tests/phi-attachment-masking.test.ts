import { describe, test, expect, beforeEach } from '@jest/globals';
import { PHIClassifier } from '../security/phi-classifier.js';
import { PHIAuthorizationEngine } from '../security/phi-authorization-engine.js';
import { CANARY, CANARY_BASE64 } from './fixtures/canary.js';
import { authorizeAndMask, createAuthEngine, serialize } from './fixtures/phi-harness.js';

interface Attachment {
  contentType?: string;
  data?: string;
  size?: number;
  hash?: string;
  title?: string;
}

describe('Finding 6 - Attachment.data carries the document, not a pointer to it', () => {
  let engine: PHIAuthorizationEngine;

  beforeEach(() => {
    engine = createAuthEngine('permissive');
  });

  test('removes attachment data but keeps contentType, size and hash', async () => {
    const documentReference = {
      resourceType: 'DocumentReference',
      id: 'dr1',
      status: 'current',
      subject: { reference: 'Patient/p1' },
      content: [
        {
          attachment: {
            contentType: 'application/pdf',
            data: CANARY_BASE64,
            size: 12345,
            hash: 'c3VtLWhhc2g=',
            title: 'Discharge summary'
          }
        }
      ]
    };

    const outcome = await authorizeAndMask(engine, documentReference);

    expect(outcome.authorized).toBe(true);
    expect(outcome.maskedResource).toBeDefined();

    const masked = outcome.maskedResource as { content: Array<{ attachment: Attachment }> };
    const attachment = masked.content[0].attachment;

    expect(attachment.data).toBeUndefined();
    // The model is still told a document exists.
    expect(attachment.contentType).toBe('application/pdf');
    expect(attachment.size).toBe(12345);
    expect(attachment.hash).toBe('c3VtLWhhc2g=');
  });

  test('does not leak a base64-encoded canary', async () => {
    const documentReference = {
      resourceType: 'DocumentReference',
      id: 'dr2',
      status: 'current',
      content: [{ attachment: { contentType: 'application/pdf', data: CANARY_BASE64 } }]
    };

    const outcome = await authorizeAndMask(engine, documentReference);

    expect(outcome.authorized).toBe(true);
    expect(outcome.maskedResource).toBeDefined();

    const blob = serialize(outcome.maskedResource);
    // Assert the ENCODED form, not just the plaintext -- the plaintext never
    // appears in a base64 blob, so asserting it alone proves nothing.
    expect(blob).not.toContain(CANARY_BASE64);
    expect(blob).not.toContain(CANARY);
  });

  test('removes presentedForm data on DiagnosticReport', async () => {
    const report = {
      resourceType: 'DiagnosticReport',
      id: 'rep1',
      status: 'final',
      subject: { reference: 'Patient/p1' },
      presentedForm: [
        { contentType: 'application/pdf', data: CANARY_BASE64, size: 999 },
        { contentType: 'image/png', data: CANARY_BASE64 }
      ]
    };

    const outcome = await authorizeAndMask(engine, report);

    expect(outcome.authorized).toBe(true);
    expect(outcome.maskedResource).toBeDefined();

    const masked = outcome.maskedResource as { presentedForm: Attachment[] };
    expect(masked.presentedForm[0].data).toBeUndefined();
    expect(masked.presentedForm[1].data).toBeUndefined();
    expect(masked.presentedForm[0].contentType).toBe('application/pdf');
    expect(serialize(outcome.maskedResource)).not.toContain(CANARY_BASE64);
  });

  test('removes Media.content.data', async () => {
    const media = {
      resourceType: 'Media',
      id: 'm1',
      status: 'completed',
      content: { contentType: 'image/jpeg', data: CANARY_BASE64, size: 42 }
    };

    const classification = new PHIClassifier().classifyResource(media);
    expect(
      classification.requiredMasking.some(
        rule => rule.field === 'content.data' && rule.maskingType === 'remove'
      )
    ).toBe(true);
  });

  test('removes Binary.data', async () => {
    const binary = {
      resourceType: 'Binary',
      id: 'b1',
      contentType: 'application/pdf',
      data: CANARY_BASE64
    };

    const classification = new PHIClassifier().classifyResource(binary);
    expect(
      classification.requiredMasking.some(
        rule => rule.field === 'data' && rule.maskingType === 'remove'
      )
    ).toBe(true);
  });

  test('the attachment rules reach a resource type with no case in the switch', () => {
    // Communication has no `case`. It must still get the attachment rules.
    const classification = new PHIClassifier().classifyResource({
      resourceType: 'Communication',
      id: 'comm1',
      status: 'completed'
    });

    const fields = classification.requiredMasking.map(rule => rule.field);
    expect(fields).toContain('payload.contentAttachment.data');
    expect(fields).toContain('content.attachment.data');
  });

  test('a nested attachment inside contained[] is NOT yet stripped - lane D owns recursion', async () => {
    // Documented gap, asserted so it cannot be mistaken for coverage.
    // The masking engine selects rules from the OUTER resource type and never
    // recurses into contained[], so a contained DocumentReference keeps its
    // blob. Finding 5 (phi-masking-engine.ts) fixes this; when it lands, this
    // expectation flips and this test becomes a real canary case.
    const observation = {
      resourceType: 'Observation',
      id: 'o1',
      status: 'final',
      contained: [
        {
          resourceType: 'DocumentReference',
          id: 'inner',
          status: 'current',
          content: [{ attachment: { contentType: 'application/pdf', data: CANARY_BASE64 } }]
        }
      ],
      subject: { reference: '#inner' }
    };

    const outcome = await authorizeAndMask(engine, observation);

    expect(outcome.authorized).toBe(true);
    expect(outcome.maskedResource).toBeDefined();
    expect(serialize(outcome.maskedResource)).toContain(CANARY_BASE64);
  });
});
