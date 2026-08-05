import { assertEgressClean, EgressRefusedError, inspectEgress } from '../src/privacy/egress';

describe('egress assertion — values that must never reach a provider', () => {
  it('refuses a dashed SSN', () => {
    expect(inspectEgress('the decedent, ssn 123-45-6789, held two trusts')).toEqual({
      clean: false,
      detector: 'ssn',
    });
  });

  it('refuses a space-separated SSN', () => {
    expect(inspectEgress('123 45 6789')).toEqual({ clean: false, detector: 'ssn' });
  });

  it('refuses a Luhn-valid card number, grouped or not', () => {
    // 4242 4242 4242 4242 is the canonical Luhn-valid test number.
    expect(inspectEgress('card 4242424242424242 on file')).toEqual({
      clean: false,
      detector: 'payment_card',
    });
    expect(inspectEgress('card 4242 4242 4242 4242 on file')).toEqual({
      clean: false,
      detector: 'payment_card',
    });
  });

  it('throws rather than returning a verdict a caller could ignore', () => {
    expect(() => assertEgressClean('123-45-6789')).toThrow(EgressRefusedError);
    expect(() => assertEgressClean('nothing sensitive here')).not.toThrow();
  });

  it('never puts the matched value in the error', () => {
    // The error message reaches logs. The entire point of the class is that
    // the value does not follow it there.
    try {
      assertEgressClean('ssn 123-45-6789');
      throw new Error('expected EgressRefusedError');
    } catch (err) {
      expect(err).toBeInstanceOf(EgressRefusedError);
      expect((err as Error).message).not.toContain('123-45-6789');
      expect((err as EgressRefusedError).detector).toBe('ssn');
    }
  });
});

describe('egress assertion — what it deliberately does NOT detect', () => {
  // These are documented non-detections, not gaps. A gate that fires on
  // ordinary estate traffic is a gate people route around; names, emails and
  // phone numbers are the PR2 tokenizer's job.
  it('passes an email address', () => {
    expect(inspectEgress('contact jane@example.com about the trust')).toEqual({ clean: true });
  });

  it('passes a phone number', () => {
    expect(inspectEgress('call 555-0142 before filing')).toEqual({ clean: true });
  });

  it('passes a personal name', () => {
    expect(inspectEgress('Jane Doe is the successor trustee')).toEqual({ clean: true });
  });

  it('passes a bare nine-digit run', () => {
    // Nine consecutive digits in an estate conversation are far more often an
    // amount in cents or an identifier than an SSN. Matching them would make
    // the detector noisy enough to be disabled.
    expect(inspectEgress('the account balance was 123456789 cents')).toEqual({ clean: true });
  });

  it('passes a card-shaped run that fails the Luhn check', () => {
    // Order numbers and long identifiers are card-shaped. The structural check
    // is what lets this detector be fail-closed instead of advisory.
    expect(inspectEgress('order 4242424242424243')).toEqual({ clean: true });
  });

  it('passes ordinary money and dates', () => {
    expect(inspectEgress('valued at 1,250,000.00 on 2026-08-04')).toEqual({ clean: true });
  });
});
