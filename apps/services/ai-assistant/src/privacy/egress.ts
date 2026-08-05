/**
 * The last gate before anything leaves for a model provider (docs/03 §4 TB5:
 * "PII tokenization before any model call").
 *
 * SCOPE, stated precisely so this is not mistaken for a tokenizer. M10 PR2
 * introduces the tokenizer that replaces names and user-authored titles with
 * per-conversation placeholders. THIS module is narrower and different in kind:
 * it is a fail-closed assertion for values that must never leave the platform
 * in ANY form, tokenized or not. An SSN does not get a placeholder — a
 * round-tripped SSN is still an SSN that crossed TB5, and the docs/02 rule that
 * SSNs get no blind index because "no legitimate SSN-equality search exists"
 * has the same shape as the rule here: there is no legitimate reason for one to
 * reach a model provider.
 *
 * Deliberately NOT detected here: email addresses, phone numbers and personal
 * names. Those are the tokenizer's job, they have legitimate presence in an
 * estate conversation, and blocking on them would produce a gate people
 * route around. A gate that fires on the wrong things gets disabled; this one
 * fires only on values whose presence is unambiguously a defect.
 */

/** Category tokens. What gets audited — never the matched text itself. */
export type EgressDetector = 'ssn' | 'payment_card';

export type EgressVerdict =
  { readonly clean: true } | { readonly clean: false; readonly detector: EgressDetector };

export class EgressRefusedError extends Error {
  constructor(readonly detector: EgressDetector) {
    // Category only. The message reaches logs, and the whole point of this
    // class is that the matched value must not.
    super(`outbound payload refused by the egress assertion (${detector})`);
    this.name = 'EgressRefusedError';
  }
}

/**
 * Separated SSNs only. A bare nine-digit run is not matched on purpose: in an
 * estate conversation nine consecutive digits are far more often an account
 * balance in cents or an identifier than an SSN, and a detector with a high
 * false-positive rate on ordinary traffic is one that gets switched off.
 */
const SSN = /\b\d{3}[- ]\d{2}[- ]\d{4}\b/;

/** Candidate card numbers: 13–19 digits, optionally grouped by spaces or dashes. */
const CARD_CANDIDATE = /\b(?:\d[ -]?){12,18}\d\b/g;

/**
 * Luhn check digit. Card-shaped digit runs are common in ordinary text (order
 * numbers, long identifiers), so the structural check is what makes this
 * detector precise enough to be fail-closed rather than advisory.
 */
function passesLuhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    const char = digits[i];
    if (char === undefined) {
      return false;
    }
    let value = char.charCodeAt(0) - 48;
    if (value < 0 || value > 9) {
      return false;
    }
    if (double) {
      value *= 2;
      if (value > 9) {
        value -= 9;
      }
    }
    sum += value;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * Inspect an outbound payload. Returns the first category found; callers turn
 * a non-clean verdict into a refusal plus an audited `assistant.egress.refused`
 * event, because a control that fires silently is indistinguishable from a
 * control that never fired (the M9 rule about gates auditing themselves).
 */
export function inspectEgress(payload: string): EgressVerdict {
  if (SSN.test(payload)) {
    return { clean: false, detector: 'ssn' };
  }
  for (const match of payload.matchAll(CARD_CANDIDATE)) {
    const digits = match[0].replace(/[ -]/g, '');
    if (digits.length >= 13 && digits.length <= 19 && passesLuhn(digits)) {
      return { clean: false, detector: 'payment_card' };
    }
  }
  return { clean: true };
}

/** Fail-closed wrapper: throws rather than returning a value the caller might ignore. */
export function assertEgressClean(payload: string): void {
  const verdict = inspectEgress(payload);
  if (!verdict.clean) {
    throw new EgressRefusedError(verdict.detector);
  }
}
