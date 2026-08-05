/**
 * The finding vocabulary every analyser speaks (M10 PR3).
 *
 * ===========================================================================
 * WHY THE ANALYSERS ARE DETERMINISTIC CODE AND NOT PROMPTS
 * ===========================================================================
 *
 * docs/00 feature 6 asks for funding recommendations, missing-document and
 * beneficiary-conflict detection, and estate-tax estimation. Every one of those
 * is a question about STRUCTURE — is this asset titled in the trust, do these
 * shares total 100%, is the estate above the exemption — over facts the platform
 * already computes and stores. None of them needs a language model, and giving
 * one the job would mean a number on a user's estate-readiness panel was a token
 * sampled from a distribution.
 *
 * So the split is: THE ANALYSER COMPUTES, THE MODEL EXPLAINS. Findings carry
 * enum `code`s from the closed unions below, not prose, and the conversational
 * layer turns a code into a sentence. That has three consequences worth stating.
 * A finding can be rendered by the UI (PR4) with no model involved at all. Two
 * users with the same estate get the same findings, which is what makes the
 * feature testable. And an injected instruction in a document cannot invent a
 * finding, because findings are not text the model produced — the worst it can
 * do is describe a real one badly.
 *
 * ===========================================================================
 * EDUCATION AND ANALYSIS ONLY
 * ===========================================================================
 *
 * docs/01 §2.8: assistant outputs "are education/analysis only and are
 * watermarked in-product as non-legal-advice". Every analyser result therefore
 * carries `disclaimer` as a required field rather than leaving it to whatever
 * renders the result — a warning that a caller may forget to display is not a
 * warning. `analysis.spec.ts` asserts every analyser's result carries one, and
 * PR4 renders it adjacent to the findings, never behind a disclosure triangle.
 */

/** How much a finding should worry the reader. Three levels, deliberately. */
export type FindingSeverity =
  /** A gap with a real consequence today (an intestate estate, a 60% designation). */
  | 'high'
  /** Worth fixing, no immediate exposure (an unexecuted draft, partial funding). */
  | 'medium'
  /** Informational: the estate is fine here, and saying so is the useful answer. */
  | 'info';

/**
 * What a finding is ABOUT, as an id and a label.
 *
 * `label` is user-authored text (an asset or document title), so it is
 * tokenized on the way to a provider like every other title — the tokenizer's
 * rules name these paths explicitly. `ref` is a UUID from the owning service,
 * which is what lets PR4 link a finding to the thing it is about, and what lets
 * a later "fix this" flow exist without the analyser having to describe the
 * subject in prose.
 */
export interface FindingSubject {
  readonly kind: 'asset' | 'document' | 'estate';
  /** Null for an estate-level finding, which is about no single row. */
  readonly ref: string | null;
  /** Null when the subject has no user-authored label (an estate-level finding). */
  readonly label: string | null;
}

/**
 * One finding. `code` is the load-bearing field: it is a closed token, so the
 * set of things this platform can tell a user about their estate is enumerable,
 * reviewable, and cannot grow because a model decided it should.
 *
 * `detail` carries the numbers behind the code — share percentages, money as
 * decimal strings, counts — as structured values rather than as a rendered
 * sentence, so the UI and the model format them independently and neither is
 * parsing the other's prose.
 */
export interface Finding<TCode extends string> {
  readonly code: TCode;
  readonly severity: FindingSeverity;
  readonly subject: FindingSubject;
  readonly detail: Readonly<Record<string, string | number | boolean | null>>;
}

/**
 * The standing non-advice watermark (docs/01 §2.8). One constant, so every
 * surface says the same thing and a spec can assert its presence.
 */
export const ANALYSIS_DISCLAIMER =
  'This is an automated analysis of the information in your account, for education only. ' +
  'It is not legal or tax advice, and it does not account for facts the platform does not hold. ' +
  'Confirm anything that matters with a licensed attorney or tax professional in your state.';

/**
 * What every analyser returns.
 *
 * `status` distinguishes THREE things that must never be confused, which is the
 * same distinction the tool layer draws between a refusal and an empty result:
 *
 *   * `ok`        — the analysis ran; `findings` is the answer, and an empty
 *                   list means "nothing found", which is a real result.
 *   * `unavailable` — an input could not be read (a peer was down). NOT an
 *                   empty estate. A user with twelve assets must never be told
 *                   their beneficiary designations are complete because the
 *                   assets service was restarting.
 *   * `refused`   — the analysis exists but must not run here, today. The
 *                   estate-tax analyser refuses in production while its
 *                   reference data is unreviewed (see `reference/`).
 */
export type AnalysisResult<TCode extends string, TSummary> =
  | {
      readonly status: 'ok';
      readonly findings: readonly Finding<TCode>[];
      readonly summary: TSummary;
      readonly disclaimer: string;
    }
  | {
      readonly status: 'unavailable';
      /** Enum token, never an upstream message. */
      readonly reason: 'upstream_unavailable';
      readonly disclaimer: string;
    }
  | {
      readonly status: 'refused';
      readonly reason: 'reference_unreviewed';
      readonly disclaimer: string;
    };

/** The `unavailable` result, built in one place so its shape cannot drift. */
export function analysisUnavailable<TCode extends string, TSummary>(): AnalysisResult<
  TCode,
  TSummary
> {
  return {
    status: 'unavailable',
    reason: 'upstream_unavailable',
    disclaimer: ANALYSIS_DISCLAIMER,
  };
}

/** The `refused` result. Only the reference-data gate produces this today. */
export function analysisRefused<TCode extends string, TSummary>(): AnalysisResult<TCode, TSummary> {
  return {
    status: 'refused',
    reason: 'reference_unreviewed',
    disclaimer: ANALYSIS_DISCLAIMER,
  };
}

/** The `ok` result. Callers never build one by hand, so `disclaimer` cannot be forgotten. */
export function analysisOk<TCode extends string, TSummary>(
  findings: readonly Finding<TCode>[],
  summary: TSummary,
): AnalysisResult<TCode, TSummary> {
  return { status: 'ok', findings, summary, disclaimer: ANALYSIS_DISCLAIMER };
}

/** An estate-level subject: the finding is about the estate, not one row. */
export const ESTATE_SUBJECT: FindingSubject = { kind: 'estate', ref: null, label: null };
