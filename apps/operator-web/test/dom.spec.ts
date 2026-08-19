/**
 * @jest-environment jsdom
 */

/**
 * The DOM helper, which is the runtime counterpart of a fence.
 *
 * `fences.spec.ts` asserts that no source file on this origin NAMES an HTML
 * sink. That is the static half. This is the behavioural one: every path
 * through `el` and `replaceChildren` produces nodes rather than parsed markup,
 * so a value that looks like a tag arrives as characters.
 *
 * It matters because of what this console will render. Reporter-supplied case
 * notes and provider signal payloads are untrusted input, shown on a screen
 * somebody reads before authorizing a lock on a living person's account.
 */
import { el, onClick, replaceChildren, requireElement } from '../src/client/dom';

beforeEach(() => {
  document.body.replaceChildren();
});

describe('every node is built, never parsed', () => {
  it('turns a string child into a TEXT node, whatever it looks like', () => {
    const node = el('p', {}, ['<img src=x onerror=alert(1)>']);
    expect(node.childNodes).toHaveLength(1);
    expect(node.childNodes[0]?.nodeType).toBe(Node.TEXT_NODE);
    expect(node.textContent).toBe('<img src=x onerror=alert(1)>');
    expect(node.querySelector('img')).toBeNull();
  });

  it('does the same for a string passed to replaceChildren', () => {
    const host = el('div');
    replaceChildren(host, '<script>evil()</script>', el('span', {}, ['ok']));
    expect(host.querySelector('script')).toBeNull();
    expect(host.textContent).toBe('<script>evil()</script>ok');
  });

  it('sets attributes as strings, and a `true` as a bare attribute', () => {
    const node = el('button', { class: 'button', disabled: true, hidden: false, id: 'x' });
    expect(node.getAttribute('class')).toBe('button');
    // A boolean attribute is present-with-empty-value; `false` is ABSENT rather
    // than the string "false", which would be truthy to the browser.
    expect(node.getAttribute('disabled')).toBe('');
    expect(node.hasAttribute('hidden')).toBe(false);
    expect(node.getAttribute('id')).toBe('x');
  });

  it('prevents the default on a click, so a handler cannot navigate by accident', () => {
    const button = el('button', { type: 'button' });
    document.body.append(button);
    let ran = 0;
    onClick(button, () => {
      ran += 1;
    });
    const event = new MouseEvent('click', { cancelable: true, bubbles: true });
    button.dispatchEvent(event);
    expect(ran).toBe(1);
    expect(event.defaultPrevented).toBe(true);
  });

  it('throws on a missing element, because the shell is static', () => {
    // A wiring mistake rather than a runtime condition: the shell ships in the
    // same artifact as this code, so a missing id is a bug to see loudly rather
    // than a state to degrade through.
    expect(() => requireElement('nope')).toThrow(/missing element/);
    const main = el('main', { id: 'app' });
    document.body.append(main);
    expect(requireElement('app')).toBe(main);
  });
});
