/**
 * The DOM helpers, and the absence they exist to preserve.
 *
 * There is no parser here and no `innerHTML` — `fences.spec.ts` refuses one
 * with zero exemptions. What these cases pin is that the helpers build TEXT
 * NODES from whatever they are given, so a value that looks like markup arrives
 * on screen as characters rather than as elements.
 */
import { el, render } from '../src/dom';

describe('building DOM without a parser', () => {
  it('sets only the attributes it is given', () => {
    const input = el('input', { id: 'x', type: 'text', placeholder: 'EP1-…', class: 'code' });
    expect(input.id).toBe('x');
    expect(input.type).toBe('text');
    expect(input.placeholder).toBe('EP1-…');
    expect(input.className).toBe('code');

    const bare = el('p');
    expect(bare.id).toBe('');
    expect(bare.className).toBe('');
  });

  it('ignores input-only attributes on a non-input element', () => {
    const paragraph = el('p', { type: 'text', placeholder: 'nope' });
    expect(paragraph.getAttribute('type')).toBeNull();
    expect(paragraph.getAttribute('placeholder')).toBeNull();
  });

  it('makes a TEXT NODE of a string child, whatever it looks like', () => {
    const node = el('p', {}, '<img src=x onerror=alert(1)>');
    expect(node.querySelector('img')).toBeNull();
    expect(node.textContent).toBe('<img src=x onerror=alert(1)>');
  });

  it('render replaces contents, and treats strings the same way', () => {
    const host = el('div', {}, el('span', {}, 'old'));
    render(host, 'a <b>bold</b> claim', el('em', {}, 'kept'));
    expect(host.querySelector('b')).toBeNull();
    expect(host.querySelector('em')?.textContent).toBe('kept');
    expect(host.textContent).toBe('a <b>bold</b> claimkept');
  });
});
