/**
 * @jest-environment jsdom
 */

/**
 * THE CODE THAT TOUCHES A PAGE, and mostly what it must refuse to do.
 *
 * `fillIntoPage` is injected into somebody else's document (docs/03 §4 TB9), so
 * the cases that matter are the absences: it never submits, it never dispatches
 * `blur` (which a page may itself submit on), it fills nothing when there is no
 * password field to anchor on, and it does not reach outside the form it found.
 */
import { fillIntoPage } from '../src/fill-into-page';

const render = (html: string): void => {
  document.body.innerHTML = html;
};

const LOGIN = `
  <form id="login">
    <input id="u" name="username" type="text">
    <input id="p" name="password" type="password">
    <button type="submit">Sign in</button>
  </form>`;

describe('filling a page', () => {
  it('fills the password and the username before it, and reports both', () => {
    render(LOGIN);
    expect(fillIntoPage({ username: 'someone', secret: 's3cret' })).toEqual({
      filledUsername: true,
      filledSecret: true,
    });
    expect((document.getElementById('u') as HTMLInputElement).value).toBe('someone');
    expect((document.getElementById('p') as HTMLInputElement).value).toBe('s3cret');
  });

  it('NEVER SUBMITS — the absolute §4 TB9 states', () => {
    render(LOGIN);
    const submits: Event[] = [];
    document.getElementById('login')?.addEventListener('submit', (event) => {
      event.preventDefault();
      submits.push(event);
    });
    fillIntoPage({ username: 'someone', secret: 's3cret' });
    expect(submits).toEqual([]);
  });

  it('dispatches input and change, and deliberately NOT blur', () => {
    render(LOGIN);
    const seen: string[] = [];
    for (const type of ['input', 'change', 'blur', 'keydown', 'keypress'] as const) {
      document
        .getElementById('p')
        ?.addEventListener(type, () => seen.push(type), { capture: true });
    }
    fillIntoPage({ username: 'someone', secret: 's3cret' });
    expect(seen).toContain('input');
    expect(seen).toContain('change');
    // A page is free to submit on blur, so dispatching one would be
    // auto-submission by proxy. Synthetic keys are not sent either.
    expect(seen).not.toContain('blur');
    expect(seen).not.toContain('keydown');
    expect(seen).not.toContain('keypress');
  });

  it('fills NOTHING when there is no password field to anchor on', () => {
    // A page with a lone text box is not a login form, and guessing is how a
    // credential lands somewhere it was never meant to.
    render('<form><input id="q" type="text" name="search"></form>');
    expect(fillIntoPage({ username: 'someone', secret: 's3cret' })).toEqual({
      filledUsername: false,
      filledSecret: false,
    });
    expect((document.getElementById('q') as HTMLInputElement).value).toBe('');
  });

  it('does not take a username from outside the form it found', () => {
    render(`
      <input id="outside" type="text">
      <form><input id="inside" type="text"><input id="p" type="password"></form>`);
    fillIntoPage({ username: 'someone', secret: 's3cret' });
    expect((document.getElementById('inside') as HTMLInputElement).value).toBe('someone');
    expect((document.getElementById('outside') as HTMLInputElement).value).toBe('');
  });

  it('skips disabled and read-only fields rather than pretending to fill them', () => {
    render('<form><input id="u" type="text" disabled><input id="p" type="password"></form>');
    expect(fillIntoPage({ username: 'someone', secret: 's3cret' })).toEqual({
      filledUsername: false,
      filledSecret: true,
    });

    render('<form><input id="p" type="password" readonly></form>');
    expect(fillIntoPage({ username: 'someone', secret: 's3cret' })).toEqual({
      filledUsername: false,
      filledSecret: false,
    });
  });

  it('reports an empty secret as not filled rather than writing an empty string', () => {
    render(LOGIN);
    expect(fillIntoPage({ username: '', secret: '' })).toEqual({
      filledUsername: false,
      filledSecret: false,
    });
    expect((document.getElementById('p') as HTMLInputElement).value).toBe('');
  });

  it('takes the username field NEAREST the password, not the first on the page', () => {
    render(`
      <form>
        <input id="first" type="text">
        <input id="near" type="text">
        <input id="p" type="password">
      </form>`);
    fillIntoPage({ username: 'someone', secret: 's3cret' });
    expect((document.getElementById('near') as HTMLInputElement).value).toBe('someone');
    expect((document.getElementById('first') as HTMLInputElement).value).toBe('');
  });
});
