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

  it('THIS CODE never submits — narrowed from an absolute, because a page may', () => {
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

  /**
   * ORDER, AND THE CLAIM THAT HAD TO BE NARROWED WITH IT (M16 review).
   *
   * A fill has to dispatch `input` and `change` or no framework notices the
   * value — and the module's own reason for withholding `blur` ("a page is free
   * to submit on blur") is true of those too. So "nothing is ever
   * auto-submitted" was never the extension's to promise. What IS its to
   * promise is which field is written last.
   */
  it('writes the USERNAME first, so a page that commits on the password has both', () => {
    document.body.innerHTML = `
      <form>
        <input id="u" type="text">
        <input id="p" type="password">
      </form>`;
    const seen: Array<{ on: string; username: string; secret: string }> = [];
    const snap = (on: string) => (): void => {
      seen.push({
        on,
        username: (document.getElementById('u') as HTMLInputElement).value,
        secret: (document.getElementById('p') as HTMLInputElement).value,
      });
    };
    document.getElementById('p')?.addEventListener('change', snap('password change'));
    document.getElementById('u')?.addEventListener('change', snap('username change'));

    fillIntoPage({ username: 'alice@example.com', secret: 'REAL-PASSWORD' });

    // The password's change is the LAST event and the one a login form acts on.
    expect(seen.at(-1)?.on).toBe('password change');
    // And by then the username is present. It used to be '' — the page got the
    // real secret with a field the user never filled.
    expect(seen.at(-1)?.username).toBe('alice@example.com');
    // The username's own change fired before the secret existed, which is the
    // harmless direction.
    expect(seen[0]).toEqual({ on: 'username change', username: 'alice@example.com', secret: '' });
  });

  it('a page CAN observe the fill — stated, because the extension cannot prevent it', () => {
    // Not a defect and not fixable: the events are what make a fill work. It is
    // pinned so nobody re-asserts the absolute the docs used to carry.
    document.body.innerHTML = `<form><input id="p" type="password"></form>`;
    let observed = '';
    document.getElementById('p')?.addEventListener('input', () => {
      observed = (document.getElementById('p') as HTMLInputElement).value;
    });
    fillIntoPage({ username: '', secret: 'REAL-PASSWORD' });
    expect(observed).toBe('REAL-PASSWORD');
  });
});
