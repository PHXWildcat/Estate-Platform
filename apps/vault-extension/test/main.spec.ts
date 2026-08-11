/**
 * The popup's entry point, smoke-tested.
 *
 * `vault-web` leaves its two `main.ts` bootstraps at 0% and says why: a test
 * that imports one only proves it can be imported. That is true of the import,
 * and it is not true of what this asserts — that the entry FINDS its mount
 * point and renders. The realistic regression is a renamed element id or a
 * moved script tag, which no other test in this package would catch and which
 * ships as a permanently blank popup.
 */
import { clearChromeDouble, installChromeDouble } from './chrome-double';

describe('the popup entry', () => {
  afterEach(() => {
    clearChromeDouble();
    jest.resetModules();
  });

  it('mounts into the element the shell provides', async () => {
    installChromeDouble();
    (globalThis as { fetch?: unknown }).fetch = () =>
      Promise.resolve({
        ok: true,
        status: 200,
        text: () => Promise.resolve('{}'),
      } as unknown as Response);

    // The id here must match `public/popup.html`; that agreement is the whole
    // point of the case.
    document.body.innerHTML = '';
    const root = document.createElement('main');
    root.id = 'root';
    document.body.append(root);

    await import('../src/main');
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(document.body.textContent).toContain('Connect to Estate');
  });

  it('does nothing at all when the mount point is absent', async () => {
    installChromeDouble();
    document.body.innerHTML = '';
    await expect(import('../src/main')).resolves.toBeDefined();
    expect(document.body.textContent).toBe('');
  });
});
