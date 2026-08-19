/**
 * DOM construction for the operator origin.
 *
 * EVERY node in this app is built here, and this module contains no way to
 * parse markup. That is not a style preference — it is what makes the origin's
 * `require-trusted-types-for 'script'` / `trusted-types 'none'` policy
 * enforceable at all. With no Trusted-Types policy in existence, any assignment
 * to `innerHTML`, `outerHTML`, `insertAdjacentHTML` or `document.write` THROWS
 * in the browser rather than parsing, so an injection has nowhere to land.
 *
 * The absence is the control, exactly as M11's `MessageText` is: there is no
 * parser to misconfigure, no allowlist to widen, and no dependency.
 * `test/fences.spec.ts` asserts it over the source, with ZERO declared
 * exemptions — the main app has one for its theme script; this origin has none
 * and must never acquire one.
 *
 * Text always arrives through `textContent`, which is a data assignment and not
 * a parse. That matters more here than it looks: the strings this console will
 * render are reporter-supplied case notes and provider signal payloads, which
 * is to say untrusted input on a screen somebody reads before authorizing a
 * lock on a living person's account.
 */

export type Child = Node | string;

/** Attributes that may be set through `el`. Deliberately not `href`/`src`. */
export interface Attrs {
  readonly class?: string;
  readonly id?: string;
  readonly type?: string;
  readonly disabled?: boolean;
  readonly hidden?: boolean;
  readonly role?: string;
  readonly 'aria-live'?: string;
  readonly 'aria-label'?: string;
  readonly 'data-testid'?: string;
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: readonly Child[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (value === true) {
      node.setAttribute(key, '');
      continue;
    }
    node.setAttribute(key, String(value));
  }
  for (const child of children) {
    // A string child becomes a TEXT NODE. There is deliberately no branch here
    // that would interpret one as markup.
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

/** Replace a container's children. Used instead of any `innerHTML = ''`. */
export function replaceChildren(container: Element, ...children: readonly Child[]): void {
  container.replaceChildren(
    ...children.map((child) =>
      typeof child === 'string' ? document.createTextNode(child) : child,
    ),
  );
}

export function onClick(node: Element, handler: () => void): void {
  node.addEventListener('click', (event) => {
    event.preventDefault();
    handler();
  });
}

export function requireElement(id: string): HTMLElement {
  const node = document.getElementById(id);
  if (!node) {
    // A wiring mistake, not a runtime condition: the shell is static and ships
    // in the same artifact as this code.
    throw new Error(`missing element: ${id}`);
  }
  return node;
}
