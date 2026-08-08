/**
 * DOM construction for the vault origin.
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
 * `test/no-html-sinks.spec.ts` asserts it over the source, with ZERO declared
 * exemptions — the main app has one for its theme script; this origin has none
 * and must never acquire one.
 *
 * Text always arrives through `textContent`, which is a data assignment and not
 * a parse: a vault item whose title is `<img onerror=…>` renders as those
 * characters.
 */

export type Child = Node | string;

/** Attributes that may be set through `el`. Deliberately not `href`/`src`. */
export interface Attrs {
  readonly class?: string;
  readonly id?: string;
  readonly type?: string;
  readonly name?: string;
  readonly value?: string;
  readonly placeholder?: string;
  readonly autocomplete?: string;
  readonly disabled?: boolean;
  readonly hidden?: boolean;
  readonly role?: string;
  readonly for?: string;
  readonly rows?: string;
  readonly min?: string;
  readonly max?: string;
  readonly checked?: boolean;
  readonly readonly?: boolean;
  readonly spellcheck?: string;
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

export function text(value: string): Text {
  return document.createTextNode(value);
}

/** Replace a container's children. Used instead of any `innerHTML = ''`. */
export function replaceChildren(container: Element, ...children: readonly Child[]): void {
  container.replaceChildren(
    ...children.map((child) =>
      typeof child === 'string' ? document.createTextNode(child) : child,
    ),
  );
}

/**
 * A labelled input. One helper rather than three nodes at each call site,
 * because the label/id pairing is the part that gets forgotten and the vault is
 * not a surface where a screen-reader user should have to guess which field is
 * which.
 */
export interface FieldOptions {
  readonly id: string;
  readonly label: string;
  readonly type?: string;
  readonly value?: string;
  readonly autocomplete?: string;
  readonly hint?: string;
  readonly multiline?: boolean;
}

export interface Field {
  readonly row: HTMLElement;
  readonly input: HTMLInputElement | HTMLTextAreaElement;
}

export function field(options: FieldOptions): Field {
  const input = options.multiline
    ? el('textarea', { id: options.id, rows: '4', spellcheck: 'false' })
    : el('input', {
        id: options.id,
        type: options.type ?? 'text',
        // Browsers and password managers both act on this. `off` on a vault
        // field keeps ANOTHER manager from offering to save the secret this one
        // is holding — a small thing that would otherwise scatter copies.
        autocomplete: options.autocomplete ?? 'off',
        spellcheck: 'false',
      });
  if (options.value !== undefined) {
    input.value = options.value;
  }
  const row = el('div', { class: 'field' }, [
    el('label', { class: 'field-label', for: options.id }, [options.label]),
    ...(options.hint ? [el('p', { class: 'field-hint' }, [options.hint])] : []),
    input,
  ]);
  return { row, input };
}

export function onSubmit(form: HTMLFormElement, handler: () => void): void {
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    handler();
  });
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
