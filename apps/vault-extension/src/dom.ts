/**
 * DOM construction, and the absence of a parser.
 *
 * `createElement` and `textContent` only — there is no `innerHTML` anywhere in
 * this package and `test/fences.spec.ts` refuses one, with ZERO declared
 * exemptions. The vault origin can make that claim because it has no framework;
 * this artifact can make it for the same reason and one more: it is the piece
 * of the product that will eventually run beside code we did not write, and a
 * markup parser on that surface is the thing not to add.
 *
 * Deliberately no `href` or `src` helper. Either is an outbound GET, which
 * would be a second egress path alongside `api.ts` and would make the
 * one-network-module fence a statement about `fetch` rather than about the
 * network. The extension displays; it does not fetch pictures.
 */

type Child = string | Node;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: { class?: string; id?: string; type?: string; placeholder?: string } = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (attrs.class !== undefined) node.className = attrs.class;
  if (attrs.id !== undefined) node.id = attrs.id;
  if (attrs.type !== undefined && node instanceof HTMLInputElement) node.type = attrs.type;
  if (attrs.placeholder !== undefined && node instanceof HTMLInputElement) {
    node.placeholder = attrs.placeholder;
  }
  for (const child of children) {
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

/** Replace a container's contents. Text nodes in, never markup. */
export function render(into: HTMLElement, ...children: Child[]): void {
  into.replaceChildren(
    ...children.map((child) =>
      typeof child === 'string' ? document.createTextNode(child) : child,
    ),
  );
}
