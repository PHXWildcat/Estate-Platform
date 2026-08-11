/**
 * THE ONLY CODE IN THIS EXTENSION THAT RUNS INSIDE A PAGE (M16 PR3b, docs/03 §4 TB9).
 *
 * It is injected one-shot by `chrome.scripting.executeScript` at the moment of a
 * gesture in extension-owned UI, into ONE named frame, and then it is gone.
 * There is no declared content script and no persistent listener, so there is no
 * standing channel a page can address — the control is an ABSENCE, the same
 * shape as the vault origin's missing Trusted-Types policy.
 *
 * WHAT IT CANNOT DO, structurally rather than by discipline:
 *
 *   · It cannot ASK for anything. `func` is serialized and deserialized for
 *     injection, so it closes over nothing and carries no import; the credential
 *     arrives as an `args` value that the key holder already decided to send.
 *     There is no message it can post and no variant it could post — the popup
 *     union has no "give me a secret" member, and this function has no reference
 *     to `chrome` at all.
 *   · It cannot reach the network. `api.ts` is the extension's one call site
 *     (`test/fences.spec.ts`), and this file contains no fetch of any kind.
 *   · It cannot import the crypto. `packages/vault-crypto`'s declared-importer
 *     fence lists exactly one module in this package, and it is not this one.
 *
 * IT NEVER SUBMITS. §4 TB9 states that as an absolute and it is kept absolutely
 * here: no `form.submit()`, no synthetic Enter, no click on a submit control,
 * and deliberately NO `blur` event either — a page is free to submit on blur,
 * so dispatching one would be auto-submission by proxy. What is dispatched is
 * `input` and `change`, which is what a field needs to notice a value at all —
 * and nothing is FOCUSED either, because moving focus is itself how a blur is
 * fired. The first draft called `focus()` to look like a user and thereby broke
 * the promise in the paragraph above it.
 *
 * A NAIVE ASSIGNMENT IS ENOUGH, and this is the one place the usual advice is
 * wrong. The received wisdom for autofill is that a React-controlled field
 * ignores `el.value = x` because React's value tracker — an own-property setter
 * it installs on the node — records the write and then sees no change. MEASURED
 * in Chrome 151: that own property belongs to the PAGE's world and is invisible
 * from an isolated world, so an assignment made here reaches the native setter,
 * leaves the tracker stale, and the change is duly noticed. Both the naive form
 * and the prototype-setter dance fired the change event in the rig. The simpler
 * one is used, with the reason written down so nobody "fixes" it back.
 */

export interface FillPayload {
  readonly username: string;
  readonly secret: string;
}

/**
 * Fill the first plausible credential pair in this document.
 *
 * Returns a small report rather than throwing: the caller is a popup that may
 * already be closed, and a thrown error crossing the injection boundary carries
 * a stack naming internals for no one to read.
 */
export function fillIntoPage(payload: FillPayload): {
  readonly filledUsername: boolean;
  readonly filledSecret: boolean;
} {
  const editable = (node: Element | null): node is HTMLInputElement =>
    node instanceof HTMLInputElement && !node.disabled && !node.readOnly;

  const put = (node: HTMLInputElement, value: string): boolean => {
    if (value.length === 0) return false;
    // NOTHING IS FOCUSED HERE, and the first version of this function got that
    // wrong. Calling `focus()` to look like a user MOVES focus, and moving focus
    // fires `blur` on whatever held it — so the code claiming never to dispatch
    // a blur was dispatching two. Its own test caught it. A value can be set and
    // announced without focus, so no element is focused at any point; the cost
    // is that the caret is left where the user put it, which is also the polite
    // behaviour.
    node.value = value;
    // `input` is what a framework listens to; `change` is what a hand-written
    // validator usually listens to. Neither is `blur`, and neither submits.
    node.dispatchEvent(new Event('input', { bubbles: true }));
    node.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  };

  // The password field is the anchor: a login form without one is not a login
  // form, and guessing at a username-only page is how a fill lands somewhere it
  // was never meant to.
  const secretField = [...document.querySelectorAll('input[type="password"]')].find(editable);
  if (!secretField) return { filledUsername: false, filledSecret: false };

  // The username is looked for BEFORE the password field in document order, and
  // within the same form when there is one — which is what distinguishes a
  // login form's own username box from a search field elsewhere on the page.
  const scope: ParentNode = secretField.form ?? document;
  const candidates = [...scope.querySelectorAll('input')].filter(
    (node) =>
      editable(node) &&
      node !== secretField &&
      node.compareDocumentPosition(secretField) & Node.DOCUMENT_POSITION_FOLLOWING &&
      ['text', 'email', 'tel', 'username', ''].includes(node.type.toLowerCase()),
  );
  const usernameField = candidates[candidates.length - 1];

  const filledSecret = put(secretField, payload.secret);
  const filledUsername = usernameField ? put(usernameField, payload.username) : false;
  return { filledUsername, filledSecret };
}
