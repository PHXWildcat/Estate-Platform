import { PLACEHOLDER, type ClauseCondition, type TemplateSource } from './template-model';

/**
 * The deterministic rendering engine. Input: a validated template + a
 * validated intake payload. Output: canonical HTML bytes — same inputs, same
 * bytes, always — so `document_versions.content_sha256` is reproducible and
 * content addressing means something.
 *
 * Security posture:
 *  - Every substituted value is HTML-entity escaped; intake data is DATA and
 *    can never become markup, script, or structure (docs/03: user input is
 *    untrusted, including here where the "user" is the document owner).
 *  - A placeholder with no available value FAILS the render (never silently
 *    renders an empty blank into a legal instrument).
 *  - No dates, randomness, or environment access inside — determinism is the
 *    integrity property.
 */

export class RenderError extends Error {
  constructor(message: string) {
    // Message carries variable NAMES only, never values.
    super(message);
    this.name = 'RenderError';
  }
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function conditionHolds(
  when: ClauseCondition,
  variables: Record<string, string | boolean>,
): boolean {
  const name = typeof when === 'string' ? when : when.not;
  const value = variables[name];
  // Validation guarantees boolean-typed `when` variables; an absent optional
  // boolean counts as false.
  const truthy = value === true;
  return typeof when === 'string' ? truthy : !truthy;
}

function substitute(text: string, variables: Record<string, string | boolean>): string {
  return text.replace(PLACEHOLDER, (_match, name: string) => {
    const value = variables[name];
    if (typeof value !== 'string') {
      // Absent optional variable referenced by an included clause: fail
      // closed. Template authors gate such clauses with a boolean `when`.
      throw new RenderError(`no value for placeholder '${name}'`);
    }
    return escapeHtml(value);
  });
}

/** Paragraphs are blank-line separated within a clause's text. */
function paragraphs(text: string, variables: Record<string, string | boolean>): string {
  return text
    .split(/\n{2,}/)
    .map((p) => p.trim())
    .filter((p) => p.length > 0)
    .map((p) => `<p>${substitute(p, variables)}</p>`)
    .join('\n');
}

/**
 * Render a template to canonical HTML. `variables` must already have passed
 * `intakeSchemaFor(template)` — this function re-checks nothing about shape,
 * but still fails closed on any unsubstitutable placeholder.
 */
export function renderDocument(
  template: TemplateSource,
  variables: Record<string, string | boolean>,
): string {
  const sections = template.body
    .filter((clause) => clause.when === undefined || conditionHolds(clause.when, variables))
    .map((clause) => {
      const heading =
        clause.heading !== undefined ? `<h2>${substitute(clause.heading, variables)}</h2>\n` : '';
      return `<section>\n${heading}${paragraphs(clause.text, variables)}\n</section>`;
    });
  if (sections.length === 0) {
    throw new RenderError('no clauses rendered');
  }
  const title = escapeHtml(template.title);
  return [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    `<title>${title}</title>`,
    '</head>',
    '<body>',
    `<article data-doc-type="${template.docType}" data-state="${template.state}" data-template-version="${template.version}">`,
    `<h1>${title}</h1>`,
    ...sections,
    '</article>',
    '</body>',
    '</html>',
    '',
  ].join('\n');
}
