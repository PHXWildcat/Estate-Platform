import { DocTypeSchema, UsStateSchema } from '@estate/contracts';
import { z } from 'zod';

/**
 * The template source model — the JSON files under
 * `apps/services/documents/templates/<state>/<doc_type>/v<N>.json`, published
 * to the object store + `document_templates` by the publish CLI.
 *
 * Templates are DELIBERATELY not a programming language: a body is a list of
 * clauses, a clause is text with `{{placeholder}}` substitution, and the only
 * conditional form is a single boolean variable (optionally negated). No
 * expressions, no loops, no helpers, no eval — rendering a legal instrument
 * is a security-critical path, so the engine is small enough to audit in one
 * sitting (the same rationale as the node:crypto webhook verifier).
 */

/** Variable/placeholder names: lowerCamelCase identifiers. */
export const VARIABLE_NAME = /^[a-z][a-zA-Z0-9]{0,63}$/;

const VariableNameSchema = z.string().regex(VARIABLE_NAME);

/** Calendar-checked ISO date (YYYY-MM-DD). */
export const IsoDateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .refine((s) => {
    const [y = 0, m = 0, d = 0] = s.split('-').map(Number);
    const date = new Date(Date.UTC(y, m - 1, d));
    return date.getUTCFullYear() === y && date.getUTCMonth() === m - 1 && date.getUTCDate() === d;
  }, 'not a calendar date');

const TextVariableSchema = z.object({
  name: VariableNameSchema,
  kind: z.literal('text'),
  label: z.string().min(1).max(200).optional(),
  required: z.boolean().default(true),
  maxLength: z.number().int().min(1).max(2000).default(200),
});

const BooleanVariableSchema = z.object({
  name: VariableNameSchema,
  kind: z.literal('boolean'),
  label: z.string().min(1).max(200).optional(),
  required: z.boolean().default(true),
});

const DateVariableSchema = z.object({
  name: VariableNameSchema,
  kind: z.literal('date'),
  label: z.string().min(1).max(200).optional(),
  required: z.boolean().default(true),
});

const EnumVariableSchema = z.object({
  name: VariableNameSchema,
  kind: z.literal('enum'),
  label: z.string().min(1).max(200).optional(),
  required: z.boolean().default(true),
  options: z
    .array(z.string().min(1).max(100))
    .min(2)
    .max(20)
    .refine((opts) => new Set(opts).size === opts.length, 'duplicate options'),
});

export const VariableDeclSchema = z.discriminatedUnion('kind', [
  TextVariableSchema,
  BooleanVariableSchema,
  DateVariableSchema,
  EnumVariableSchema,
]);
export type VariableDecl = z.infer<typeof VariableDeclSchema>;

/** `when`: include the clause iff a boolean variable is true (or false via not). */
export const ClauseConditionSchema = z.union([
  VariableNameSchema,
  z.object({ not: VariableNameSchema }).strict(),
]);
export type ClauseCondition = z.infer<typeof ClauseConditionSchema>;

export const ClauseSchema = z
  .object({
    heading: z.string().min(1).max(200).optional(),
    text: z.string().min(1).max(20000),
    when: ClauseConditionSchema.optional(),
  })
  .strict();
export type Clause = z.infer<typeof ClauseSchema>;

/** Per-state execution requirements (docs/02 §4 execution_requirements). */
export const ExecutionRequirementsSchema = z
  .object({
    witnesses: z.number().int().min(0).max(4),
    notarization: z.boolean(),
    selfProvingAffidavit: z.boolean().default(false),
  })
  .strict();
export type ExecutionRequirements = z.infer<typeof ExecutionRequirementsSchema>;

export const TemplateSourceSchema = z
  .object({
    docType: DocTypeSchema,
    state: UsStateSchema,
    version: z.number().int().positive(),
    /** Static display title — placeholders are NOT allowed here. */
    title: z.string().min(1).max(200),
    /** Attorney sign-off is structural: a source without it cannot parse. */
    legalReview: z
      .object({
        by: z.string().min(1).max(200),
        at: z.string().datetime(),
      })
      .strict(),
    /** Publishing this source also activates it for its (docType, state). */
    activate: z.boolean().default(false),
    executionRequirements: ExecutionRequirementsSchema,
    variables: z
      .array(VariableDeclSchema)
      .max(100)
      .refine((vars) => new Set(vars.map((v) => v.name)).size === vars.length, 'duplicate names'),
    body: z.array(ClauseSchema).min(1).max(200),
  })
  .strict();
export type TemplateSource = z.infer<typeof TemplateSourceSchema>;

/** Matches `{{ name }}` placeholders; used by validation and the renderer. */
export const PLACEHOLDER = /\{\{\s*([A-Za-z][A-Za-z0-9]*)\s*\}\}/g;

export class TemplateValidationError extends Error {
  constructor(readonly issues: string[]) {
    super(`invalid template: ${issues.join('; ')}`);
    this.name = 'TemplateValidationError';
  }
}

/**
 * Parse + cross-validate a template source. Beyond the zod shape:
 *  - every `{{placeholder}}` refers to a declared text/date/enum variable
 *    (booleans drive `when`, never substitution);
 *  - every `when` refers to a declared boolean variable;
 *  - no stray `{{` / `}}` survives outside a well-formed placeholder;
 *  - the title carries no placeholders (it is static display text).
 */
export function parseTemplateSource(input: unknown): TemplateSource {
  const parsed = TemplateSourceSchema.safeParse(input);
  if (!parsed.success) {
    throw new TemplateValidationError(
      parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`),
    );
  }
  const template = parsed.data;
  const issues: string[] = [];
  const byName = new Map(template.variables.map((v) => [v.name, v]));
  if (/[{}]/.test(template.title)) {
    issues.push('title: placeholders are not allowed');
  }
  template.body.forEach((clause, index) => {
    for (const text of [clause.text, clause.heading ?? '']) {
      for (const name of placeholderNames(text)) {
        const decl = byName.get(name);
        if (!decl) {
          issues.push(`body[${index}]: undeclared placeholder '${name}'`);
        } else if (decl.kind === 'boolean') {
          issues.push(`body[${index}]: boolean variable '${name}' cannot be substituted`);
        }
      }
      for (const stray of strayBraces(text)) {
        issues.push(`body[${index}]: ${stray}`);
      }
    }
    if (clause.when !== undefined) {
      const name = typeof clause.when === 'string' ? clause.when : clause.when.not;
      const decl = byName.get(name);
      if (!decl) {
        issues.push(`body[${index}].when: undeclared variable '${name}'`);
      } else if (decl.kind !== 'boolean') {
        issues.push(`body[${index}].when: variable '${name}' is not boolean`);
      }
    }
  });
  if (issues.length > 0) {
    throw new TemplateValidationError(issues);
  }
  return template;
}

export function placeholderNames(text: string): string[] {
  const names: string[] = [];
  for (const match of text.matchAll(PLACEHOLDER)) {
    names.push(match[1]!);
  }
  return names;
}

/** Any brace content that is not a well-formed placeholder is a defect. */
function strayBraces(text: string): string[] {
  const cleaned = text.replace(PLACEHOLDER, '');
  return /[{}]/.test(cleaned) ? ['malformed braces outside a placeholder'] : [];
}

/**
 * Build the zod schema a generation request's `variables` payload must
 * satisfy: exactly the declared variables, correctly typed, nothing extra.
 * `.strict()` means an intake payload can never smuggle undeclared data.
 */
export function intakeSchemaFor(
  template: TemplateSource,
): z.ZodType<Record<string, string | boolean>> {
  const shape: Record<string, z.ZodTypeAny> = {};
  for (const decl of template.variables) {
    let field: z.ZodTypeAny;
    switch (decl.kind) {
      case 'text':
        field = z.string().min(1).max(decl.maxLength);
        break;
      case 'boolean':
        field = z.boolean();
        break;
      case 'date':
        field = IsoDateSchema;
        break;
      case 'enum':
        field = z.enum(decl.options as [string, ...string[]]);
        break;
    }
    shape[decl.name] = decl.required ? field : field.optional();
  }
  return z.object(shape).strict() as z.ZodType<Record<string, string | boolean>>;
}
