'use client';

import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useState, type FormEvent, type ReactElement } from 'react';
import {
  gqlRequest,
  type DocumentTemplateInfo,
  type DocumentVariableInput,
  type TemplateVariableInfo,
} from '../graphql/client';
import { messageFor, stepUpMessageFor } from '../lib/copy';
import { documentKindLabel, executionRequirementsSummary } from '../lib/documents';
import { validateTotpCode } from '../lib/validation';
import { FormStatus } from './FormStatus';

/**
 * Generating a state-specific instrument (M12), and revising one into a new
 * version — the same flow, because they are the same act with a different
 * destination.
 *
 * THE QUESTIONNAIRE IS THE TEMPLATE'S. Every field below is built from the
 * template's own `variables` declaration, which ships in the reviewed, in-repo
 * source and is content-pinned by sha256. This app writes no field list of its
 * own, so a template whose intake changes under attorney review changes this
 * form on the next deploy of the SERVICE, with nothing here to update and
 * nothing to drift.
 *
 * STEP-UP IS INLINE, not a detour. Document generation is on docs/01 §5's
 * mandatory step-up list, so the server refuses until the session has a fresh
 * check; the code prompt appears here and the SAME submission is retried, so
 * nobody loses a filled-in form to an authentication round trip. Answers are
 * never stored anywhere in the meantime — see below.
 *
 * INTAKE ANSWERS ARE NOT PERSISTED, ANYWHERE. The M4 decision is that the
 * encrypted rendered artifact is the record and the variables that produced it
 * are not kept — so a revision means filling the form again. That reads as a
 * gap and is not one: keeping a plaintext copy of the answers would create a
 * second, unencrypted home for exactly the facts the document exists to
 * protect. This component holds them in component state for one submission and
 * nothing writes them to storage.
 */

/** The 50 states plus DC, matching the service's own template matrix. */
const STATES: readonly string[] = [
  'AL',
  'AK',
  'AZ',
  'AR',
  'CA',
  'CO',
  'CT',
  'DE',
  'DC',
  'FL',
  'GA',
  'HI',
  'ID',
  'IL',
  'IN',
  'IA',
  'KS',
  'KY',
  'LA',
  'ME',
  'MD',
  'MA',
  'MI',
  'MN',
  'MS',
  'MO',
  'MT',
  'NE',
  'NV',
  'NH',
  'NJ',
  'NM',
  'NY',
  'NC',
  'ND',
  'OH',
  'OK',
  'OR',
  'PA',
  'RI',
  'SC',
  'SD',
  'TN',
  'TX',
  'UT',
  'VT',
  'VA',
  'WA',
  'WV',
  'WI',
  'WY',
];

export interface ReviseTarget {
  readonly documentId: string;
  /** Only templates of this kind are offered — the service enforces the same. */
  readonly docType: string;
  readonly title: string;
}

export interface DocumentGeneratorProps {
  /** Absent for a new document; present when revising an existing one. */
  readonly revise?: ReviseTarget;
}

type CatalogState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; templates: DocumentTemplateInfo[] };

type AnswerValue = string | boolean;

function labelFor(variable: TemplateVariableInfo): string {
  return variable.label ?? variable.name;
}

/**
 * Client-side required-field checks, mirroring the template's declaration. A
 * UX layer only: the service re-validates the whole payload against the
 * resolved template's typed intake schema, and refuses a render on any
 * unsubstitutable placeholder. It exists so somebody does not submit a will and
 * get back a single generic refusal that names nothing (the service withholds
 * WHICH variable failed, on purpose — the values are PII).
 */
function missingRequired(
  variables: readonly TemplateVariableInfo[],
  answers: Readonly<Record<string, AnswerValue>>,
): string[] {
  return variables
    .filter((variable) => {
      if (!variable.required || variable.kind === 'boolean') return false;
      const value = answers[variable.name];
      return typeof value !== 'string' || value.trim().length === 0;
    })
    .map(labelFor);
}

/**
 * Collapse answers into the wire shape. An EMPTY OPTIONAL TEXT VALUE IS OMITTED
 * rather than sent as an empty string: the template's intake schema types an
 * optional variable as absent-or-non-empty, so '' would be refused as invalid
 * rather than understood as "not applicable".
 */
function toVariableInputs(
  variables: readonly TemplateVariableInfo[],
  answers: Readonly<Record<string, AnswerValue>>,
): DocumentVariableInput[] {
  const inputs: DocumentVariableInput[] = [];
  for (const variable of variables) {
    const value = answers[variable.name];
    if (variable.kind === 'boolean') {
      inputs.push({ name: variable.name, boolean: value === true });
      continue;
    }
    if (typeof value === 'string' && value.trim().length > 0) {
      inputs.push({ name: variable.name, text: value.trim() });
    }
  }
  return inputs;
}

export function DocumentGenerator({ revise }: DocumentGeneratorProps): ReactElement {
  const router = useRouter();
  const [state, setState] = useState('');
  const [catalog, setCatalog] = useState<CatalogState>({ kind: 'idle' });
  const [templateId, setTemplateId] = useState<string | null>(null);
  const [answers, setAnswers] = useState<Record<string, AnswerValue>>({});
  const [title, setTitle] = useState(revise?.title ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [missing, setMissing] = useState<string[]>([]);
  /** True once the server has asked for a fresh identity check. */
  const [stepUpNeeded, setStepUpNeeded] = useState(false);
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<string | null>(null);
  const [stepUpBusy, setStepUpBusy] = useState(false);

  const loadCatalog = useCallback(
    async (nextState: string): Promise<void> => {
      setTemplateId(null);
      setAnswers({});
      setMissing([]);
      setError(null);
      if (nextState.length === 0) {
        setCatalog({ kind: 'idle' });
        return;
      }
      setCatalog({ kind: 'loading' });
      const result = await gqlRequest('DocumentTemplates', { state: nextState });
      if (!result.ok) {
        setCatalog({ kind: 'error', message: messageFor(result.code) });
        return;
      }
      // A response missing its field is not data (the M11 rule).
      if (!Array.isArray(result.data.documentTemplates)) {
        setCatalog({ kind: 'error', message: messageFor('UNKNOWN') });
        return;
      }
      const templates = result.data.documentTemplates.filter(
        (template) => revise === undefined || template.docType === revise.docType,
      );
      setCatalog({ kind: 'ready', templates });
    },
    [revise],
  );

  useEffect(() => {
    void loadCatalog(state);
  }, [state, loadCatalog]);

  const selected =
    catalog.kind === 'ready'
      ? (catalog.templates.find((template) => template.templateId === templateId) ?? null)
      : null;

  async function submit(event?: FormEvent): Promise<void> {
    event?.preventDefault();
    if (selected === null) return;
    const gaps = missingRequired(selected.variables, answers);
    setMissing(gaps);
    if (gaps.length > 0) {
      return;
    }
    setError(null);
    setBusy(true);
    const variables = toVariableInputs(selected.variables, answers);
    const trimmedTitle = title.trim();
    const result =
      revise === undefined
        ? await gqlRequest('GenerateDocument', {
            docType: selected.docType,
            state: selected.state,
            templateId: selected.templateId,
            ...(trimmedTitle.length > 0 ? { title: trimmedTitle } : {}),
            variables,
          })
        : await gqlRequest('RegenerateDocument', {
            documentId: revise.documentId,
            templateId: selected.templateId,
            ...(trimmedTitle.length > 0 ? { title: trimmedTitle } : {}),
            variables,
          });
    setBusy(false);
    if (result.ok) {
      setStepUpNeeded(false);
      /*
       * A RESPONSE MISSING ITS FIELD IS NOT DATA — and on a WRITE path that
       * matters more than on a read, because the side effect already happened.
       * `gqlRequest` answers `ok` for any `data` object, so a version skew
       * arrives as `{"data":{}}`; dereferencing it threw inside a `void`-ed
       * handler after `setBusy(false)` had run, leaving the form idle with no
       * error and no navigation for a document that HAD been generated —
       * inviting a second press and a second legal instrument. Every read path
       * in this milestone applies this guard; the M12 review found the two
       * write paths did not.
       */
      const data = result.data;
      const documentId =
        'generateDocument' in data
          ? data.generateDocument?.documentId
          : data.regenerateDocument?.documentId;
      if (typeof documentId !== 'string') {
        setError(
          'Your document was created, but we couldn’t read the reply. Open your documents list to find it — don’t create it again.',
        );
        return;
      }
      router.push(`/documents/${documentId}`);
      return;
    }
    if (result.code === 'STEPUP_REQUIRED') {
      // Not an error to send someone elsewhere for: reveal the code field and
      // retry this exact submission once identity accepts it. The filled-in
      // answers stay in component state and are re-sent unchanged.
      setStepUpNeeded(true);
      return;
    }
    setError(messageFor(result.code));
  }

  async function submitStepUp(event: FormEvent): Promise<void> {
    event.preventDefault();
    const validation = validateTotpCode(code);
    setCodeError(validation);
    if (validation !== null) return;
    setStepUpBusy(true);
    const stepUp = await gqlRequest('StepUp', { code });
    setStepUpBusy(false);
    if (!stepUp.ok) {
      // Not `messageFor`: identity answers `invalid_credentials` for a bad TOTP
      // code as well as a bad password, and the login wording is nonsense on a
      // form with neither an email nor a password on it.
      setCodeError(stepUpMessageFor(stepUp.code));
      return;
    }
    setCode('');
    await submit();
  }

  return (
    <div className="space-y-4">
      <section aria-labelledby="template-heading" className="card p-5 sm:p-6">
        <h2 id="template-heading" className="text-base font-semibold">
          {revise === undefined ? 'Choose a document' : 'Choose the template for the new version'}
        </h2>
        <p className="mt-1 max-w-prose text-[0.8125rem] text-ink-muted">
          Estate documents are state law, so the wording comes from a template reviewed for that
          state. We only offer the ones that have been reviewed.
        </p>

        <div className="mt-4 max-w-[16rem]">
          <label className="field-label" htmlFor="template-state">
            State
          </label>
          <select
            id="template-state"
            className="field-input"
            value={state}
            onChange={(event) => {
              setState(event.target.value);
            }}
          >
            <option value="">Select a state…</option>
            {STATES.map((code2) => (
              <option key={code2} value={code2}>
                {code2}
              </option>
            ))}
          </select>
        </div>

        <div className="mt-4" role="status" aria-live="polite">
          {catalog.kind === 'loading' ? (
            <p className="text-sm text-ink-muted">Looking for reviewed templates…</p>
          ) : null}
          {catalog.kind === 'error' ? (
            <p className="text-sm text-danger">{catalog.message}</p>
          ) : null}
          {catalog.kind === 'ready' && catalog.templates.length === 0 ? (
            <p className="max-w-prose text-sm text-ink-muted">
              No attorney-reviewed templates for {state} yet. Nothing is generated without one.
            </p>
          ) : null}
        </div>

        {catalog.kind === 'ready' && catalog.templates.length > 0 ? (
          <ul className="mt-2">
            {catalog.templates.map((template) => {
              const active = template.templateId === templateId;
              return (
                <li
                  key={template.templateId}
                  className="flex flex-wrap items-start justify-between gap-3 border-b border-line py-4 last:border-b-0 sm:flex-nowrap"
                >
                  <div className="min-w-0 max-w-prose flex-1">
                    <p className="text-sm font-medium">{documentKindLabel(template.docType)}</p>
                    <p className="mt-1 text-[0.8125rem] text-ink-muted">
                      {executionRequirementsSummary(template.executionRequirements)}
                    </p>
                  </div>
                  <button
                    type="button"
                    className={`${active ? 'btn btn-secondary' : 'btn btn-primary'} shrink-0`}
                    onClick={() => {
                      setTemplateId(template.templateId);
                      setAnswers({});
                      setMissing([]);
                    }}
                  >
                    {active ? 'Selected' : 'Choose'}
                  </button>
                </li>
              );
            })}
          </ul>
        ) : null}
      </section>

      {selected !== null ? (
        <form
          className="card p-5 sm:p-6"
          noValidate
          onSubmit={(event) => {
            void submit(event);
          }}
        >
          <h2 className="text-base font-semibold">
            {documentKindLabel(selected.docType)} · {selected.state}
          </h2>
          <p className="mt-1 max-w-prose text-[0.8125rem] text-ink-muted">
            These questions come from the reviewed template itself. Your answers are used to render
            the document and are not stored — the encrypted document is the record.
          </p>

          <div className="mt-4 max-w-prose space-y-4">
            <div>
              <label className="field-label" htmlFor="document-title">
                Title
              </label>
              <p id="document-title-hint" className="field-hint">
                A label for your own list. Keep specifics out of it — unlike the document’s
                contents, the title is stored as ordinary text.
              </p>
              <input
                id="document-title"
                className="field-input mt-1"
                value={title}
                maxLength={200}
                aria-describedby="document-title-hint"
                placeholder={`e.g. ${documentKindLabel(selected.docType)}`}
                onChange={(event) => {
                  setTitle(event.target.value);
                }}
              />
            </div>

            {selected.variables.map((variable) => (
              <VariableField
                key={variable.name}
                variable={variable}
                value={answers[variable.name]}
                onChange={(value) => {
                  setAnswers((previous) => ({ ...previous, [variable.name]: value }));
                }}
              />
            ))}
          </div>

          <div className="mt-4" role="status" aria-live="polite">
            {missing.length > 0 ? (
              <p className="field-error">
                Still needed: {missing.join(', ')}. Every required answer appears in the document,
                so none of them can be left blank.
              </p>
            ) : null}
          </div>

          <div className="mt-4 flex flex-wrap gap-3">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy
                ? 'Generating…'
                : revise === undefined
                  ? 'Generate document'
                  : 'Create new version'}
            </button>
          </div>

          {stepUpNeeded ? (
            <div className="mt-4 rounded-[var(--radius-card)] border border-line p-4">
              <label className="field-label" htmlFor="generate-stepup-code">
                Confirm it’s you
              </label>
              <p id="generate-stepup-hint" className="field-hint">
                Creating a legal document needs a fresh check. Enter the six-digit code from your
                authenticator — your answers above are kept and sent unchanged.
              </p>
              <input
                id="generate-stepup-code"
                className="field-input mt-1 max-w-[12rem]"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={code}
                aria-describedby="generate-stepup-hint generate-stepup-error"
                onChange={(event) => {
                  setCode(event.target.value);
                }}
              />
              <div id="generate-stepup-error" role="status" aria-live="polite">
                {codeError !== null ? <p className="field-error">{codeError}</p> : null}
              </div>
              <div className="mt-3">
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={stepUpBusy}
                  onClick={(event) => {
                    void submitStepUp(event);
                  }}
                >
                  {stepUpBusy ? 'Checking…' : 'Confirm and generate'}
                </button>
              </div>
            </div>
          ) : null}

          <FormStatus tone="error" message={error} />
        </form>
      ) : null}
    </div>
  );
}

function VariableField({
  variable,
  value,
  onChange,
}: {
  variable: TemplateVariableInfo;
  value: AnswerValue | undefined;
  onChange: (value: AnswerValue) => void;
}): ReactElement {
  const id = `intake-${variable.name}`;
  const label = labelFor(variable);

  if (variable.kind === 'boolean') {
    return (
      <div className="flex items-start gap-3">
        <input
          id={id}
          type="checkbox"
          className="mt-1"
          checked={value === true}
          onChange={(event) => {
            onChange(event.target.checked);
          }}
        />
        <label className="text-sm" htmlFor={id}>
          {label}
        </label>
      </div>
    );
  }

  if (variable.kind === 'enum') {
    return (
      <div>
        <label className="field-label" htmlFor={id}>
          {label}
          {variable.required ? '' : ' (optional)'}
        </label>
        <select
          id={id}
          className="field-input"
          value={typeof value === 'string' ? value : ''}
          onChange={(event) => {
            onChange(event.target.value);
          }}
        >
          <option value="">Select…</option>
          {(variable.options ?? []).map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </div>
    );
  }

  return (
    <div>
      <label className="field-label" htmlFor={id}>
        {label}
        {variable.required ? '' : ' (optional)'}
      </label>
      <input
        id={id}
        className="field-input"
        // The template's own cap. The service enforces it again; this stops
        // someone typing past a limit they cannot see.
        {...(variable.kind === 'text' && variable.maxLength !== null
          ? { maxLength: variable.maxLength }
          : {})}
        type={variable.kind === 'date' ? 'date' : 'text'}
        value={typeof value === 'string' ? value : ''}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      />
    </div>
  );
}
