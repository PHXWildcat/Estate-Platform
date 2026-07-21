'use client';

import type { ReactElement } from 'react';

interface FormFieldProps {
  id: string;
  label: string;
  type: 'text' | 'email' | 'password';
  value: string;
  onChange: (value: string) => void;
  /** Current validation error, or null. The error region is always rendered so aria-live announcements work. */
  error: string | null;
  hint?: string;
  autoComplete?: string;
  inputMode?: 'numeric';
  maxLength?: number;
  disabled?: boolean;
}

export function FormField(props: FormFieldProps): ReactElement {
  const {
    id,
    label,
    type,
    value,
    onChange,
    error,
    hint,
    autoComplete,
    inputMode,
    maxLength,
    disabled,
  } = props;
  const describedBy = [hint !== undefined ? `${id}-hint` : null, `${id}-error`]
    .filter((part): part is string => part !== null)
    .join(' ');

  return (
    <div>
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        name={id}
        className="field-input"
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        aria-describedby={describedBy}
        aria-invalid={error !== null}
        autoComplete={autoComplete}
        inputMode={inputMode}
        maxLength={maxLength}
        disabled={disabled}
      />
      {hint !== undefined ? (
        <p id={`${id}-hint`} className="field-hint">
          {hint}
        </p>
      ) : null}
      <p id={`${id}-error`} className="field-error" aria-live="polite">
        {error}
      </p>
    </div>
  );
}
