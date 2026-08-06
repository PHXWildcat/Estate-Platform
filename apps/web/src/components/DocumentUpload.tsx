'use client';

import { useRef, useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { documentKindLabel } from '../lib/documents';
import { FormStatus } from './FormStatus';

/**
 * Adding a document somebody else produced (M12 PR2) — a scanned deed, an
 * executed will, an insurance policy.
 *
 * THIS COMPONENT INVENTS NO TYPE CHECK OF ITS OWN. The server decides what a
 * file is by sniffing its magic bytes and refuses anything whose bytes
 * contradict the declared type — that is the control (polyglot mislabeling),
 * and a second opinion here could disagree with it, refusing a file the
 * platform would accept or promising one it will not. So `accept` below is a
 * HINT to the file picker, `file.type` is forwarded as a DECLARATION, and the
 * only local check is the size cap, which mirrors the server's own number
 * rather than adding a rule.
 *
 * A REFUSED UPLOAD IS NEVER SHOWN AS STORED, and the pipeline is what makes
 * that honest rather than hopeful: sniff and scan both run BEFORE anything is
 * written, and the scan is fail-closed, so a 422 or a 503 means the bytes
 * reached no disk anywhere. The three refusals get three different sentences
 * because they mean different things to someone holding a file — especially
 * `MALWARE_DETECTED`, which is a positive finding about a file somebody may
 * have sent them.
 *
 * UPLOAD IS NOT STEP-UP GATED, deliberately: docs/01 §5's list is generation,
 * export and deletion. Adding content is not on it, and the scan pipeline is
 * the gate that matters here.
 */

/** The four formats the service's sniffer admits. A picker hint, not a gate. */
const ACCEPT = '.pdf,.png,.jpg,.jpeg,.tif,.tiff';

/** The service's own cap (UPLOAD_MAX_BYTES). Mirrored, not invented. */
const MAX_BYTES = 10 * 1024 * 1024;

/**
 * Vault categories (docs/00 §8) plus the instrument types worth offering for a
 * scan of something already signed. The service's vocabulary is wider; this is
 * the part a person filing a document would recognise.
 */
const KINDS: readonly string[] = [
  'legal',
  'tax',
  'identity',
  'insurance',
  'property',
  'medical',
  'military',
  'financial',
  'will',
  'revocable_trust',
  'durable_poa',
  'medical_poa',
  'living_will',
  'other',
];

/**
 * The browser's own idea of the type, or a guess from the extension when it has
 * none (Windows without a registered handler reports an empty string). Either
 * way it is a CLAIM: the service sniffs the bytes and decides.
 */
function declaredMime(file: File): string {
  if (file.type.length > 0) return file.type;
  const extension = file.name.toLowerCase().split('.').pop() ?? '';
  if (extension === 'pdf') return 'application/pdf';
  if (extension === 'png') return 'image/png';
  if (extension === 'jpg' || extension === 'jpeg') return 'image/jpeg';
  if (extension === 'tif' || extension === 'tiff') return 'image/tiff';
  return 'application/octet-stream';
}

/**
 * Bytes → base64, through the platform's own `FileReader` rather than a hand
 * loop over `arrayBuffer()`: no dependency, no chunking to get wrong on a large
 * file, and it exists in every environment this app runs in (jsdom's `File` has
 * no `arrayBuffer`, which is how the first version was caught). Nothing here
 * inspects the bytes — encoding them for transport is not reading them.
 */
function toBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = (): void => {
      reject(new Error('unreadable'));
    };
    reader.onload = (): void => {
      const result = typeof reader.result === 'string' ? reader.result : '';
      const comma = result.indexOf(',');
      // `data:<mime>;base64,<payload>` — the payload is what the service takes.
      if (comma === -1) {
        reject(new Error('unreadable'));
        return;
      }
      resolve(result.slice(comma + 1));
    };
    reader.readAsDataURL(file);
  });
}

export interface DocumentUploadProps {
  /** Called after a stored upload, so the list can re-read from the server. */
  onUploaded: () => void;
}

export function DocumentUpload({ onUploaded }: DocumentUploadProps): ReactElement {
  const [kind, setKind] = useState('legal');
  const [title, setTitle] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stored, setStored] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError(null);
    setStored(null);
    if (file === null) {
      setError('Choose a file first.');
      return;
    }
    if (title.trim().length === 0) {
      setError('Give it a title so you can find it later.');
      return;
    }
    // Mirrors the server's cap rather than adding a rule of its own: refusing
    // here saves someone a 10 MB round trip to be told the same thing.
    if (file.size > MAX_BYTES) {
      setError(messageFor('UNSUPPORTED_CONTENT'));
      return;
    }
    setBusy(true);
    let contentBase64: string;
    try {
      contentBase64 = await toBase64(file);
    } catch {
      setBusy(false);
      setError('We couldn’t read that file. Try choosing it again.');
      return;
    }
    const result = await gqlRequest('UploadDocument', {
      kind,
      title: title.trim(),
      mime: declaredMime(file),
      contentBase64,
    });
    setBusy(false);
    if (!result.ok) {
      // Every failure path lands here, and none of them leaves the impression
      // that the file was kept.
      setError(messageFor(result.code));
      return;
    }
    setStored(
      result.data.uploadDocument.ocrIndexed
        ? 'Stored and encrypted. We read the text so you can search for it.'
        : 'Stored and encrypted. We couldn’t read any text from it, so search will only match the title.',
    );
    setTitle('');
    setFile(null);
    if (inputRef.current !== null) {
      inputRef.current.value = '';
    }
    onUploaded();
  }

  return (
    <form
      aria-labelledby="upload-heading"
      className="card p-5 sm:p-6"
      noValidate
      onSubmit={(event) => {
        void submit(event);
      }}
    >
      <h2 id="upload-heading" className="text-base font-semibold">
        Add a document
      </h2>
      <p className="mt-1 max-w-prose text-[0.8125rem] text-ink-muted">
        PDFs and scans up to 10 MB. Every file is scanned for malware before it is stored — if the
        scan does not pass, nothing is kept.
      </p>

      <div className="mt-4 grid max-w-prose gap-4 sm:grid-cols-2">
        <div>
          <label className="field-label" htmlFor="upload-kind">
            Kind
          </label>
          <select
            id="upload-kind"
            className="field-input"
            value={kind}
            onChange={(event) => {
              setKind(event.target.value);
            }}
          >
            {KINDS.map((value) => (
              <option key={value} value={value}>
                {documentKindLabel(value)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="field-label" htmlFor="upload-title">
            Title
          </label>
          <input
            id="upload-title"
            className="field-input"
            value={title}
            maxLength={200}
            aria-describedby="upload-title-hint"
            onChange={(event) => {
              setTitle(event.target.value);
            }}
          />
          <p id="upload-title-hint" className="field-hint">
            Stored as ordinary text — keep specifics in the file, not the title.
          </p>
        </div>
      </div>

      <div className="mt-4">
        <label className="field-label" htmlFor="upload-file">
          File
        </label>
        <input
          id="upload-file"
          ref={inputRef}
          className="field-input"
          type="file"
          // A hint to the picker only. The server sniffs the bytes and decides.
          accept={ACCEPT}
          onChange={(event) => {
            setFile(event.target.files?.[0] ?? null);
            setStored(null);
          }}
        />
      </div>

      <div className="mt-4">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? 'Checking and storing…' : 'Upload'}
        </button>
      </div>

      <div role="status" aria-live="polite">
        {stored !== null ? <p className="mt-3 text-sm text-ink-muted">{stored}</p> : null}
      </div>
      <FormStatus tone="error" message={error} />
    </form>
  );
}
