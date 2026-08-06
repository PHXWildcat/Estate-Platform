import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { DocumentUpload } from './DocumentUpload';

/**
 * The upload surface, tested on the property that matters most: A REFUSED
 * UPLOAD IS NEVER PRESENTED AS STORED. The service's pipeline is pre-storage
 * and fail-closed, so every refusal below means the bytes reached no disk
 * anywhere — and the page has to say so in words the user can act on.
 */

const STORED = {
  documentId: 'd0000000-0000-4000-8000-00000000000u',
  version: 1,
  contentSha256: 'a'.repeat(64),
  executionStatus: 'draft',
  ocrIndexed: true,
};

function mount(overrides: Partial<Record<string, OperationHandler>> = {}): {
  requests: RecordedRequest[];
  onUploaded: jest.Mock;
} {
  const { requests } = installGraphqlFetchMock({
    UploadDocument: () => jsonResponse({ data: { uploadDocument: STORED } }),
    ...overrides,
  });
  const onUploaded = jest.fn();
  render(<DocumentUpload onUploaded={onUploaded} />);
  return { requests, onUploaded };
}

/** A File whose bytes and reported type we control. */
function file(name: string, type: string, bytes = 8): File {
  return new File([new Uint8Array(bytes)], name, { type });
}

function choose(f: File): void {
  const input = screen.getByLabelText('File');
  Object.defineProperty(input, 'files', { value: [f], configurable: true });
  fireEvent.change(input);
}

function fillTitle(value = 'a scan'): void {
  fireEvent.change(screen.getByLabelText('Title'), { target: { value } });
}

describe('the server decides what a file is', () => {
  it('forwards the browser’s declared type without checking it', async () => {
    // The service sniffs magic bytes and refuses a mismatch — that is the
    // control against polyglot mislabeling. A second opinion here could
    // disagree with it, so there isn't one.
    const { requests } = mount();
    fillTitle();
    choose(file('deed.pdf', 'application/pdf'));
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
    await waitFor(() => {
      expect(requests).toHaveLength(1);
    });
    expect(requests[0]?.body.variables).toMatchObject({
      kind: 'legal',
      title: 'a scan',
      mime: 'application/pdf',
    });
  });

  it('declares a type from the extension when the browser reports none', async () => {
    const { requests } = mount();
    fillTitle();
    choose(file('deed.PDF', ''));
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
    await waitFor(() => {
      expect(requests).toHaveLength(1);
    });
    // Still only a CLAIM: the service sniffs the bytes regardless.
    expect(requests[0]?.body.variables).toMatchObject({ mime: 'application/pdf' });
  });

  it.each([
    ['scan.png', 'image/png'],
    ['scan.jpg', 'image/jpeg'],
    ['scan.jpeg', 'image/jpeg'],
    ['scan.tif', 'image/tiff'],
    ['scan.tiff', 'image/tiff'],
    // Nothing recognisable: still a claim, and still the service's decision.
    ['scan.bin', 'application/octet-stream'],
    ['noextension', 'application/octet-stream'],
  ])('declares %s as %s when the browser reports nothing', async (name, expected) => {
    const { requests } = mount();
    fillTitle();
    choose(file(name, ''));
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
    await waitFor(() => {
      expect(requests).toHaveLength(1);
    });
    expect(requests[0]?.body.variables).toMatchObject({ mime: expected });
  });

  it('sends a file the picker hint would not have offered, and lets the server refuse it', async () => {
    const { requests } = mount({ UploadDocument: () => graphqlError('UNSUPPORTED_CONTENT') });
    fillTitle();
    choose(file('notes.txt', 'text/plain'));
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
    await waitFor(() => {
      expect(requests).toHaveLength(1);
    });
    expect(await screen.findByText(/Nothing was stored/i)).toBeVisible();
  });
});

describe('a refusal is never shown as stored', () => {
  it.each([
    ['MALWARE_DETECTED', /flagged that file as malicious/i],
    ['UNSUPPORTED_CONTENT', /couldn’t accept that file/i],
    ['SCAN_UNAVAILABLE', /couldn’t check that file for malware/i],
  ])('says what %s means, and does not report success', async (code, pattern) => {
    const { onUploaded } = mount({ UploadDocument: () => graphqlError(code) });
    fillTitle();
    choose(file('deed.pdf', 'application/pdf'));
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
    expect(await screen.findByText(pattern)).toBeVisible();
    expect(screen.queryByText(/Stored and encrypted/i)).not.toBeInTheDocument();
    // Nothing changed on the server, so nothing re-reads.
    expect(onUploaded).not.toHaveBeenCalled();
  });

  it('keeps the malware message distinct from the unsupported-type one', async () => {
    // Softening a positive scanner finding into "that file type isn't
    // supported" would withhold the one thing the user needs to know about a
    // file somebody sent them.
    mount({ UploadDocument: () => graphqlError('MALWARE_DETECTED') });
    fillTitle();
    choose(file('invoice.pdf', 'application/pdf'));
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
    expect(await screen.findByText(/treat it with suspicion/i)).toBeVisible();
  });
});

describe('local checks mirror the server, and nothing else', () => {
  it('refuses an oversized file with the server’s own cap, before sending', async () => {
    const { requests } = mount();
    fillTitle();
    choose(file('huge.pdf', 'application/pdf', 10 * 1024 * 1024 + 1));
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
    expect(await screen.findByText(/couldn’t accept that file/i)).toBeVisible();
    expect(requests).toHaveLength(0);
  });

  it('says so when the file cannot be read, rather than sending nothing quietly', async () => {
    const { requests } = mount();
    fillTitle();
    // A file the browser hands over but cannot read back — a removable drive
    // pulled out, a permissions change mid-pick.
    const broken = file('deed.pdf', 'application/pdf');
    Object.defineProperty(broken, 'size', { value: 8 });
    const reader = FileReader.prototype as unknown as {
      readAsDataURL: (this: FileReader, file: Blob) => void;
    };
    const original = reader.readAsDataURL;
    reader.readAsDataURL = function failing(this: FileReader): void {
      setTimeout(() => {
        this.onerror?.(new ProgressEvent('error') as ProgressEvent<FileReader>);
      }, 0);
    };
    choose(broken);
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
    expect(await screen.findByText(/couldn’t read that file/i)).toBeVisible();
    reader.readAsDataURL = original;
    expect(requests).toHaveLength(0);
  });

  it('asks for a file and a title rather than sending an empty request', async () => {
    const { requests } = mount();
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
    expect(await screen.findByText('Choose a file first.')).toBeVisible();
    choose(file('deed.pdf', 'application/pdf'));
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
    expect(await screen.findByText(/Give it a title/i)).toBeVisible();
    expect(requests).toHaveLength(0);
  });
});

describe('a stored upload', () => {
  it('says what happened to the text, because it changes what search finds', async () => {
    const { onUploaded } = mount();
    fillTitle();
    choose(file('deed.pdf', 'application/pdf'));
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
    expect(await screen.findByText(/We read the text so you can search for it/i)).toBeVisible();
    expect(onUploaded).toHaveBeenCalled();
  });

  it('still confirms the file was kept when the reply is not understood', async () => {
    // The bytes are already stored, so the honest answer is "kept, but we
    // can't tell you more" — never silence, and never a thrown handler that
    // skips clearing the form and refreshing the list (M12 review).
    const { onUploaded } = mount({ UploadDocument: () => jsonResponse({ data: {} }) });
    fillTitle();
    choose(file('deed.pdf', 'application/pdf'));
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
    expect(await screen.findByText(/couldn’t read the reply/i)).toBeVisible();
    await waitFor(() => {
      expect(onUploaded).toHaveBeenCalled();
    });
  });

  it('is honest when OCR found nothing, rather than silent', async () => {
    mount({
      UploadDocument: () =>
        jsonResponse({ data: { uploadDocument: { ...STORED, ocrIndexed: false } } }),
    });
    fillTitle();
    choose(file('deed.pdf', 'application/pdf'));
    fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
    // OCR is best-effort and never a gate — but a user searching later needs to
    // know that only the title will match.
    expect(await screen.findByText(/search will only match the title/i)).toBeVisible();
  });
});
