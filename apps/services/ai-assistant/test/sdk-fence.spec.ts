import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The provider SDK is confined to two files, and that confinement is the whole
 * claim of an "isolating service" (docs/01 §2.8, docs/03 §4 TB5).
 *
 * The point is not tidiness. Anything that can import `@anthropic-ai/sdk` can
 * construct a client, and anything that can construct a client can send estate
 * data to a third party — bypassing the tokenizer, the egress assertion, the
 * consent check and the audit trail in one line. Keeping the reachable set to
 * "the adapter, plus the composition root that hands it a client" is what makes
 * those controls unavoidable rather than customary.
 *
 * Written as a source scan on `readFileSync` rather than as a lint rule or a
 * type-level trick, for the same reason `packages/vault-crypto` scans its own
 * sources: the check must hold for a file nobody remembered to configure, and
 * it must not itself add a dependency edge.
 */

const SRC = join(__dirname, '..', 'src');

/** The only files that may reach the provider SDK, relative to `src/`. */
const SDK_IMPORTERS: ReadonlySet<string> = new Set([
  // The adapter itself — the one translator between our port and the wire.
  'anthropic-gateway.ts',
  // The composition root: constructs the client from config and hands the
  // gateway a one-method port, so the API key never enters a file that renders
  // prompts or handles retrieved estate content.
  'app.module.ts',
]);

/** Every `.ts` under `src/`, path relative to `src/`. */
function sourceFiles(dir: string = SRC, prefix = ''): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...sourceFiles(full, prefix === '' ? entry : `${prefix}/${entry}`));
    } else if (entry.endsWith('.ts')) {
      out.push(prefix === '' ? entry : `${prefix}/${entry}`);
    }
  }
  return out;
}

/** Strip comments so a file that merely DISCUSSES the SDK does not trip the fence. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

describe('the provider SDK is confined to the isolating adapter', () => {
  it('finds the source tree it means to scan', () => {
    // Without this, a wrong path yields an empty list and every assertion below
    // passes while checking nothing — the way a fence stops fencing.
    const files = sourceFiles();
    expect(files.length).toBeGreaterThan(15);
    expect(files).toContain('anthropic-gateway.ts');
    expect(files).toContain('conversation.service.ts');
  });

  it('lets exactly the declared files import @anthropic-ai/sdk', () => {
    const importers = sourceFiles().filter((file) =>
      /from\s+'@anthropic-ai\/sdk'|require\(\s*'@anthropic-ai\/sdk'\s*\)/.test(
        stripComments(readFileSync(join(SRC, file), 'utf8')),
      ),
    );
    expect(importers.sort()).toEqual([...SDK_IMPORTERS].sort());
  });

  it('keeps the API key out of every file but config and the composition root', () => {
    // `ANTHROPIC_API_KEY` is a THIRD-PARTY credential (this service holds no
    // internal one). It is parsed in config.ts and consumed once in
    // app.module.ts; a third reader would mean a second way to reach the
    // provider.
    const readers = sourceFiles().filter((file) =>
      /ANTHROPIC_API_KEY|apiKey/.test(stripComments(readFileSync(join(SRC, file), 'utf8'))),
    );
    expect(readers.sort()).toEqual(['app.module.ts', 'config.ts']);
  });

  it('keeps the turn loop free of the SDK', () => {
    // conversation.service.ts composes prompts out of retrieved estate content.
    // It must reach the provider only through the LlmGateway port, so that the
    // tokenizer and the egress assertion sit on the only path there is.
    const turn = stripComments(readFileSync(join(SRC, 'conversation.service.ts'), 'utf8'));
    expect(turn).not.toContain('@anthropic-ai/sdk');
    expect(turn).not.toContain('anthropic-gateway');
  });
});
