import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ConfigError, loadConfig } from '../src/config';
import { loadPersistedManifest } from '../src/persisted';

describe('loadConfig', () => {
  it('applies defaults', () => {
    const config = loadConfig({});
    expect(config).toEqual({
      nodeEnv: 'development',
      port: 4000,
      identityUrl: 'http://localhost:3001',
      assetsUrl: 'http://localhost:3003',
      // M10 PR4: the assistant's port (3009), same fail-closed posture as the
      // assets URL — a wrong value is refused downstream, never widened.
      aiAssistantUrl: 'http://localhost:3009',
      // M12: the document service (3005). Same posture again.
      documentsUrl: 'http://localhost:3005',
      // M13: the profile & contacts service (3002). Same posture again, and it
      // has no service-credential routes at all — nothing here that a bearer
      // token could not have opened anyway.
      profileUrl: 'http://localhost:3002',
      // M15: handed to the browser, never called by the BFF.
      vaultOrigin: 'http://vault.localhost:3010',
      // M21 PR3a: the operator console's origin (3011). Handed to the browser
      // in startOperatorHandoff, never called by the BFF — and, like the vault
      // origin, holding no credential for it.
      operatorOrigin: 'http://operator.localhost:3011',
      persistedManifestPath: null,
    });
  });

  it('trims trailing slashes off DOCUMENTS_URL', () => {
    expect(loadConfig({ DOCUMENTS_URL: 'http://documents.internal//' }).documentsUrl).toBe(
      'http://documents.internal',
    );
  });

  it('trims trailing slashes off ASSETS_URL', () => {
    expect(loadConfig({ ASSETS_URL: 'http://assets.internal///' }).assetsUrl).toBe(
      'http://assets.internal',
    );
  });

  it('trims trailing slashes off AI_ASSISTANT_URL', () => {
    expect(loadConfig({ AI_ASSISTANT_URL: 'http://assistant.internal//' }).aiAssistantUrl).toBe(
      'http://assistant.internal',
    );
  });

  it('trims trailing slashes off IDENTITY_URL', () => {
    const config = loadConfig({ IDENTITY_URL: 'http://identity.internal:3001/' });
    expect(config.identityUrl).toBe('http://identity.internal:3001');
  });

  it('names the offending variable, never its value', () => {
    const badPort = 'super-secret-value-99999';
    let error: unknown;
    try {
      loadConfig({ PORT: badPort });
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(ConfigError);
    const message = (error as ConfigError).message;
    expect(message).toContain('PORT');
    expect(message).not.toContain(badPort);
  });

  it('requires PERSISTED_MANIFEST_PATH in production', () => {
    expect(() => loadConfig({ NODE_ENV: 'production' })).toThrow(/PERSISTED_MANIFEST_PATH/);
    expect(
      loadConfig({ NODE_ENV: 'production', PERSISTED_MANIFEST_PATH: '/etc/estate/manifest.json' })
        .persistedManifestPath,
    ).toBe('/etc/estate/manifest.json');
  });
});

describe('loadPersistedManifest', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bff-manifest-'));

  it('returns an empty manifest when no path is configured', () => {
    expect(loadPersistedManifest(null).size).toBe(0);
  });

  it('loads a valid manifest', () => {
    const hash = 'a'.repeat(64);
    const path = join(dir, 'valid.json');
    writeFileSync(path, JSON.stringify({ [hash]: 'query Q { session { userId } }' }));
    const manifest = loadPersistedManifest(path);
    expect(manifest.get(hash)).toBe('query Q { session { userId } }');
  });

  it('rejects non-sha256 keys without echoing manifest contents', () => {
    const path = join(dir, 'bad-keys.json');
    writeFileSync(
      path,
      JSON.stringify({ 'not-a-hash': 'query SECRET_DOC { session { userId } }' }),
    );
    let error: unknown;
    try {
      loadPersistedManifest(path);
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(ConfigError);
    const message = (error as ConfigError).message;
    expect(message).toContain('PERSISTED_MANIFEST_PATH');
    expect(message).not.toContain('SECRET_DOC');
  });

  it('rejects unreadable files and invalid JSON', () => {
    expect(() => loadPersistedManifest(join(dir, 'missing.json'))).toThrow(ConfigError);
    const path = join(dir, 'not-json.json');
    writeFileSync(path, '{nope');
    expect(() => loadPersistedManifest(path)).toThrow(ConfigError);
  });
});
