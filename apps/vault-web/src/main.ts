import { ConfigError, loadConfig } from './config';
import { createVaultWebServer } from './server';
import { Upstream } from './upstream';

/**
 * Boot the vault origin.
 *
 * Fails fast and loud on a bad environment, like every other deployable here:
 * a vault origin that starts with the wrong app origin configured would accept
 * a handoff from nowhere, and one with the wrong vault URL would answer every
 * request with an outage.
 */
function main(): void {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    // Issue paths and messages only — ConfigError never carries env values.
    process.stderr.write(`${err instanceof ConfigError ? err.message : String(err)}\n`);
    process.exit(1);
    return;
  }

  const server = createVaultWebServer({
    config,
    upstream: new Upstream({ identityUrl: config.identityUrl }),
  });
  server.listen(config.port, () => {
    process.stdout.write(`vault-web listening on ${config.port}\n`);
  });
}

main();
