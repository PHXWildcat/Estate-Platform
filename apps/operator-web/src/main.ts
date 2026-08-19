import { ConfigError, loadConfig } from './config';
import { createOperatorWebServer } from './server';
import { Upstream } from './upstream';

/**
 * Boot the operator origin.
 *
 * Fails fast and loud on a bad environment, like every other deployable here:
 * an operator origin that starts with the wrong app origin configured would
 * accept a handoff from nowhere, and one with the wrong identity URL would
 * answer every request with an outage.
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

  const server = createOperatorWebServer({
    config,
    upstream: new Upstream({ identityUrl: config.identityUrl }),
  });
  server.listen(config.port, () => {
    process.stdout.write(`operator-web listening on ${config.port}\n`);
  });
}

main();
