import { render } from './app.js';

/**
 * The entry point, and deliberately nothing else.
 *
 * The screen lives in `app.ts` so a test can drive it without a module's
 * import-time side effect deciding when it runs — the same separation
 * `main.ts` and `server.ts` have on the edge.
 */
void render();
