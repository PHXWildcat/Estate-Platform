import { render } from './app.js';

/**
 * The entry point, and deliberately nothing else.
 *
 * The screens live in `app.ts` so a test can drive them without a module's
 * import-time side effect deciding when it runs — the same separation `main.ts`
 * and `server.ts` have on the edge.
 */
void render();
