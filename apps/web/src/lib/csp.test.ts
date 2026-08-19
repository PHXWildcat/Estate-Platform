import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The CSP is a security header, so its content is pinned rather than eyeballed
 * (M11 security review).
 *
 * A source scan rather than an import: `next.config.ts` is a Next-flavoured
 * module that pulls in the framework's types and its `standalone` branch reads
 * the environment, so importing it into jsdom to read one string would test the
 * loader as much as the policy. What matters here is which directives are
 * WRITTEN and how they are gated, and that is exactly what the source says.
 */

const source = readFileSync(join(__dirname, '..', '..', 'next.config.ts'), 'utf8');

describe('the Content-Security-Policy', () => {
  it('closes the exfiltration channel docs/03 §6d names', () => {
    // The renderer is the control; this is the layer no component edit can
    // reopen. `data:` cannot reach the network.
    expect(source).toContain('"img-src \'self\' data:"');
    expect(source).toContain('"connect-src \'self\'"');
  });

  it('keeps unsafe-eval OUT of production', () => {
    // It shipped everywhere on the first pass while the rationale justified
    // only inline hydration — a directive nobody had explained, which is how a
    // relaxation outlives its reason. React Refresh needs it under `next dev`;
    // a production build does not.
    expect(source).toContain("process.env.NODE_ENV === 'production'");
    expect(source).toMatch(/\? "script-src 'self' 'unsafe-inline'"/);
    expect(source).toMatch(/: "script-src 'self' 'unsafe-inline' 'unsafe-eval'"/);
  });

  it('still says plainly what it does NOT do', () => {
    // An honest partial CSP beats a strict one that gets relaxed under deploy
    // pressure — but only while the honesty is written down next to it.
    expect(source).toMatch(/NOT lock(ed)? down|deliberately does not/i);
    expect(source).toMatch(/nonce/i);
  });

  it('denies the framing and object sinks outright', () => {
    expect(source).toContain('"frame-ancestors \'none\'"');
    expect(source).toContain('"object-src \'none\'"');
    expect(source).toContain('"base-uri \'self\'"');
  });

  describe('form-action and the isolated origins (M15, M21 PR3a)', () => {
    it('permits exactly two cross-origin form destinations, both named exactly', () => {
      // Opening the vault, and opening the operator console, are each a
      // top-level form POST to an isolated origin — so 'self' alone would have
      // the browser refuse them. What must NOT appear is a wildcard or a bare
      // scheme: these are the only destinations any form in this app may reach,
      // and naming each one exactly is the whole control.
      expect(source).toMatch(/form-action 'self' \$\{vaultOrigin\} \$\{operatorOrigin\}/);
      expect(source).not.toMatch(/form-action[^;`"]*\*/);
      expect(source).not.toMatch(/form-action[^;`"]*https:(?!\/\/)/);
      // TWO, and no more. A third destination is a third trust decision and
      // must be argued for rather than appearing in an interpolation.
      expect(source.match(/form-action[^`]*\$\{/g)?.[0].match(/\$\{/g)).toHaveLength(2);
    });

    it('takes both origins from the environment with localhost defaults', () => {
      // Build-time, like BFF_URL, and for the same reason — headers() is
      // serialised into the routes manifest. Stated here so the M8 PR5 defect's
      // shape stays visible to whoever changes this next.
      //
      // THIS CASE PINS THE READ AND IS BLIND TO WHETHER THE VALUE ARRIVES, and
      // for a long time it did not: web.Dockerfile had no ARG for either origin
      // and turbo.json's strict `env` stripped both, so the config fell through
      // to the defaults below in every build. `build-inputs.test.ts` is the
      // other half — it derives the variable set from next.config.ts and checks
      // the whole chain — and images.yml reads the values back out of the
      // shipped artifact. Neither replaces this one: what is asserted here is
      // that a default EXISTS and what it is, which is what makes a dev build
      // work without configuration.
      expect(source).toMatch(/process\.env\.VAULT_ORIGIN \?\? 'http:\/\/vault\.localhost:3010'/);
      expect(source).toMatch(
        /process\.env\.OPERATOR_ORIGIN \?\? 'http:\/\/operator\.localhost:3011'/,
      );
    });
  });
});
