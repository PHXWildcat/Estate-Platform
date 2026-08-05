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
});
