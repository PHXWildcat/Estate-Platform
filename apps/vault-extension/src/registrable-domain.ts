import { PUBLIC_SUFFIX_RULES } from './psl-data.js';

/**
 * THE REGISTRABLE DOMAIN, BY THE PUBLIC SUFFIX LIST — never by string surgery.
 *
 * docs/03 §4 TB9 names the two ways this is normally got wrong, and both are
 * exploitable rather than merely sloppy:
 *
 *   · A SUBSTRING match treats `evil-example.com` and `example.com.evil.net` as
 *     `example.com`, so a credential is filled into an attacker's origin.
 *   · LABEL STRIPPING ("take the last two labels") treats `example.co.uk` as
 *     `co.uk`, which makes every `.co.uk` site one registrable domain — so a
 *     credential saved at a bank is offered at any other British site.
 *
 * Neither is a corner case; both are the first thing an attacker tries. So the
 * suffix comes from the list, including its wildcard (`*`) and exception (`!`)
 * rules, and `registrableDomain` returns null rather than guessing whenever the
 * host is not something a credential can belong to.
 *
 * The list is a SNAPSHOT, vendored and digest-pinned (`vendor/`), because this
 * package has no runtime dependencies and must not fetch a security parameter
 * at runtime. It goes stale, which `test/psl.spec.ts` reports as an age rather
 * than pretending otherwise: a stale list is wrong in the SAFE direction for
 * new suffixes (an unknown TLD yields a shorter suffix, so two unrelated hosts
 * under a new multi-label registry could compare equal) — recorded in docs/03
 * §6j rather than left implicit.
 */

/** Rules bucketed by their last label, so a lookup touches ~one bucket. */
const BY_TLD = ((): ReadonlyMap<string, readonly string[]> => {
  const map = new Map<string, string[]>();
  for (const rule of PUBLIC_SUFFIX_RULES) {
    const bare = rule.startsWith('!') ? rule.slice(1) : rule;
    const tld = bare.slice(bare.lastIndexOf('.') + 1);
    const bucket = map.get(tld);
    if (bucket) bucket.push(rule);
    else map.set(tld, [rule]);
  }
  return map;
})();

/** Lower-case, trailing dot removed. Hosts are compared, never displayed. */
export function normaliseHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '');
}

function labelsMatch(ruleLabels: readonly string[], hostLabels: readonly string[]): boolean {
  if (ruleLabels.length > hostLabels.length) return false;
  const offset = hostLabels.length - ruleLabels.length;
  return ruleLabels.every((label, index) => {
    // `*` matches exactly one label — never zero, never several. Getting that
    // wrong is how `*.foo` starts matching `foo` itself.
    const against = hostLabels[offset + index] as string;
    return label === '*' || label === against;
  });
}

/**
 * The public suffix of a host, by the list's own algorithm.
 *
 * Exception (`!`) rules win outright; otherwise the LONGEST matching rule wins;
 * and a host with no matching rule gets the implicit `*` rule — its last label.
 */
export function publicSuffix(host: string): string | null {
  const normalised = normaliseHost(host);
  if (normalised.length === 0) return null;
  const hostLabels = normalised.split('.');
  if (hostLabels.some((label) => label.length === 0)) return null;

  const tld = hostLabels[hostLabels.length - 1] as string;
  const candidates = BY_TLD.get(tld) ?? [];

  let longest: string[] | null = null;
  for (const rule of candidates) {
    const isException = rule.startsWith('!');
    const ruleLabels = (isException ? rule.slice(1) : rule).split('.');
    if (!labelsMatch(ruleLabels, hostLabels)) continue;
    if (isException) {
      // An exception rule's suffix is the rule minus its leftmost label, and it
      // beats every ordinary rule outright.
      return ruleLabels.slice(1).join('.');
    }
    if (!longest || ruleLabels.length > longest.length) longest = ruleLabels;
  }
  if (longest) {
    // A wildcard rule's suffix is the LABELS OF THE HOST it matched, not the
    // rule text — `*.ck` against `www.ck` is the suffix `www.ck`.
    return hostLabels.slice(hostLabels.length - longest.length).join('.');
  }
  // The implicit `*` rule: an unknown TLD is itself the suffix.
  return tld;
}

/**
 * The registrable domain: the public suffix plus one more label.
 *
 * Null when there is no such thing — a bare suffix (`com`, `co.uk`), a single
 * label, or an IP address. A credential cannot belong to any of those, and
 * returning something anyway is how a matcher starts saying yes to hosts nobody
 * registered.
 */
export function registrableDomain(host: string): string | null {
  const normalised = normaliseHost(host);
  // An IP literal has no registrable domain. Bracketed IPv6 never reaches here
  // as a `hostname`, but a bare v4 does and would otherwise fall through the
  // implicit rule and return `1.2.3.4` — a "domain" two different networks
  // could share.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(normalised) || normalised.includes(':')) return null;

  const suffix = publicSuffix(normalised);
  if (suffix === null) return null;
  if (suffix === normalised) return null; // the host IS a suffix: not registrable

  const suffixLabels = suffix.split('.').length;
  const hostLabels = normalised.split('.');
  if (hostLabels.length <= suffixLabels) return null;
  return hostLabels.slice(hostLabels.length - suffixLabels - 1).join('.');
}
