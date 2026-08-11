/**
 * WHERE THIS EXTENSION IS ALLOWED TO TALK, READ FROM THE MANIFEST ITSELF.
 *
 * The origin is not a second constant compiled in beside the manifest — it IS
 * the manifest's `host_permissions` entry, read back at runtime. That removes
 * the whole class of defect M8 PR5 found the hard way, where a value baked into
 * an artifact at build time disagreed with the value the rest of the system
 * used and every test passed over it: here there is only one value, so there is
 * nothing to disagree with. It is also self-enforcing — code cannot reach an
 * origin the manifest does not permit, because the browser refuses the request
 * regardless of what this module returns.
 *
 * EXACTLY ONE entry is permitted, and a second is a hard failure rather than a
 * choice of the first. "One `host_permission`, one origin" is docs/04's stated
 * transport decision, and the moment there are two, which one this function
 * should return is a question nobody has answered — so it refuses instead of
 * guessing.
 *
 * The trailing `/*` that Chrome requires in a host permission is stripped, so
 * callers compose URLs against a bare origin.
 */
export class ExtensionConfigError extends Error {}

export function vaultOrigin(): string {
  const declared = chrome.runtime.getManifest().host_permissions ?? [];
  if (declared.length !== 1) {
    throw new ExtensionConfigError(
      `expected exactly one host permission, found ${String(declared.length)}`,
    );
  }
  const pattern = declared[0] as string;
  const origin = pattern.replace(/\/\*$/, '').replace(/\/$/, '');
  // A match pattern is not a URL, and a wildcard host would mean this artifact
  // could be pointed at an origin nobody reviewed. Parsed rather than trusted.
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new ExtensionConfigError('host permission is not an origin');
  }
  if (parsed.hostname.includes('*') || `${parsed.origin}` !== origin) {
    throw new ExtensionConfigError('host permission is not an exact origin');
  }
  return parsed.origin;
}
