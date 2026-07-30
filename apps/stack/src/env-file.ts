/**
 * Reading a generated dotenv file back.
 *
 * Its own module because both the doctor (which diagnoses a file) and the
 * generator (which can re-address an existing one) need it, and importing one
 * from the other would make the two a cycle.
 */

/** Parse a dotenv file. Deliberately minimal: no interpolation, no exports. */
export function parseEnvFile(contents: string): Map<string, string> {
  const env = new Map<string, string>();
  for (const raw of contents.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }
    const eq = line.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    env.set(line.slice(0, eq).trim(), line.slice(eq + 1).trim());
  }
  return env;
}
