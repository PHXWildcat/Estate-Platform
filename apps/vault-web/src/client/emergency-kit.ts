/**
 * The Emergency Kit: the Secret Key, on paper.
 *
 * 2SKD means a vault needs BOTH the password (known) and the Secret Key (on the
 * device). Lose the device without a copy and the only way back is RESET, which
 * is a crypto-shred — every item becomes permanently unreadable (docs/04 M6).
 * So the kit is not a nicety; it is the difference between a lost laptop and a
 * lost vault.
 *
 * A DOWNLOADED FILE, generated here from a Blob, and deliberately not: an email
 * (M9's doctrine has no field for content and forbids links), a QR code (a
 * dependency on the origin whose whole argument is that it has none), or
 * anything stored server-side (the server must never hold this).
 *
 * The kit contains the Secret Key and NOT the password. Together they open the
 * vault, so a kit carrying both would turn a filing cabinet into a single point
 * of failure — which is exactly what 2SKD exists to avoid.
 */

export interface KitDetails {
  readonly secretKey: string;
  readonly accountLabel: string;
  /** ISO date, passed in so this module needs no clock and stays testable. */
  readonly issuedAt: string;
}

/**
 * Plain text rather than PDF or HTML: it prints, it opens on any machine
 * including a very old one, and generating it needs no library. The file is
 * read by a person under stress, so it leads with what to do rather than with
 * what it is.
 */
export function renderEmergencyKit(details: KitDetails): string {
  return [
    'ESTATE — VAULT EMERGENCY KIT',
    '',
    'Keep this on paper, somewhere you keep important documents.',
    'Anyone holding BOTH this Secret Key and your vault password can open',
    'your vault. Your password is deliberately NOT written here.',
    '',
    `Account:   ${details.accountLabel}`,
    `Issued:    ${details.issuedAt}`,
    '',
    'SECRET KEY',
    '',
    `    ${details.secretKey}`,
    '',
    'WHAT THIS IS FOR',
    '',
    'Your vault is encrypted on your device using your vault password AND',
    'this Secret Key. Estate never receives either one and cannot recover',
    'your vault for you — not for a support request, and not for a court',
    'order.',
    '',
    'You need this key when you sign in to your vault on a new device.',
    '',
    'IF YOU LOSE IT',
    '',
    'There is no recovery. The only way forward is to reset the vault,',
    'which permanently destroys every item in it — the contents cannot be',
    'decrypted by anyone, including us. Store this somewhere you will still',
    'have it after a lost or stolen device.',
    '',
  ].join('\n');
}

/** Filename for the download. No account identifier — this may sit in a shared
 *  Downloads folder, and the file's own contents already say whose it is. */
export const EMERGENCY_KIT_FILENAME = 'estate-vault-emergency-kit.txt';

/**
 * Hand the file to the browser.
 *
 * An object URL that is revoked immediately after the click: leaving it live
 * would keep the Secret Key reachable from a `blob:` URL for the life of the
 * document, which is a second copy nobody asked for.
 */
export function downloadEmergencyKit(details: KitDetails): void {
  const blob = new Blob([renderEmergencyKit(details)], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = EMERGENCY_KIT_FILENAME;
  anchor.click();
  URL.revokeObjectURL(url);
}
