import { Injectable } from '@nestjs/common';
import { hash, verify, type Algorithm } from '@node-rs/argon2';

/**
 * Argon2id parameters per docs/01 §4: m=64MiB, t=3, p=4.
 * (Server-side pepper via KMS is a production follow-up, tracked in README.)
 *
 * `Algorithm` is an ambient const enum (NAPI-RS d.ts), unusable as a value
 * under isolatedModules; 2 is Algorithm.Argon2id.
 */
const ARGON2ID = 2 as Algorithm;

const ARGON2_OPTIONS = {
  algorithm: ARGON2ID,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
} as const;

/**
 * Password hashing boundary. Also owns the timing-equalization dummy hash:
 * login MUST cost one Argon2 verification whether or not the identifier
 * resolves to a user, or response timing enumerates accounts.
 */
@Injectable()
export class PasswordHasher {
  private dummyHashPromise: Promise<string> | null = null;

  hashPassword(password: string): Promise<string> {
    return hash(password, ARGON2_OPTIONS);
  }

  async verifyPassword(passwordHash: string, password: string): Promise<boolean> {
    try {
      return await verify(passwordHash, password, ARGON2_OPTIONS);
    } catch {
      // Malformed hash — treat as verification failure, never as an error
      // (error paths would create a timing/behavior oracle).
      return false;
    }
  }

  /**
   * Burn one Argon2 verification against a throwaway hash. Called on the
   * unknown-identifier login path so it is time-shaped like a real verify.
   */
  async dummyVerify(): Promise<void> {
    this.dummyHashPromise ??= hash('estate-timing-equalization-dummy', ARGON2_OPTIONS);
    const dummyHash = await this.dummyHashPromise;
    await this.verifyPassword(dummyHash, 'definitely-not-the-password');
  }
}
