import {
  Inject,
  Injectable,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import type { IdentityConfig } from './config';
import { CLOCK, CONFIG, type Clock } from './di-tokens';
import { ErasureService } from './erasure.service';

/**
 * The in-process erasure driver (M25 PR3) — a timer that carries owner-armed
 * erasure requests through identity's own destroy leg once their grace period
 * has lapsed.
 *
 * SHAPED ON `SettlementWorkflowDriver` DELIBERATELY: same lifecycle hooks, same
 * unref'd interval, same "not under NODE_ENV=test", same swallowed errors with
 * an idempotent sweep behind them. One behaviour, one spelling — and when
 * Temporal arrives, the same substitution works on both.
 *
 * AND IT DIFFERS IN THE ONE WAY THAT MATTERS, which is why this says so rather
 * than leaving the resemblance to imply otherwise. Settlement's driver is
 * "deliberately powerless": case state never advances on a timer, because a
 * death claim is never fully automated and a human must confirm every step.
 * THIS driver does advance state, all the way to destroying a key. That is
 * permitted here for a reason settlement cannot borrow — the human review has
 * already happened. The account's OWNER asked, in a session that proved a fresh
 * second factor, and the grace period is the window in which they may still
 * change their mind. No third party can arm this, and no operator role exists
 * that could (docs/06, 2026-08-21). Settlement decides something ABOUT a
 * person; erasure executes something FOR one.
 *
 * LOSING THIS DRIVER DELAYS ERASURES AND WIDENS NOTHING. Every safety
 * predicate — the grace period, the account-status allowlist, the live-request
 * index — travels inside the statements `ErasureService` runs, so a driver that
 * never ticks, ticks twice, or runs in two processes at once cannot erase an
 * account that a single correct tick would not have erased. Availability, not
 * safety, is what a missed tick costs.
 */
@Injectable()
export class ErasureDriver implements OnApplicationBootstrap, OnApplicationShutdown {
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly erasure: ErasureService,
    @Inject(CONFIG) private readonly config: IdentityConfig,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  onApplicationBootstrap(): void {
    if (this.config.nodeEnv === 'test') {
      // Suites drive runDueErasures directly with an injected clock. A timer
      // racing a test that is asserting on a DEK's destroyed_at would make the
      // most irreversible path in the product the flakiest one.
      return;
    }
    this.timer = setInterval(() => {
      void this.erasure.runDueErasures(this.clock()).catch(() => {
        // Retried next tick. Every step of the leg re-reads the fact it
        // changes, so a partial run resumes rather than repeating.
      });
    }, this.config.erasureDriverIntervalMs);
    // Never keep the process alive just to sweep.
    this.timer.unref();
  }

  onApplicationShutdown(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}
