import {
  Inject,
  Injectable,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import type { SettlementConfig } from './config';
import { CLOCK, CONFIG, type Clock } from './di-tokens';
import { SettlementService } from './settlement.service';

/**
 * The in-process workflow driver — the deterministic implementation behind
 * M7's approved deviation from docs/01 §7 (Temporal deferred until the cloud
 * environment exists; recorded in docs/04 + the decision log).
 *
 * Deliberately powerless: the ONLY thing scheduled here is the owner-contact
 * sweep. Case state never advances on a timer — a lapsed waiting period makes
 * a case eligible and a human confirms it — so losing this driver degrades
 * contact-attempt liveness, never safety. That shape is exactly what makes
 * Temporal a drop-in later: durable timers replace setInterval around the
 * same idempotent SettlementService.runContactSweep.
 *
 * Not started under NODE_ENV=test: suites drive runContactSweep directly with
 * an injected clock. Sweep errors are swallowed by design — this service logs
 * nothing (observability is audit events), and the next tick retries; the
 * sweep is idempotent per (case, seq).
 */
@Injectable()
export class SettlementWorkflowDriver implements OnApplicationBootstrap, OnApplicationShutdown {
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly settlement: SettlementService,
    @Inject(CONFIG) private readonly config: SettlementConfig,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  onApplicationBootstrap(): void {
    if (this.config.nodeEnv === 'test') {
      return;
    }
    this.timer = setInterval(() => {
      void this.settlement.runContactSweep(this.clock()).catch(() => {
        // Retried next tick; idempotent per (case, seq).
      });
    }, this.config.driverIntervalMs);
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
