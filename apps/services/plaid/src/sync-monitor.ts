import { Inject, Injectable } from '@nestjs/common';
import { CLOCK, type Clock } from './di-tokens';
import { EventsService } from './events.service';

/** Syncs per item within the window before the anomaly alert fires. */
const WINDOW_MS = 60 * 60 * 1000;
const THRESHOLD = 30;

/**
 * TB5 "anomalous sync patterns alert" — the in-process hook. Counts syncs per
 * item over a sliding window; crossing the threshold emits the
 * `plaid.sync.anomalous` audit event (IDs and counts only), which the audit
 * pipeline can page on. Deliberately interface-light so a real detector
 * (metrics/SIEM-backed, cross-instance) can replace it without touching call
 * sites; per-instance memory is the honest scope of an M3 in-process check.
 */
@Injectable()
export class SyncActivityMonitor {
  private readonly windows = new Map<string, number[]>();

  constructor(
    private readonly events: EventsService,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  /** Record one sync for the item; fires the alert when the window overflows. */
  async recordSync(itemId: string): Promise<void> {
    const now = this.clock().getTime();
    const cutoff = now - WINDOW_MS;
    const window = (this.windows.get(itemId) ?? []).filter((t) => t > cutoff);
    window.push(now);
    this.windows.set(itemId, window);
    if (window.length > THRESHOLD) {
      await this.events.syncAnomalous(itemId, { syncsInWindow: window.length });
    }
  }
}
