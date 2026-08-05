import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import {
  BadRequestException,
  ForbiddenException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { GUARDS_METADATA } from '@nestjs/common/constants';
import { CallerGuard, StepUpGuard, type CallerRequest } from '@estate/auth-guard';
import { AnalysisController } from '../src/analysis.controller';
import type { AnalysisService } from '../src/analysis.service';
import { ANALYSIS_DISCLAIMER, type AnalysisResult } from '../src/analysis';
import type { ConsentScope } from '../src/consent';
import type { ConsentsRepo } from '../src/consents.repo';
import type { EventsService } from '../src/events.service';

const USER = randomUUID();
const BEARER = 'the-callers-own-access-token';

function request(): CallerRequest {
  return {
    headers: { authorization: `Bearer ${BEARER}` },
    caller: {
      userId: USER,
      sessionId: randomUUID(),
      mfaLevel: 'mfa',
      stepupExpiresAt: null,
    },
  };
}

const OK_RESULT: AnalysisResult<string, unknown> = {
  status: 'ok',
  findings: [
    {
      code: 'asset_not_titled_in_trust',
      severity: 'high',
      subject: { kind: 'asset', ref: randomUUID(), label: 'Elm Street house' },
      detail: {},
    },
  ],
  summary: {},
  disclaimer: ANALYSIS_DISCLAIMER,
};

interface Emitted {
  name: string;
  detail: Record<string, unknown>;
}

function harness(options: { granted: ConsentScope[]; result?: AnalysisResult<string, unknown> }) {
  const bearers: string[] = [];
  const years: (number | undefined)[] = [];
  const emitted: Emitted[] = [];
  const result = options.result ?? OK_RESULT;

  const analysis = {
    funding: (bearer: string) => {
      bearers.push(bearer);
      return Promise.resolve(result);
    },
    missingDocuments: (bearer: string) => {
      bearers.push(bearer);
      return Promise.resolve(result);
    },
    beneficiaryConflicts: (bearer: string) => {
      bearers.push(bearer);
      return Promise.resolve(result);
    },
    estateTax: (bearer: string, taxYear?: number) => {
      bearers.push(bearer);
      years.push(taxYear);
      return Promise.resolve(result);
    },
  } as unknown as AnalysisService;

  const consents = {
    grantedScopes: () => Promise.resolve(new Set<ConsentScope>(options.granted)),
  } as unknown as ConsentsRepo;

  const events = {
    analysisCompleted: (_userId: string, detail: Record<string, unknown>) => {
      emitted.push({ name: 'completed', detail });
      return Promise.resolve();
    },
    analysisRefused: (_userId: string, detail: Record<string, unknown>) => {
      emitted.push({ name: 'refused', detail });
      return Promise.resolve();
    },
  } as unknown as EventsService;

  return {
    controller: new AnalysisController(analysis, consents, events),
    bearers,
    years,
    emitted,
  };
}

describe('guards', () => {
  it('is CallerGuard only — no step-up, and no route-level guard anywhere', () => {
    // Reading your own computed findings is not an export: nothing leaves the
    // platform on this path (docs/01 §5's step-up list is about egress and
    // destructive actions). Granting a consent, which DOES widen egress, is
    // step-up gated on the consents controller instead.
    const guards = Reflect.getMetadata(GUARDS_METADATA, AnalysisController) as unknown[];
    expect(guards).toEqual([CallerGuard]);
    expect(guards).not.toContain(StepUpGuard);
  });
});

describe('the master switch gates the routes, and nothing else does', () => {
  it('refuses when the assistant is switched off', async () => {
    // 403 with an actionable error, not a 404: unlike a conversation id, there
    // is nothing here to enumerate — every route is about the caller themselves.
    const h = harness({ granted: [] });
    await expect(h.controller.funding(request())).rejects.toBeInstanceOf(ForbiddenException);
    expect(h.bearers).toEqual([]);
  });

  it('runs on the master switch ALONE — no capability scope required', async () => {
    // The deliberate asymmetry with the tools (see the controller docstring):
    // consent scopes gate egress to a model provider, and this path sends
    // nothing anywhere. Requiring them would teach users to grant provider
    // egress in order to see their own document checklist.
    const h = harness({ granted: ['assistant.enabled'] });
    await expect(h.controller.funding(request())).resolves.toMatchObject({ status: 'ok' });
    await expect(h.controller.missingDocuments(request())).resolves.toMatchObject({ status: 'ok' });
    await expect(h.controller.beneficiaryConflicts(request())).resolves.toMatchObject({
      status: 'ok',
    });
    await expect(h.controller.estateTax(request())).resolves.toMatchObject({ status: 'ok' });
  });
});

describe('forwarding and results', () => {
  it('forwards the caller own bearer to the analysers', async () => {
    const h = harness({ granted: ['assistant.enabled'] });
    await h.controller.funding(request());
    expect(h.bearers).toEqual([BEARER]);
  });

  it('returns the analyser result unmodified, watermark included', async () => {
    const h = harness({ granted: ['assistant.enabled'] });
    await expect(h.controller.funding(request())).resolves.toEqual(OK_RESULT);
  });

  it('audits a completed analysis with a COUNT, never the findings', async () => {
    // docs/02 §6: which gaps a user's estate has is exactly the sort of detail
    // that does not belong in the audit stream.
    const h = harness({ granted: ['assistant.enabled'] });
    await h.controller.funding(request());
    expect(h.emitted).toEqual([
      { name: 'completed', detail: { analyzer: 'funding', findingCount: 1 } },
    ]);
    expect(JSON.stringify(h.emitted)).not.toContain('Elm Street');
  });
});

describe('a failed or refused analysis is never a 200', () => {
  it('turns an unavailable read into a 503 and audits the refusal', async () => {
    // A client rendering "0 findings" from a failed peer read would tell a user
    // their estate is in order on the strength of an outage.
    const h = harness({
      granted: ['assistant.enabled'],
      result: {
        status: 'unavailable',
        reason: 'upstream_unavailable',
        disclaimer: ANALYSIS_DISCLAIMER,
      },
    });
    await expect(h.controller.beneficiaryConflicts(request())).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
    expect(h.emitted).toEqual([
      {
        name: 'refused',
        detail: { analyzer: 'beneficiary_conflicts', reason: 'upstream_unavailable' },
      },
    ]);
  });

  it('surfaces the reference-data gate as its own reason token', async () => {
    // A control firing must not read as an outage (the M9 rule): "get the tax
    // table reviewed" and "check whether a peer is up" are different jobs.
    const h = harness({
      granted: ['assistant.enabled'],
      result: {
        status: 'refused',
        reason: 'reference_unreviewed',
        disclaimer: ANALYSIS_DISCLAIMER,
      },
    });
    await expect(h.controller.estateTax(request())).rejects.toMatchObject({
      response: { error: 'reference_unreviewed' },
    });
    expect(h.emitted[0]).toMatchObject({
      name: 'refused',
      detail: { analyzer: 'estate_tax', reason: 'reference_unreviewed' },
    });
  });
});

describe('taxYear', () => {
  it('passes a four-digit year through as a number', async () => {
    const h = harness({ granted: ['assistant.enabled'] });
    await h.controller.estateTax(request(), '2026');
    expect(h.years).toEqual([2026]);
  });

  it('is optional', async () => {
    const h = harness({ granted: ['assistant.enabled'] });
    await h.controller.estateTax(request());
    expect(h.years).toEqual([undefined]);
  });

  it('rejects junk rather than quietly answering for the latest year', async () => {
    // Answering `taxYear=abc` with a plausible number about someone's estate
    // tax would hide the caller's bug behind their own money.
    const h = harness({ granted: ['assistant.enabled'] });
    for (const bad of ['abc', '2026x', '', '-2026', '2026.5']) {
      await expect(h.controller.estateTax(request(), bad)).rejects.toBeInstanceOf(
        BadRequestException,
      );
    }
    expect(h.years).toEqual([]);
  });
});
