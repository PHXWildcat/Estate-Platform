import { Controller, Get, HttpCode, Param, Req, UseGuards } from '@nestjs/common';
import { CallerGuard, requireCaller, type CallerRequest } from '@estate/auth-guard';
import { DocumentsService, type ContentDto } from './documents.service';
import { parse, UuidSchema, VersionParamSchema } from './schemas';

/** Raw bearer token, re-extracted for forwarding to settlement. CallerGuard
 * already validated the header shape; '' here only means a wiring anomaly and
 * fails closed inside the settlement client. */
function bearerTokenOf(req: CallerRequest): string {
  const raw = req.headers['authorization'];
  const header = Array.isArray(raw) ? raw[0] : raw;
  return typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : '';
}

/**
 * M7 settlement-evidence reads — a DELIBERATELY separate route from the
 * owner-scoped document reads. The normal content route stays owner-only
 * (Cedar owner.cedar); this one exists so a settlement operator can review a
 * death certificate during mandatory human review (docs/03 §5.1 control 2),
 * with settlement — not this service — holding the authority decision. The
 * caller's own bearer is forwarded; every authorized read is audited as
 * document.evidence.accessed with onBehalfOf = the document owner.
 */
@Controller('v1')
@UseGuards(CallerGuard)
export class EvidenceController {
  constructor(private readonly documents: DocumentsService) {}

  @Get('evidence/:documentId/versions/:version/content')
  @HttpCode(200)
  content(
    @Req() req: CallerRequest,
    @Param('documentId') documentId: string,
    @Param('version') version: string,
  ): Promise<ContentDto> {
    return this.documents.getEvidenceContent(
      requireCaller(req).userId,
      bearerTokenOf(req),
      parse(UuidSchema, documentId),
      parse(VersionParamSchema, version),
    );
  }
}
