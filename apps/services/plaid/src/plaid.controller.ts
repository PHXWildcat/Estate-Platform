import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { CallerGuard, requireCaller, type CallerRequest } from './caller.guard';
import { PlaidService } from './plaid.service';
import { LinkItemBody, parseBody } from './schemas';
import { StepUpGuard } from './stepup.guard';

/** Owner-facing item + account routes. Every route runs behind CallerGuard. */
@Controller('v1')
@UseGuards(CallerGuard)
export class PlaidController {
  constructor(private readonly service: PlaidService) {}

  @Post('plaid/link-token')
  @HttpCode(201)
  createLinkToken(@Req() req: CallerRequest): Promise<{ linkToken: string }> {
    return this.service.createLinkToken(requireCaller(req).userId);
  }

  @Post('plaid/items')
  @HttpCode(201)
  linkItem(@Req() req: CallerRequest, @Body() body: unknown): Promise<unknown> {
    const { publicToken } = parseBody(LinkItemBody, body);
    return this.service.linkItem(requireCaller(req).userId, publicToken);
  }

  @Get('plaid/items')
  listItems(@Req() req: CallerRequest): Promise<unknown> {
    return this.service.listItems(requireCaller(req).userId);
  }

  @Post('plaid/items/:id/sync')
  @HttpCode(200)
  sync(
    @Req() req: CallerRequest,
    @Param('id', new ParseUUIDPipe({ errorHttpStatusCode: 404 })) id: string,
  ): Promise<unknown> {
    return this.service.sync(requireCaller(req).userId, id);
  }

  /** Deletion-class action: revocation requires fresh step-up (docs/01 §5). */
  @Delete('plaid/items/:id')
  @UseGuards(StepUpGuard)
  @HttpCode(204)
  async revoke(
    @Req() req: CallerRequest,
    @Param('id', new ParseUUIDPipe({ errorHttpStatusCode: 404 })) id: string,
  ): Promise<void> {
    await this.service.revoke(requireCaller(req).userId, id);
  }

  @Get('accounts')
  listAccounts(@Req() req: CallerRequest): Promise<unknown> {
    return this.service.listAccounts(requireCaller(req).userId);
  }
}
