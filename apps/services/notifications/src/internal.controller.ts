import { Body, Controller, Get, HttpCode, Param, Post, Put, UseGuards } from '@nestjs/common';
import { ServiceCredentialGuard } from '@estate/auth-guard';
import { NotificationsService } from './notifications.service';
import { RecipientsCredentialGuard } from './recipients-credential.guard';
import { RecipientStatusCredentialGuard } from './recipient-status-credential.guard';
import { SecurityCredentialGuard } from './security-credential.guard';
import { VerificationCredentialGuard } from './verification-credential.guard';
import {
  AccountSecuritySchema,
  parseBody,
  parseUserId,
  RecipientSchema,
  SendSchema,
  VerificationSchema,
} from './schemas';

/**
 * Internal-only surface, split into FIVE credential-guarded controllers
 * because its routes are five different capabilities with different legitimate
 * holders (credential-graph.ts). There are deliberately NO user-facing routes
 * in this service — a bearer token must never be able to make the platform
 * speak.
 *
 * SENDING (NOTIFICATIONS_INTERNAL_TOKEN; holders vault + settlement +
 * profile): pick which of ten closed ESTATE template kinds fires, for a user,
 * now. The wire has no text field, so a holder never chooses the words and
 * never chooses the destination — and `SendSchema` is built from
 * ESTATE_NOTIFICATION_KINDS, so it cannot reach the one kind that carries a
 * variable.
 */
@Controller('internal/v1/notifications')
@UseGuards(ServiceCredentialGuard)
export class InternalController {
  constructor(private readonly notifications: NotificationsService) {}

  @Post('send')
  @HttpCode(200)
  send(@Body() body: unknown): Promise<{ delivered: boolean; channel: string }> {
    return this.notifications.send(parseBody(SendSchema, body));
  }
}

/**
 * RECIPIENTS (NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN; holder identity ALONE):
 * set the address a user's notifications are delivered to, and declare that
 * the user proved they own it.
 *
 * Separated from sending by the M9 security review. This route decides where
 * every future owner alert lands, so holding it is the power to silence the
 * §5.1 death-case sweep and the §5.2 emergency-access waiting period by
 * pointing them at a mailbox the owner never reads. Identity is the only
 * service that legitimately knows an address — it watches the user type it at
 * registration and login — and it is the only holder.
 *
 * M14 put the VOUCHING route here rather than on a fifth credential because it
 * is the same capability class: both statements decide what the delivery store
 * believes about reaching a user, and a holder that can already repoint an
 * address gains nothing from also being able to mark one verified.
 */
@Controller('internal/v1/notifications')
@UseGuards(RecipientsCredentialGuard)
export class RecipientsController {
  constructor(private readonly notifications: NotificationsService) {}

  @Put('recipients')
  @HttpCode(200)
  upsertRecipient(@Body() body: unknown): Promise<{ ok: true }> {
    return this.notifications.upsertRecipient(parseBody(RecipientSchema, body));
  }

  @Put('recipients/:userId/verified')
  @HttpCode(200)
  markVerified(@Param('userId') userId: string): Promise<{ ok: boolean }> {
    return this.notifications.markRecipientVerified(parseUserId(userId));
  }
}

/**
 * VERIFICATION SEND (NOTIFICATIONS_VERIFY_INTERNAL_TOKEN; holder identity
 * ALONE): mail one address-verification code to the address already on file.
 *
 * Its own credential rather than a share of either neighbour. Not the SEND
 * one, because that fires estate alarms and the service that mints sessions
 * must not be able to ring "a death report was filed on your account". Not the
 * RECIPIENTS one, because that can REPOINT an address and this can only mail
 * to whatever is already stored — so the first future holder of a resend
 * capability does not inherit the power the M9 review split out.
 */
@Controller('internal/v1/notifications')
@UseGuards(VerificationCredentialGuard)
export class VerificationController {
  constructor(private readonly notifications: NotificationsService) {}

  // Named `sendCode`, not `send`: the estate send route is `InternalController.send`
  // and two same-named handlers on two differently-guarded classes is how a
  // future refactor merges them by accident.
  @Post('verification')
  @HttpCode(200)
  sendCode(@Body() body: unknown): Promise<{ delivered: boolean; channel: string }> {
    return this.notifications.sendAddressVerification(parseBody(VerificationSchema, body));
  }
}

/**
 * ACCOUNT SECURITY (NOTIFICATIONS_SECURITY_INTERNAL_TOKEN; holder identity
 * ALONE, M17): tell a user something changed about their account's own
 * credentials.
 *
 * The fifth credential on this callee, and the one whose absence would have
 * been most tempting to paper over. A silent password change is unacceptable;
 * so is handing identity the estate send credential, which would let the
 * service that mints sessions ring "a death report was filed on your account".
 * Neither is it folded into the VERIFY credential beside it: that mails a code
 * the caller minted, and the first future holder of a resend capability must
 * not inherit the ability to announce credential changes — which is the exact
 * message an attacker would most like to be able to send, because it is a
 * phishing pretext a recipient acts on.
 *
 * `AccountSecuritySchema` is built from ACCOUNT_SECURITY_KINDS, a SUBSET of the
 * system kinds, so this route cannot fire an estate kind and cannot fire the
 * verification kind either. Three send routes, three vocabularies, all three
 * exclusions structural.
 */
@Controller('internal/v1/notifications')
@UseGuards(SecurityCredentialGuard)
export class SecurityController {
  constructor(private readonly notifications: NotificationsService) {}

  // Named `sendSecurity`, not `send`, on `VerificationController.sendCode`'s
  // reasoning: same-named handlers on differently-guarded classes are how a
  // future refactor merges two capabilities by accident.
  @Post('security')
  @HttpCode(200)
  sendSecurity(@Body() body: unknown): Promise<{ delivered: boolean; channel: string }> {
    return this.notifications.sendAccountSecurity(parseBody(AccountSecuritySchema, body));
  }
}

/**
 * RECIPIENT STATUS (NOTIFICATIONS_STATUS_INTERNAL_TOKEN): one boolean about
 * one named user — whether the store holds an address that user proved they
 * own.
 *
 * This is the question three shipped fail-closed gates have always ASSUMED and
 * never asked. It is its own credential because settlement sends and never asks
 * (its §5.1 gates proceed on an unverified recipient and record it), so a
 * standalone read is a capability settlement has no use for.
 *
 * WHAT THE SPLIT ACTUALLY BUYS, corrected by the M14 review: the send response
 * carries `recipientVerified` too, so a send holder can obtain the same bit by
 * mailing the user. This route withholds the SILENT read — no alarm reaches the
 * subject, no send-log row, no audit event. An earlier version of this comment
 * claimed the send edge exposed no delivery state at all, which was false the
 * moment PR2 shipped.
 *
 * It returns no address and no timestamp, and writes nothing.
 */
@Controller('internal/v1/notifications')
@UseGuards(RecipientStatusCredentialGuard)
export class RecipientStatusController {
  constructor(private readonly notifications: NotificationsService) {}

  @Get('recipients/:userId/status')
  status(@Param('userId') userId: string): Promise<{ verified: boolean }> {
    return this.notifications.recipientStatus(parseUserId(userId));
  }
}
