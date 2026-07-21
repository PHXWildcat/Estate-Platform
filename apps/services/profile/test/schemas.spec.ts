import { BadRequestException } from '@nestjs/common';
import {
  ContactSchema,
  FamilyMemberSchema,
  parse,
  PermissionGrantSchema,
  ProfileUpsertSchema,
  RoleAssignmentSchema,
  UuidSchema,
} from '../src/schemas';

describe('request validation', () => {
  it('accepts a well-formed profile upsert', () => {
    const out = parse(ProfileUpsertSchema, {
      legalName: 'Jane Q. Public',
      ssn: '123456789',
      maritalStatus: 'married',
      stateOfResidence: 'CA',
    });
    expect(out.legalName).toBe('Jane Q. Public');
  });

  it('rejects a bad SSN, marital status, and state code', () => {
    expect(() => parse(ProfileUpsertSchema, { legalName: 'x', ssn: '12-34' })).toThrow(
      BadRequestException,
    );
    expect(() =>
      parse(ProfileUpsertSchema, { legalName: 'x', maritalStatus: 'complicated' }),
    ).toThrow(BadRequestException);
    expect(() =>
      parse(ProfileUpsertSchema, { legalName: 'x', stateOfResidence: 'california' }),
    ).toThrow(BadRequestException);
  });

  it('rejects a missing legal name', () => {
    expect(() => parse(ProfileUpsertSchema, {})).toThrow(BadRequestException);
  });

  it('validates family, contact, role, and permission bodies', () => {
    expect(
      parse(FamilyMemberSchema, { relation: 'child', name: 'Kid', isMinor: true }).isMinor,
    ).toBe(true);
    expect(() => parse(FamilyMemberSchema, { relation: 'cousin', name: 'x' })).toThrow();
    expect(parse(ContactSchema, { name: 'Attorney', email: 'a@b.com' }).email).toBe('a@b.com');
    expect(() => parse(ContactSchema, { name: 'x', email: 'not-an-email' })).toThrow();
    const ra = parse(RoleAssignmentSchema, {
      contactId: 'a1111111-1111-4111-8111-111111111111',
      role: 'beneficiary',
      scopeType: 'asset',
    });
    expect(ra.effectiveCondition).toBe('immediate');
    expect(() =>
      parse(RoleAssignmentSchema, { contactId: 'x', role: 'beneficiary', scopeType: 'asset' }),
    ).toThrow();
    expect(parse(PermissionGrantSchema, { resource: 'contact', action: 'read' }).action).toBe(
      'read',
    );
    expect(() =>
      parse(PermissionGrantSchema, { resource: 'Contact Row', action: 'read' }),
    ).toThrow();
  });

  it('rejects a non-UUID param', () => {
    expect(() => parse(UuidSchema, 'not-a-uuid')).toThrow(BadRequestException);
  });

  it('NEVER echoes the offending value in the error (generic token only)', () => {
    const secret = 'SSN-987-65-4321';
    try {
      parse(ProfileUpsertSchema, { legalName: 'x', ssn: secret });
      throw new Error('expected BadRequestException');
    } catch (err) {
      expect(err).toBeInstanceOf(BadRequestException);
      const body = (err as BadRequestException).getResponse();
      expect(body).toEqual({ error: 'invalid_request' });
      expect(JSON.stringify(body)).not.toContain(secret);
    }
  });
});
