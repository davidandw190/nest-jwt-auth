import { ExtractJwt, Strategy } from 'passport-jwt';
import { Injectable, UnauthorizedException } from '@nestjs/common';

import { PassportStrategy } from '@nestjs/passport';
import { RefreshTokenPayload } from '../types';
import { Request } from 'express';

/**
 * Strategy for validating refresh tokens using Passport.
 */
@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.REFRESH_TOKEN_SECRET,
      passReqToCallback: true,
    });
  }

  /**
   * Validates the payload extracted from the refresh token.
   *
   * @param req - HTTP request object.
   * @param payload - Payload extracted from the refresh token.
   * @returns Validated payload with the refresh token added.
   * @throws UnauthorizedException if authorization header is missing or malformed.
   */
  validate(req: Request, payload: RefreshTokenPayload) {
    const authHeader = req.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new UnauthorizedException('Invalid authorization header');
    }
    const refreshToken = authHeader.replace('Bearer ', '').trim();

    return { ...payload, refreshToken };
  }
}
