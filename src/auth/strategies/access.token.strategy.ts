import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt } from 'passport-jwt';
import { AccessTokenPayload } from '../types/access.token.payload';

@Injectable()
export class AccessTokenStrategy extends PassportStrategy(String, 'jwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.ACCESS_TOKEN_SECRET,
    });
  }

  validate(payload: AccessTokenPayload) {
    return payload;
  }
}
