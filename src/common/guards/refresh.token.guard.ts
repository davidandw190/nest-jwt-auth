import { AuthGuard } from '@nestjs/passport/dist/auth.guard';

/**
 * Guard for protecting routes using refresh tokens.
 * Allows access to routes only with a valid refresh token.
 */
export class RefreshTokenGuard extends AuthGuard('jwt-refresh') {
  constructor() {
    super();
  }
}
