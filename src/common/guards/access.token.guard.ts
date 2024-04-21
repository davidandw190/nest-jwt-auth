import { AuthGuard } from '@nestjs/passport/dist/auth.guard';
import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

/**
 * Guard for protecting routes using access tokens.
 * Allows access to routes marked as public or with a valid access token.
 */
export class AccessTokenGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  /**
   * Determines if the route can be activated.
   *
   * @param context - ExecutionContext containing information about the route and request.
   * @returns True if the route can be activated, false otherwise.
   */
  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      context.getHandler(), // Get metadata from route handler
      context.getClass(), // Get metadata from controller class
    ]);

    if (isPublic) return true;

    return super.canActivate(context);
  }
}
