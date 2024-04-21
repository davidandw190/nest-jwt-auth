import { SetMetadata } from '@nestjs/common/decorators/core/set-metadata.decorator';

/**
 * Decorator to mark a route as publicly accessible.
 * Routes marked with this decorator will bypass authentication checks.
 * Used in conjunction with the AccessTokenGuard.
 */
export const PublicResource = () => SetMetadata('isPublic', true);
