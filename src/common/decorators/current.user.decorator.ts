import { ExecutionContext, createParamDecorator } from '@nestjs/common';

import { RefreshTokenPayload } from 'src/auth/types';

export const CurrentUser = createParamDecorator(
  (data: keyof RefreshTokenPayload | undefined, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest();
    if (!data) return request.user;
    return request.user[data];
  },
);
