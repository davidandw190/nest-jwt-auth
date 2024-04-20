import { AuthGuard } from '@nestjs/passport/dist/auth.guard';

export class RefreshTokenGuard extends AuthGuard('jwt-refresh') {
  constructor() {
    super();
  }
}
