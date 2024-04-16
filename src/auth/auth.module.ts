import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AccessTokenStrategy } from './strategies/access.token.strategy';
import { RefreshTokenStrategy } from './strategies/refresh.token.strategy';
import { JwtModule } from '@nestjs/jwt';
import { TOKEN_ISSUER, TOKEN_SIGN_ALGORITHM } from './constants/auth.constants';

@Module({
  imports: [
    JwtModule.register({
      signOptions: {
        issuer: TOKEN_ISSUER,
        algorithm: TOKEN_SIGN_ALGORITHM,
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, AccessTokenStrategy, RefreshTokenStrategy],
})
export class AuthModule {}
