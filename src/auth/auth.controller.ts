import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterPayloadDTO, LoginPayloadDTO } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  register(@Body() registerPayload: RegisterPayloadDTO): Promise<Tokens> {
    return this.authService.register(registerPayload);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Body() loginPayload: LoginPayloadDTO): Promise<Tokens> {
    return this.authService.login(loginPayload);
  }

  @Post('refresh-token')
  @HttpCode(HttpStatus.OK)
  refreshTokens(userId: number, refreshToken: string): Promise<Tokens> {
    return this.authService.refresh(userId, refreshToken);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(userId: number): Promise<boolean> {
    return this.authService.logout(userId);
  }
}
