import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterPayloadDTO, LoginPayloadDTO } from './dto';
import { Tokens } from './types';
import { RefreshTokenGuard } from 'src/common/guards';
import {
  CurrentUserId,
  FromCurrentUser,
  PublicResource,
} from 'src/common/decorators';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @PublicResource()
  @HttpCode(HttpStatus.CREATED)
  register(@Body() registerPayload: RegisterPayloadDTO): Promise<Tokens> {
    return this.authService.register(registerPayload);
  }

  @Post('login')
  @PublicResource()
  @HttpCode(HttpStatus.OK)
  login(@Body() loginPayload: LoginPayloadDTO): Promise<Tokens> {
    return this.authService.login(loginPayload);
  }

  @Post('refresh-token')
  @PublicResource()
  @HttpCode(HttpStatus.OK)
  refreshTokens(
    @CurrentUserId() userId: number,
    @FromCurrentUser('refreshToken') refreshToken: string,
  ): Promise<Tokens> {
    return this.authService.refresh(userId, refreshToken);
  }

  @Post('logout')
  @UseGuards(RefreshTokenGuard)
  @HttpCode(HttpStatus.OK)
  logout(@CurrentUserId() userId: number): Promise<boolean> {
    return this.authService.logout(userId);
  }
}
