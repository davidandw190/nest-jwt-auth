import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginPayloadDTO } from './dto/login.payload.dto';
import { Tokens } from './types/tokens.type';
import { RegisterPayloadDTO } from './dto/register.payload.dto';

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
}
