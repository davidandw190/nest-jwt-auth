import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterPayloadDTO } from './dto/register.payload.dto';
import * as bcrypt from 'bcrypt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { Tokens } from './types/tokens.type';
import { JwtService } from '@nestjs/jwt';
import { TokenPayload } from './types/jwt.token.payload';
@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {}

  async register(registerPayload: RegisterPayloadDTO): Promise<Tokens> {
    // const hash = await argon.hash(dto.password);

    const registeredUser = await this.prisma.user
      .create({
        data: {
          email: registerPayload.email,
          passwrodHash: await this.hashData(registerPayload.password),
        },
      })
      .catch((error) => {
        if (error instanceof PrismaClientKnownRequestError) {
          if (error.code === 'P2002') {
            throw new ForbiddenException('Credentials incorrect');
          }
        }
        throw error;
      });

    // TODO

    return registeredUser;
  }

  async getTokens(
    userId: number,
    email: string,
    firstName: string,
    lastName: string,
  ): Promise<Tokens> {
    const jwtPayload: TokenPayload = {
      subject: userId,
      email: email,
      firstName: firstName,
      lastName: lastName,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.ACCESS_TOKEN_SECRET,
        expiresIn: process.env.ACCESS_TOKEN_TTL,
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.REFRESH__TOKEN_SECRET,
        expiresIn: process.env.REFRESH_TOKEN_TTL,
      }),
    ]);

    return { accessToken, refreshToken };
  }

  private hashData(data: string) {
    return bcrypt.hash(data, 10);
  }
}
