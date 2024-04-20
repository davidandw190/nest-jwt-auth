import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterPayloadDTO } from './dto/register.payload.dto';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { Tokens } from './types/tokens.type';
import { JwtService } from '@nestjs/jwt';
import { TokenPayload } from './types/jwt.token.payload';
import { LoginPayloadDTO } from './dto/login.payload.dto';
import argon2 from 'argon2';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {}

  async register(registerPayload: RegisterPayloadDTO): Promise<Tokens> {
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

    const tokens = await this.getTokens(
      registeredUser.id,
      registeredUser.email,
      registeredUser.firstName,
      registeredUser.lastName,
    );

    await this.updateRefreshTokenHash(registeredUser.id, tokens.refreshToken);

    return registeredUser;
  }

  async login(loginPayload: LoginPayloadDTO): Promise<Tokens> {
    const loggedInUser = await this.prisma.user.findUnique({
      where: {
        email: loginPayload.email,
      },
    });

    if (!loggedInUser) throw new ForbiddenException('Access Denied');

    const passwordMatches = await argon2.verify(
      loginPayload.password,
      loggedInUser.password,
    );

    if (!passwordMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(
      loggedInUser.id,
      loggedInUser.email,
      loggedInUser.firstName,
      loggedInUser.lastName,
    );

    await this.updateRefreshTokenHash(loggedInUser.id, tokens.refreshToken);

    return tokens;
  }

  private async getTokens(
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

  private async updateRefreshTokenHash(userId: number, refreshToken: string) {
    const hash = await this.hashData(refreshToken);

    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRefreshToken: hash,
      },
    });
  }

  private async hashData(data: string) {
    return await argon2.hash(data);
  }
}
