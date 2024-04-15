import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterPayloadDTO } from './dto/register.payload.dto';
import * as bcrypt from 'bcrypt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async register(registerPayload: RegisterPayloadDTO): Promise<any> {
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

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }
}
