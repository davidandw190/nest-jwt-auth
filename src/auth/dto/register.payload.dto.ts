import { IsNotEmpty, IsEmail, Matches } from 'class-validator';

export class LoginPayloadDTO {
  @IsNotEmpty({ message: 'First Name cannot be empty' })
  firstName: string;

  @IsNotEmpty({ message: 'Last Name cannot be empty' })
  lastName: string;

  @IsNotEmpty({ message: 'Email cannot be empty' })
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;

  @IsNotEmpty({ message: 'Password cannot be empty' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/, {
    message:
      'Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, and one digit',
  })
  password: string;

  @IsNotEmpty({ message: 'Password cannot be empty' })
  confirmationPassword: string;
}
