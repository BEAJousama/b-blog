import { IsEmail, IsEmpty, IsNotEmpty, IsString, Length } from "class-validator";

export class UserDto {
    @IsEmail()
     email: string;
    @IsNotEmpty()
     password: string;
    @Length(0, 5)
    role: string;
} 