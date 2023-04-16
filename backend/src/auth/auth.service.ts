import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { UserDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from 'src/utils/constants';
import { Request, Response } from 'express';
import { UserRole } from '@prisma/client';

@Injectable()
export class AuthService {

    constructor(private prisma: PrismaService, private jwt : JwtService) {}


    async signup(dto: UserDto) {
        const { email, password, role } = dto;
        const hashedPassword = await bcrypt.hash(password, 10);
        const data = {email, hashedPassword, role:  role ? UserRole[role] : UserRole["USER"]}
        const foundUser = await this.prisma.user.findUnique({
            where: { email : email },
            select: {
                email: true
            }
        });
        if (foundUser) {
            throw  new BadRequestException("User already exists");
        }
        else
        {
            const user = await this.prisma.user.create({
                data,
            });
            return {   
                    "message": "Successfully created user",
                     "user" : user
                    };
        }
    }

    async signin(dto: UserDto, req  : Request , res : Response) {
        
        const { email, password } = dto;
        const foundUser = await this.prisma.user.findUnique({
            where: { email : email },
            select: {
                email: true,
                hashedPassword: true,
                id: true
            }
        });

        if (!foundUser) {
            throw  new BadRequestException("User does not exist");
        }
        else
        {
            const isMatch = await bcrypt.compare(password, foundUser.hashedPassword);
            if (isMatch) {
                const token = await this.signToken({id: foundUser.id, email : foundUser.email});
                if (!token) {
                    throw  new BadRequestException("Error signing token");
                }
                res.cookie('token', token);
                // req.user = foundUser;
                res.send({
                    "message": "Successfully signed in",
                    "user" : foundUser,
                    "token" : token
                });
            }
            else {
                throw  new BadRequestException("Incorrect password");
            }
        }
    }

    async signout(req  : Request , res : Response) {
        res.clearCookie('token');
        return {message : "Sign out successfully!"};
    }

    async hashPassword(password: string) {
        return await bcrypt.hash(password, 10);
    }

    async signToken(args: {id: string, email : string}) {
        const payload = args;
        return this.jwt.sign(payload, {secret : jwtSecret});
    }
}
