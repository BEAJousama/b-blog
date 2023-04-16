import { Body, ForbiddenException, Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { UserDto } from 'src/auth/dto/auth.dto';
import { Request } from 'express';
import { use } from 'passport';


@Injectable()
export class UsersService {
    constructor(private prisma: PrismaService) {}
    async getUser(id: string, req : Request) {

        const decodedUser = req.user as { id: string, email: string };
        const user = await this.prisma.user.findUnique({
            where: { 
                id,
            },
        });
        if (!user) {
            throw new NotFoundException();
        }
        if (decodedUser.id !== user.id) {
            throw new ForbiddenException();
        }
        delete user.hashedPassword;
        delete user.name;
        return user;
    }
    
    async deleteUser(id: string) {
        return await this.prisma.user.delete({
            where: {
                id,
            },
        });
    }

    async deleteAllUsers() {
        return await this.prisma.user.deleteMany();
    }

    async updateUser(id: string, @Body() data: UserDto) {

        const hashedPassword = await bcrypt.hash(data.password, 10);

        return await this.prisma.user.update({
            where: {
                id,
            },
            data: {
                email: data.email,
                hashedPassword: data.password,
            },
        });
    }

    async getAllUsers() {
        return await this.prisma.user.findMany({
            select: {
                id: true,
                email: true,
            },
        });
    }

}
