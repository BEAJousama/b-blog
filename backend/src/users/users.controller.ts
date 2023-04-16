import { Body, Controller, Delete, Get, Param, Patch, Put, Req, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { UserDto } from 'src/auth/dto/auth.dto';
import { JwtAuthGuard } from 'src/auth/jwt.guards';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(JwtAuthGuard)
  @Get(':id') 
  async getUser(@Param('id') id: string, @Req() req) {
    return await this.usersService.getUser(id, req);
  }

  @Delete(':id')
  async deleteUser(@Param('id') id: string) {
    return await this.usersService.deleteUser(id);
  }

  @Delete()
  async deleteAllUsers() {
    return await this.usersService.deleteAllUsers();
  }

  @Put(':id')
  async updateUser(@Param('id') id: string, @Body() dto: UserDto) {
    return await this.usersService.updateUser(id, {
      email: dto.email,
      password: dto.password,
      role : dto.role,
    });
  }

  @Get()
  async getAllUsers() {
    return await this.usersService.getAllUsers();
  }
}
