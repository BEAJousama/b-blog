import { Body, Controller, Get, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserDto } from './dto/auth.dto';
import { Request, Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signup(@Body() dto : UserDto) {
    return await this.authService.signup(dto);
  }

  @Post('signin')
  async signin(@Body() dto : UserDto, @Req() req : Request , @Res() res : Response) {
    return await this.authService.signin(dto, req, res);
  }

  @Get('signout')
  async signout( @Req() req : Request , @Res() res : Response) {
    return await this.authService.signout(req, res);
  }
}
