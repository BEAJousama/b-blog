
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { jwtSecret } from '../utils/constants';
import { Request } from 'express';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        JwtStrategy.extractJwtFromCookie,
      ]),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
    });
  }

  private static extractJwtFromCookie(req : Request) : string | null {
    if (req && req.cookies && req.cookies['token'] ) {
      return req.cookies['token'];
    }
    return null;
  }

  async validate(payload:  { id: string, email : string}) {
    return { id: payload.id, email: payload.email };
  }
}
