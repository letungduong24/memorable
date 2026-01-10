import {
    Controller,
    Post,
    Body,
    Res,
    Req,
    HttpCode,
    HttpStatus,
    UseGuards,
    Get,
} from '@nestjs/common';
import type { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { GetClientType } from './decorators/client-type.decorator';
import { ClientType } from './types/client-type.enum';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('register')
    async register(
        @Body() registerDto: RegisterDto,
        @GetClientType() clientType: ClientType,
        @Res({ passthrough: true }) res: Response,
    ) {
        return this.authService.register(registerDto, clientType, res);
    }

    @Post('login')
    @HttpCode(HttpStatus.OK)
    async login(
        @Body() loginDto: LoginDto,
        @GetClientType() clientType: ClientType,
        @Res({ passthrough: true }) res: Response,
    ) {
        return this.authService.login(loginDto, clientType, res);
    }

    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    async refresh(
        @GetClientType() clientType: ClientType,
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ) {
        return this.authService.refreshTokens(clientType, req, res);
    }

    @Post('logout')
    @HttpCode(HttpStatus.OK)
    async logout(
        @GetClientType() clientType: ClientType,
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ) {
        return this.authService.revokeRefreshToken(clientType, req, res);
    }

    @Get('profile')
    @UseGuards(JwtAuthGuard)
    async getProfile(@Req() req: any) {
        return {
            user: req.user,
        };
    }
}
