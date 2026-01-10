import {
    Injectable,
    UnauthorizedException,
    ConflictException,
    BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import type { Request, Response } from 'express';
import * as bcrypt from 'bcrypt';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ClientType } from './types/client-type.enum';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService,
        private configService: ConfigService,
    ) { }

    async register(registerDto: RegisterDto, clientType: ClientType, res: Response) {
        const { email, password, name } = registerDto;

        // Check if user already exists
        const existingUser = await this.prisma.user.findUnique({
            where: { email },
        });

        if (existingUser) {
            throw new ConflictException('User with this email already exists');
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = await this.prisma.user.create({
            data: {
                email,
                password: hashedPassword,
                name,
            },
        });

        // Generate tokens
        const tokens = await this.generateTokens(user.id, user.email);

        return this.formatAuthResponse(
            {
                id: user.id,
                email: user.email,
                name: user.name,
            },
            tokens,
            clientType,
            res,
        );
    }

    async login(loginDto: LoginDto, clientType: ClientType, res: Response) {
        const { email, password } = loginDto;

        // Find user
        const user = await this.prisma.user.findUnique({
            where: { email },
        });

        if (!user) {
            throw new UnauthorizedException('Invalid credentials');
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid credentials');
        }

        // Generate tokens
        const tokens = await this.generateTokens(user.id, user.email);

        return this.formatAuthResponse(
            {
                id: user.id,
                email: user.email,
                name: user.name,
            },
            tokens,
            clientType,
            res,
        );
    }

    async refreshTokens(clientType: ClientType, req: Request, res: Response) {
        // Get refresh token based on client type
        const refreshToken = clientType === ClientType.WEB
            ? req.cookies?.refreshToken
            : (req.body as any)?.refreshToken;

        if (!refreshToken) {
            throw new BadRequestException('Refresh token is required');
        }

        // Verify refresh token
        let payload: any;
        try {
            payload = this.jwtService.verify(refreshToken, {
                secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
            });
        } catch (error) {
            throw new UnauthorizedException('Invalid refresh token');
        }

        // Check if refresh token exists in database
        const storedToken = await this.prisma.refreshToken.findUnique({
            where: { token: refreshToken },
            include: { user: true },
        });

        if (!storedToken) {
            throw new UnauthorizedException('Refresh token not found');
        }

        // Check if token is expired
        if (storedToken.expiresAt < new Date()) {
            // Delete expired token
            await this.prisma.refreshToken.delete({
                where: { id: storedToken.id },
            });
            throw new UnauthorizedException('Refresh token expired');
        }

        // Delete old refresh token (rotation)
        await this.prisma.refreshToken.delete({
            where: { id: storedToken.id },
        });

        // Generate new tokens
        const tokens = await this.generateTokens(
            storedToken.user.id,
            storedToken.user.email,
        );

        return this.formatAuthResponse(
            {
                id: storedToken.user.id,
                email: storedToken.user.email,
                name: storedToken.user.name,
            },
            tokens,
            clientType,
            res,
        );
    }

    async revokeRefreshToken(clientType: ClientType, req: Request, res: Response) {
        // Get refresh token based on client type
        const refreshToken = clientType === ClientType.WEB
            ? req.cookies?.refreshToken
            : (req.body as any)?.refreshToken;

        if (clientType === ClientType.WEB) {
            res.clearCookie('refreshToken');
        }

        if (!refreshToken) {
            return { message: 'No token to revoke' };
        }

        try {
            await this.prisma.refreshToken.delete({
                where: { token: refreshToken },
            });
            return { message: 'Logged out successfully' };
        } catch (error) {
            // Token doesn't exist, which is fine
            return { message: 'Logged out successfully' };
        }
    }

    private async generateTokens(userId: string, email: string) {
        const payload = { sub: userId, email };

        const jwtSecret = this.configService.get<string>('JWT_SECRET') || '';
        const jwtRefreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET') || '';
        const jwtExpiresIn = this.configService.get<string>('JWT_EXPIRES_IN') || '15m';
        const jwtRefreshExpiresIn = this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') || '7d';

        // Generate access token
        const accessToken = this.jwtService.sign(payload, {
            secret: jwtSecret,
            expiresIn: jwtExpiresIn,
        } as any);

        // Generate refresh token
        const refreshToken = this.jwtService.sign(payload, {
            secret: jwtRefreshSecret,
            expiresIn: jwtRefreshExpiresIn,
        } as any);

        // Store refresh token in database
        const expiresAt = new Date();

        // Parse expiration time (simple parser for common formats like "7d", "24h")
        const match = jwtRefreshExpiresIn.match(/^(\d+)([dhms])$/);
        if (match) {
            const value = parseInt(match[1]);
            const unit = match[2];

            switch (unit) {
                case 'd':
                    expiresAt.setDate(expiresAt.getDate() + value);
                    break;
                case 'h':
                    expiresAt.setHours(expiresAt.getHours() + value);
                    break;
                case 'm':
                    expiresAt.setMinutes(expiresAt.getMinutes() + value);
                    break;
                case 's':
                    expiresAt.setSeconds(expiresAt.getSeconds() + value);
                    break;
            }
        } else {
            // Default to 7 days if parsing fails
            expiresAt.setDate(expiresAt.getDate() + 7);
        }

        await this.prisma.refreshToken.create({
            data: {
                token: refreshToken,
                userId,
                expiresAt,
            },
        });

        return {
            accessToken,
            refreshToken,
        };
    }

    async validateUser(email: string, password: string) {
        const user = await this.prisma.user.findUnique({
            where: { email },
        });

        if (!user) {
            return null;
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return null;
        }

        return {
            id: user.id,
            email: user.email,
            name: user.name,
        };
    }

    private formatAuthResponse(
        user: { id: string; email: string; name: string | null },
        tokens: { accessToken: string; refreshToken: string },
        clientType: ClientType,
        res: Response,
    ) {
        if (clientType === ClientType.WEB) {
            // For web clients, set cookie and return only access token
            res.cookie('refreshToken', tokens.refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            });

            return {
                user,
                accessToken: tokens.accessToken,
            };
        } else {
            // For mobile clients, return both tokens in response
            return {
                user,
                accessToken: tokens.accessToken,
                refreshToken: tokens.refreshToken,
            };
        }
    }
}
