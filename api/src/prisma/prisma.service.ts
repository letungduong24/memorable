import { Injectable } from '@nestjs/common';
import { PrismaPg } from '@prisma/adapter-pg';
import {PrismaClient} from '../generated/client'
import { ConfigService } from '@nestjs/config';

@Injectable()
export class PrismaService extends PrismaClient {
  constructor(configService: ConfigService) {
    const adapter = new PrismaPg({
      connectionString: configService.get<string>('DATABASE_URL'),
    });

    super({ adapter }); 
  }
}
