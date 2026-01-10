import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { ClientType } from '../types/client-type.enum';

export const GetClientType = createParamDecorator(
    (data: unknown, ctx: ExecutionContext): ClientType => {
        const request = ctx.switchToHttp().getRequest();
        const clientHeader = request.headers['x-client'];

        if (clientHeader === ClientType.APP) {
            return ClientType.APP;
        }

        // Default to web if header is missing or invalid
        return ClientType.WEB;
    },
);
