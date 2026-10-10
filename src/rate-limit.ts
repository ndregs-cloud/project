import { createHmac } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { AppConfig } from './config.js';
import { AppError } from './errors.js';

type Actor = { kind: 'ip' | 'user'; identity: string; max: number };

export function registerRateLimiting(app: FastifyInstance, config: AppConfig): void {
  // IP limits run before authentication and use only the dedicated limiter principal.
  app.addHook('onRequest', async (request, reply) => {
    const routeKey = getRouteKey(request);
    if (isHealthProbe(routeKey)) return;
    const routeConfig = request.routeOptions.config;
    await recordActor(request, reply, routeKey, config, {
      kind: 'ip',
      identity: request.ip,
      max: routeConfig.ipRateLimitMax ?? Math.max(config.RATE_LIMIT_MAX * 5, 300),
    });
  });

  // The auth preHandler runs before this hook, preserving per-account limits.
  app.addHook('preHandler', async (request, reply) => {
    const routeKey = getRouteKey(request);
    if (isHealthProbe(routeKey) || !request.user) return;
    const routeConfig = request.routeOptions.config;
    await recordActor(request, reply, routeKey, config, {
      kind: 'user',
      identity: request.user.id,
      max: routeConfig.rateLimitMax ?? config.RATE_LIMIT_MAX,
    });
  });
}

function getRouteKey(request: FastifyRequest): string {
  return request.routeOptions.url ?? 'unknown';
}

function isHealthProbe(routeKey: string): boolean {
  return routeKey === '/healthz' || routeKey === '/readyz';
}

async function recordActor(
  request: FastifyRequest,
  reply: FastifyReply,
  routeKey: string,
  config: AppConfig,
  actor: Actor,
): Promise<void> {
  const windowMs = request.routeOptions.config.rateLimitWindowMs ?? config.RATE_LIMIT_WINDOW_MS;
  const windowStartMs = Math.floor(Date.now() / windowMs) * windowMs;
  const bucketKey = createHmac('sha256', config.RATE_LIMIT_HMAC_KEY)
    .update(`${actor.kind}:${actor.identity}:${routeKey}`).digest('hex');
  const result = await request.server.rateLimitPg.query<{ hits: number }>(
    'SELECT public.nova_rate_limit_record($1,to_timestamp($2 / 1000.0)) AS hits',
    [bucketKey, windowStartMs],
  );
  if ((result.rows[0]?.hits ?? 0) > actor.max) {
    const retryAfter = Math.max(1, Math.ceil((windowStartMs + windowMs - Date.now()) / 1000));
    reply.header('Retry-After', retryAfter);
    throw new AppError(429, 'RATE_LIMITED', 'Terlalu banyak permintaan. Coba lagi nanti.');
  }
}
