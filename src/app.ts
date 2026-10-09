import { randomUUID } from 'node:crypto';
import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import { pool } from './db.js';
import { loadConfig, type AppConfig } from './config.js';
import { registerAuth } from './auth.js';
import { registerRateLimiting } from './rate-limit.js';
import { installErrorHandler } from './errors.js';
import { MediaStorage } from './storage/s3.js';
import type { Pool } from 'pg';
import type { AuthUser } from './types.js';
import { registerProfileRoutes } from './routes/profiles.js';
import { registerStoryRoutes } from './routes/stories.js';
import { registerSocialRoutes } from './routes/social.js';
import { registerCommentRoutes } from './routes/comments.js';
import { registerReportRoutes } from './routes/reports.js';
import { registerReportMetricsRoute } from './routes/report-metrics.js';
import { registerFeedbackRoutes } from './routes/feedback.js';
import { registerSecurityReportRoutes } from './routes/security-reports.js';
import { registerModerationRoutes } from './routes/moderation.js';
import { registerMediaRoutes } from './routes/media.js';
import { processPendingMediaKeyRevocations } from './media-key-revocations.js';

export interface AppDependencies {
  config?: AppConfig;
  pg?: Pool;
  mediaStorage?: MediaStorage;
}

export async function buildApp(dependencies: AppDependencies = {}): Promise<FastifyInstance> {
  const config = dependencies.config ?? loadConfig();
  const database = dependencies.pg ?? pool;
  const mediaStorage = dependencies.mediaStorage ?? new MediaStorage(config);
  const app = Fastify({
    genReqId: () => `req_${randomUUID().replaceAll('-', '')}`,
    requestIdHeader: false,
    bodyLimit: 1_000_000,
    trustProxy: config.TRUST_PROXY ? config.TRUST_PROXY.split(',').map((value) => value.trim()).filter(Boolean) : false,
    logger: {
      level: config.LOG_LEVEL,
      redact: { paths: ['req.headers.authorization', 'req.headers.cookie', 'req.body'], censor: '[REDACTED]' },
    },
  });

  app.decorate('pg', database);
  app.decorate('config', config);
  app.decorate('mediaStorage', mediaStorage);
  await app.register(cors, {
    origin: config.CORS_ORIGINS.split(',').map((value) => value.trim()).filter(Boolean),
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type', 'If-Match', 'If-None-Match'],
    exposedHeaders: ['ETag', 'Retry-After', 'X-Request-Id'],
    credentials: false,
  });
  await app.register(helmet, {
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    hsts: config.NODE_ENV === 'production' ? { maxAge: 31_536_000, includeSubDomains: true } : false,
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginResourcePolicy: { policy: 'same-site' },
  });

  app.addHook('onSend', async (_request, reply, payload) => {
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('X-Request-Id', _request.id);
    if (config.NOINDEX) reply.header('X-Robots-Tag', 'noindex, nofollow, noarchive');
    return payload;
  });
  installErrorHandler(app);
  registerAuth(app, config);
  registerRateLimiting(app, config);

  app.get('/healthz', async () => ({ status: 'ok' }));
  app.get('/readyz', async (_request, reply) => {
    try {
      await app.pg.query('SELECT 1');
      return { status: 'ready' };
    } catch {
      reply.code(503);
      return { status: 'not_ready' };
    }
  });
  app.get('/api/v1', async () => ({ name: 'NOVA API', version: 'v1' }));

  await registerProfileRoutes(app);
  await registerStoryRoutes(app);
  await registerSocialRoutes(app);
  await registerCommentRoutes(app);
  await registerReportRoutes(app);
  await registerReportMetricsRoute(app);
  await registerFeedbackRoutes(app);
  await registerSecurityReportRoutes(app);
  await registerModerationRoutes(app);
  await registerMediaRoutes(app);

  let mediaRevocationWork: Promise<void> | null = null;
  const mediaRevocationTimer = setInterval(() => {
    if (mediaRevocationWork) return;
    mediaRevocationWork = processPendingMediaKeyRevocations(app).finally(() => { mediaRevocationWork = null; });
  }, 5_000);
  mediaRevocationTimer.unref();

  app.setNotFoundHandler((request, reply) => reply.code(404).send({
    error: { code: 'NOT_FOUND', message: 'Endpoint tidak ditemukan.', requestId: request.id },
  }));
  app.addHook('onClose', async () => {
    clearInterval(mediaRevocationTimer);
    await mediaRevocationWork;
    await mediaStorage.close();
  });
  return app;
}

declare module 'fastify' {
  interface FastifyInstance {
    pg: Pool;
    config: AppConfig;
    mediaStorage: MediaStorage;
  }
  interface FastifyRequest {
    user: AuthUser | null;
  }
  interface FastifyContextConfig {
    rateLimitMax?: number;
    ipRateLimitMax?: number;
    rateLimitWindowMs?: number;
  }
}
