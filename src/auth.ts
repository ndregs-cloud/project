import { randomUUID } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { AppConfig } from './config.js';
import type { AuthUser } from './types.js';
import { AppError } from './errors.js';

export async function authenticateToken(request: FastifyRequest, config: AppConfig): Promise<AuthUser> {
  const authorization = request.headers.authorization;
  if (!authorization?.startsWith('Bearer ')) {
    throw new AppError(401, 'UNAUTHENTICATED', 'Autentikasi diperlukan.');
  }
  if (!config.AUTH_JWKS_URL || !config.AUTH_ISSUER || !config.AUTH_AUDIENCE) {
    throw new AppError(503, 'AUTH_NOT_CONFIGURED', 'Penyedia identitas belum dikonfigurasi.');
  }

  let subject: string;
  try {
    const jwks = getJwks(config.AUTH_JWKS_URL);
    const { payload } = await jwtVerify(authorization.slice(7), jwks, {
      issuer: config.AUTH_ISSUER,
      audience: config.AUTH_AUDIENCE,
      algorithms: ['RS256', 'ES256'],
    });
    if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) throw new Error('Missing expiry');
    if (typeof payload.sub !== 'string' || payload.sub.length === 0) throw new Error('Missing subject');
    subject = payload.sub;
  } catch (error) {
    request.log.warn({ reason: safeJwtError(error) }, 'Access token verification failed');
    throw new AppError(401, 'INVALID_TOKEN', 'Token autentikasi tidak valid atau sudah kedaluwarsa.');
  }

  return upsertIdentity(request, subject);
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function getJwks(url: string): ReturnType<typeof createRemoteJWKSet> {
  let jwks = jwksCache.get(url);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(url));
    jwksCache.set(url, jwks);
  }
  return jwks;
}

async function upsertIdentity(request: FastifyRequest, subject: string): Promise<AuthUser> {
  const pool = request.server.pg;
  const generatedUsername = `reader_${randomUUID().replaceAll('-', '').slice(0, 20)}`;
  const result = await pool.query<AuthUser & { status: string }>(
    `INSERT INTO users (auth_subject, username, username_normalized)
     VALUES ($1, $2, $3)
     ON CONFLICT (auth_subject) DO UPDATE SET auth_subject = EXCLUDED.auth_subject
     RETURNING id, auth_subject AS subject, username, role, status`,
    [subject, generatedUsername, generatedUsername.toLowerCase()],
  );
  const user = result.rows[0];
  if (!user) throw new AppError(503, 'IDENTITY_UNAVAILABLE', 'Akun belum dapat dimuat.');
  if (user.status !== 'active') throw new AppError(403, 'ACCOUNT_UNAVAILABLE', 'Akun ini tidak dapat digunakan.');
  const { status: _status, ...authUser } = user;
  return authUser;
}

export function registerAuth(app: FastifyInstance, config: AppConfig): void {
  app.decorateRequest('user', null);
  app.addHook('preHandler', async (request) => {
    const { authRequired, authOptional } = request.routeOptions.config;
    if (!authRequired && !authOptional) return;
    const hasBearer = request.headers.authorization?.startsWith('Bearer ') ?? false;
    if (!authRequired && !hasBearer) return;
    request.user = await authenticateToken(request, config);
  });
}

function safeJwtError(error: unknown): string {
  if (error instanceof Error) return error.name;
  return 'TokenVerificationError';
}
