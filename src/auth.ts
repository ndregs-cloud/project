import { randomUUID } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { AppConfig } from './config.js';
import type { AuthUser } from './types.js';
import { AppError } from './errors.js';

const allowedRoles = new Set<AuthUser['role']>(['reader', 'moderator', 'support', 'security', 'admin']);
type RequestRollbackCompensation = {
  compensate: () => Promise<void>;
  confirmCommitted?: () => Promise<boolean>;
  onOutcomeUnknown?: () => void;
};
const requestRollbackCompensations = new WeakMap<FastifyRequest, RequestRollbackCompensation[]>();

export function registerRequestRollbackCompensation(
  request: FastifyRequest,
  compensation: () => Promise<void>,
  outcome?: Pick<RequestRollbackCompensation, 'confirmCommitted' | 'onOutcomeUnknown'>,
): void {
  const callbacks = requestRollbackCompensations.get(request) ?? [];
  callbacks.push({ compensate: compensation, ...outcome });
  requestRollbackCompensations.set(request, callbacks);
}

type IdentityRow = AuthUser & { status: string };

async function authenticateToken(request: FastifyRequest, config: AppConfig): Promise<AuthUser> {
  const subject = await verifySubject(request, config);
  const client = await request.server.pg.connect();
  request.db = client;

  try {
    await client.query('BEGIN');
    // This value is taken only from the signature-verified JWT sub claim.
    await client.query("SELECT set_config('app.auth_subject', $1, true)", [subject]);
    let identity: IdentityRow | undefined;
    try {
      identity = await resolveIdentity(client);
    } catch {
      throw new AppError(503, 'IDENTITY_UNAVAILABLE', 'Layanan identitas sementara tidak tersedia.');
    }
    if (!identity || identity.subject !== subject || !allowedRoles.has(identity.role)) {
      throw new AppError(503, 'IDENTITY_UNAVAILABLE', 'Layanan identitas sementara tidak tersedia.');
    }
    if (identity.status !== 'active') {
      throw new AppError(403, 'ACCOUNT_UNAVAILABLE', 'Akun ini tidak dapat digunakan.');
    }

    // Actor ID and role are database-resolved; token/body role claims are ignored.
    await client.query(
      "SELECT set_config('app.user_id', $1, true), set_config('app.auth_subject', $2, true), set_config('app.user_role', $3, true)",
      [identity.id, subject, identity.role],
    );
    const { status: _status, ...authUser } = identity;
    return authUser;
  } catch (error) {
    request.db = null;
    await client.query('ROLLBACK').catch(() => undefined);
    client.release();
    throw error;
  }
}

async function verifySubject(request: FastifyRequest, config: AppConfig): Promise<string> {
  const authorization = request.headers.authorization;
  if (!authorization?.startsWith('Bearer ')) {
    throw new AppError(401, 'UNAUTHENTICATED', 'Autentikasi diperlukan.');
  }
  if (!config.AUTH_JWKS_URL || !config.AUTH_ISSUER || !config.AUTH_AUDIENCE) {
    throw new AppError(503, 'AUTH_NOT_CONFIGURED', 'Penyedia identitas belum dikonfigurasi.');
  }

  try {
    const jwks = getJwks(config.AUTH_JWKS_URL);
    const { payload } = await jwtVerify(authorization.slice(7), jwks, {
      issuer: config.AUTH_ISSUER,
      audience: config.AUTH_AUDIENCE,
      algorithms: ['RS256', 'ES256'],
    });
    if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) throw new Error('Missing expiry');
    if (typeof payload.sub !== 'string' || payload.sub.length === 0 || payload.sub.length > 512) {
      throw new Error('Invalid subject');
    }
    return payload.sub;
  } catch (error) {
    request.log.warn({ reason: safeJwtError(error) }, 'Access token verification failed');
    throw new AppError(401, 'INVALID_TOKEN', 'Token autentikasi tidak valid atau sudah kedaluwarsa.');
  }
}

export async function resolveIdentity(client: import('pg').PoolClient): Promise<IdentityRow | undefined> {
  const generatedUsername = `reader_${randomUUID().replaceAll('-', '').slice(0, 20)}`;
  await client.query('SAVEPOINT nova_identity_resolution');
  try {
    // Identity bootstrap is available only through this narrow database helper;
    // the runtime never performs direct users/auth_subject DML.
    const result = await client.query<IdentityRow>(
      'SELECT id, subject, username, role, status FROM public.nova_auth_bootstrap_identity($1)',
      [generatedUsername],
    );
    await client.query('RELEASE SAVEPOINT nova_identity_resolution');
    return result.rows[0];
  } catch (error) {
    await client.query('ROLLBACK TO SAVEPOINT nova_identity_resolution');
    await client.query('RELEASE SAVEPOINT nova_identity_resolution');
    if (isUndefinedFunction(error)) {
      throw new AppError(503, 'IDENTITY_UNAVAILABLE', 'Layanan identitas sementara tidak tersedia.');
    }
    throw error;
  }
}

function isUndefinedFunction(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === '42883';
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

export function registerAuth(app: FastifyInstance, config: AppConfig): void {
  app.decorateRequest('user', null);
  app.decorateRequest('db', null);
  app.addHook('preHandler', async (request) => {
    const { authRequired, authOptional } = request.routeOptions.config;
    if (!authRequired && !authOptional) return;
    const hasBearer = request.headers.authorization?.startsWith('Bearer ') ?? false;
    if (!authRequired && !hasBearer) return;
    request.user = await authenticateToken(request, config);
  });

  app.addHook('onError', async (request) => {
    await rollbackRequestTransaction(request);
  });
  app.addHook('onSend', async (request, _reply, payload) => {
    await commitRequestTransaction(request);
    return payload;
  });
  app.addHook('onResponse', async (request) => {
    // Defensive cleanup for aborted/short-circuited responses.
    await rollbackRequestTransaction(request);
  });
}

export async function commitRequestTransaction(request: FastifyRequest): Promise<void> {
  const client = request.db;
  if (!client) return;
  request.db = null;
  let clientReleased = false;
  try {
    await client.query('COMMIT');
    requestRollbackCompensations.delete(request);
  } catch (error) {
    const definiteAbort = isDefinitivePostgresAbort(error);
    if (definiteAbort) {
      await client.query('ROLLBACK').catch(() => undefined);
      await runRequestRollbackCompensations(request);
    } else {
      // Drop the original session before checking committed state through the
      // separately credentialed worker pool. Never delete a possibly referenced object.
      client.release(true);
      clientReleased = true;
      if (await confirmRequestCommitFromFreshState(request)) {
        requestRollbackCompensations.delete(request);
        request.log.warn({ event: 'request_transaction_commit_ack_lost_but_state_confirmed' },
          'Commit acknowledgement was lost; an independent worker-pool read confirmed the committed revocation state.');
        return;
      }
      await preserveRequestCopiesForReconciliation(request);
    }
    request.log.error({
      event: 'request_transaction_commit_failed',
      errorType: error instanceof Error ? error.name : 'UnknownError',
      commitOutcome: definiteAbort ? 'definitely_aborted' : 'unconfirmed',
      refreshRequired: true,
    }, 'Transaction COMMIT did not produce a confirmed outcome; refresh authoritative state before retrying.');
    throw new AppError(
      503,
      'TRANSACTION_OUTCOME_UNCONFIRMED',
      "We couldn't confirm the status. Refresh before trying again.",
    );
  } finally {
    if (!clientReleased) client.release();
  }
}

async function rollbackRequestTransaction(request: FastifyRequest): Promise<void> {
  const client = request.db;
  request.db = null;
  if (client) {
    await client.query('ROLLBACK').catch(() => undefined);
    client.release();
  }
  await runRequestRollbackCompensations(request);
}

async function runRequestRollbackCompensations(request: FastifyRequest): Promise<void> {
  const callbacks = requestRollbackCompensations.get(request);
  requestRollbackCompensations.delete(request);
  if (!callbacks) return;
  for (const compensate of callbacks.reverse()) {
    try {
      await compensate.compensate();
    } catch (error) {
      request.log.error(
        { errorType: error instanceof Error ? error.name : 'UnknownError' },
        'Request rollback compensation failed.',
      );
    }
  }
}

const DEFINITIVE_POSTGRES_ABORT_CODES = new Set([
  '40001', // serialization_failure
  '40002', // transaction_integrity_constraint_violation
  '40P01', // deadlock_detected
  '23502', // not_null_violation
  '23503', // foreign_key_violation
  '23505', // unique_violation
  '23514', // check_violation (including a deferred constraint at COMMIT)
  '23P01', // exclusion_violation
]);

function isDefinitivePostgresAbort(error: unknown): boolean {
  if (typeof error !== 'object' || error === null || !('code' in error) || typeof error.code !== 'string') return false;
  const code = error.code.toUpperCase();
  // Only known transaction-abort outcomes permit destructive copy compensation;
  // every other COMMIT error must be resolved from fresh state or treated as unknown.
  return /^[0-9A-Z]{5}$/.test(code) && DEFINITIVE_POSTGRES_ABORT_CODES.has(code);
}

async function confirmRequestCommitFromFreshState(request: FastifyRequest): Promise<boolean> {
  const callbacks = requestRollbackCompensations.get(request);
  if (!callbacks?.length || callbacks.some((callback) => !callback.confirmCommitted)) return false;
  try {
    for (const callback of callbacks) {
      if (!(await callback.confirmCommitted!())) return false;
    }
    return true;
  } catch {
    return false;
  }
}

async function preserveRequestCopiesForReconciliation(request: FastifyRequest): Promise<void> {
  const callbacks = requestRollbackCompensations.get(request);
  requestRollbackCompensations.delete(request);
  for (const callback of callbacks ?? []) {
    try { callback.onOutcomeUnknown?.(); } catch { /* do not replace the neutral API error */ }
  }
}

function safeJwtError(error: unknown): string {
  if (error instanceof Error) return error.name;
  return 'TokenVerificationError';
}
