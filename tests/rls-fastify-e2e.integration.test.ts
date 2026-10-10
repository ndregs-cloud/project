import { createServer, type Server } from 'node:http';
import { randomBytes } from 'node:crypto';
import { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Pool } from 'pg';
import { exportJWK, generateKeyPair, SignJWT, type JWTPayload } from 'jose';
import type { MediaStorage } from '../src/storage/s3.js';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { closePool, mediaRevocationPool, pool, rateLimitPool } from '../src/db.js';

const enabled = process.env.RUN_RLS_FASTIFY_E2E === '1';
type Response = { statusCode: number; headers?: Record<string, string | string[] | undefined>; json: () => any };

function assertLoopbackDisposable(url: string | undefined, label: string): string {
  if (!url) throw new Error(`${label} is required for RUN_RLS_FASTIFY_E2E=1`);
  const parsed = new URL(url);
  if (!['127.0.0.1', 'localhost', '::1'].includes(parsed.hostname)) {
    throw new Error(`${label} must point to a loopback-only PostgreSQL 17 disposable database`);
  }
  const database = decodeURIComponent(parsed.pathname.replace(/^\//, ''));
  if (!database.startsWith('nova_rls_e2e_')) {
    throw new Error(`${label} must name a disposable database beginning with nova_rls_e2e_`);
  }
  return database;
}

function loginName(url: string): string {
  return decodeURIComponent(new URL(url).username);
}

function quoteRoleName(name: string): string {
  if (!/^[a-z_][a-z0-9_]*$/.test(name)) throw new Error('Unexpected disposable role name');
  return `"${name}"`;
}

async function attemptSetRole(database: typeof pool, targetRole: string): Promise<string | undefined> {
  const client = await database.connect();
  let code: string | undefined;
  try {
    await client.query('BEGIN');
    await client.query(`SET ROLE ${targetRole}`);
  } catch (error) {
    code = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : undefined;
  } finally {
    await client.query('ROLLBACK').catch(() => undefined);
    client.release();
  }
  return code;
}

async function principalMembershipProbe(database: typeof pool, expectedRole: string) {
  const result = await database.query<{
    role: string; login: string; principalInherit: boolean; principalDirectMemberships: number;
    principalMembershipClosure: number; principalAdminOptionCount: number; principalMemberCount: number;
    loginInherit: boolean; loginDirectMemberships: number; loginAdminOptionCount: number;
    loginMembershipClosure: number; loginExpectedMembershipCount: number;
    loginMembershipInheritOption: boolean; loginMembershipSetOption: boolean; loginMembershipAdminOption: boolean;
    canSetExpected: boolean;
    principalCreateRole: boolean; principalCreateDb: boolean; principalReplication: boolean;
    loginCreateRole: boolean; loginCreateDb: boolean; loginReplication: boolean;
    loginCanLogin: boolean; loginBootstrapExecute: boolean; loginUsersInsert: boolean;
    loginUsersAnyInsert: boolean; loginAuthSubjectSelect: boolean; loginAuthSubjectInsert: boolean;
    principalSchemaUsage: boolean; principalSchemaCreate: boolean; loginSchemaUsage: boolean; loginSchemaCreate: boolean;
    publicSchemaGrant: boolean;
  }>(
    `SELECT current_user::text AS role,session_user::text AS login,
       principal.rolinherit AS "principalInherit",login_role.rolinherit AS "loginInherit",
       principal.rolcreaterole AS "principalCreateRole",principal.rolcreatedb AS "principalCreateDb",
       principal.rolreplication AS "principalReplication",
       login_role.rolcreaterole AS "loginCreateRole",login_role.rolcreatedb AS "loginCreateDb",
       login_role.rolreplication AS "loginReplication",
       login_role.rolcanlogin AS "loginCanLogin",
       pg_catalog.has_schema_privilege(current_user,'public','USAGE') AS "principalSchemaUsage",
       pg_catalog.has_schema_privilege(current_user,'public','CREATE') AS "principalSchemaCreate",
       pg_catalog.has_schema_privilege(session_user,'public','USAGE') AS "loginSchemaUsage",
       pg_catalog.has_schema_privilege(session_user,'public','CREATE') AS "loginSchemaCreate",
       EXISTS (SELECT 1 FROM pg_catalog.pg_namespace ns
         CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(ns.nspacl,pg_catalog.acldefault('n',ns.nspowner))) acl
         WHERE ns.nspname='public' AND acl.grantee=0 AND acl.privilege_type IN ('USAGE','CREATE')) AS "publicSchemaGrant",
       pg_catalog.has_function_privilege(session_user,'public.nova_auth_bootstrap_identity(text)','EXECUTE') AS "loginBootstrapExecute",
       pg_catalog.has_table_privilege(session_user,'public.users','INSERT') AS "loginUsersInsert",
       pg_catalog.has_any_column_privilege(session_user,'public.users','INSERT') AS "loginUsersAnyInsert",
       pg_catalog.has_column_privilege(session_user,'public.users','auth_subject','SELECT') AS "loginAuthSubjectSelect",
       pg_catalog.has_column_privilege(session_user,'public.users','auth_subject','INSERT') AS "loginAuthSubjectInsert",
       (SELECT count(*)::integer FROM pg_catalog.pg_auth_members m WHERE m.member=principal.oid) AS "principalDirectMemberships",
       (SELECT count(*)::integer FROM pg_catalog.pg_auth_members m WHERE m.roleid=principal.oid) AS "principalMemberCount",
       (SELECT count(*)::integer FROM pg_catalog.pg_auth_members m WHERE m.member=principal.oid AND m.admin_option) AS "principalAdminOptionCount",
       (SELECT count(*)::integer FROM (
         WITH RECURSIVE closure(roleid) AS (
           SELECT m.roleid FROM pg_catalog.pg_auth_members m WHERE m.member=principal.oid
           UNION SELECT m.roleid FROM pg_catalog.pg_auth_members m JOIN closure c ON m.member=c.roleid
         ) SELECT DISTINCT roleid FROM closure
       ) closure_rows) AS "principalMembershipClosure",
       (SELECT count(*)::integer FROM pg_catalog.pg_auth_members m WHERE m.member=login_role.oid) AS "loginDirectMemberships",
       (SELECT count(*)::integer FROM pg_catalog.pg_auth_members m WHERE m.member=login_role.oid AND m.admin_option) AS "loginAdminOptionCount",
       (SELECT count(*)::integer FROM (
         WITH RECURSIVE closure(roleid) AS (
           SELECT m.roleid FROM pg_catalog.pg_auth_members m WHERE m.member=login_role.oid
           UNION SELECT m.roleid FROM pg_catalog.pg_auth_members m JOIN closure c ON m.member=c.roleid
         ) SELECT DISTINCT roleid FROM closure
       ) closure_rows) AS "loginMembershipClosure",
       (SELECT count(*)::integer FROM pg_catalog.pg_auth_members m
         WHERE m.member=login_role.oid AND m.roleid=principal.oid) AS "loginExpectedMembershipCount",
       (SELECT m.inherit_option FROM pg_catalog.pg_auth_members m
         WHERE m.member=login_role.oid AND m.roleid=principal.oid) AS "loginMembershipInheritOption",
       (SELECT m.set_option FROM pg_catalog.pg_auth_members m
         WHERE m.member=login_role.oid AND m.roleid=principal.oid) AS "loginMembershipSetOption",
       (SELECT m.admin_option FROM pg_catalog.pg_auth_members m
         WHERE m.member=login_role.oid AND m.roleid=principal.oid) AS "loginMembershipAdminOption",
       pg_catalog.pg_has_role(session_user,$1,'SET') AS "canSetExpected"
     FROM pg_catalog.pg_roles principal CROSS JOIN pg_catalog.pg_roles login_role
     WHERE principal.rolname=current_user AND login_role.rolname=session_user`, [expectedRole],
  );
  return result.rows[0];
}

describe.skipIf(!enabled)('Fastify RLS request transaction (PostgreSQL 17 disposable E2E)', () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  let controlPool: Pool | undefined;
  let jwksServer: Server;
  let privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
  let appConfig: ReturnType<typeof loadConfig> | undefined;
  let storageDependency: MediaStorage | undefined;
  const issuer = 'https://issuer.rls-e2e.test/';
  const prefix = `nova-rls-e2e:${process.env.RLS_E2E_RUN_ID ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`}`;
  const subjects = [`${prefix}:owner`, `${prefix}:other`];
  const actors = new Map<string, { subject: string; token: string; id: string }>();

  async function tokenFor(subject: string, claims: JWTPayload = {}): Promise<string> {
    return new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: 'rls-fastify-e2e' })
      .setIssuer(issuer).setAudience('nova-api').setSubject(subject).setIssuedAt()
      .setExpirationTime('5m').sign(privateKey);
  }

  async function request(method: 'GET' | 'POST' | 'PATCH', url: string, token?: string, payload?: unknown): Promise<Response> {
    const inject = app.inject.bind(app) as unknown as (options: {
      method: 'GET' | 'POST' | 'PATCH'; url: string; payload?: unknown; headers?: Record<string, string>;
    }) => Promise<Response>;
    return inject({ method, url, ...(payload === undefined ? {} : { payload }),
      ...(token ? { headers: { authorization: `Bearer ${token}` } } : {}) });
  }

  function buildAppWithPrincipalValidation() {
    if (!appConfig || !storageDependency) throw new Error('RLS test app dependencies are not initialized');
    return buildApp({ config: appConfig, pg: pool, rateLimitPg: rateLimitPool,
      mediaRevocationPg: mediaRevocationPool, mediaStorage: storageDependency, validatePrincipalStartup: true });
  }

  async function expectContextClearedAndPoolReused(expectedPid?: number): Promise<number> {
    const result = await pool.query<{ pid: number; userId: string | null; subject: string | null; role: string | null }>(
      `SELECT pg_backend_pid() AS pid,
         NULLIF(current_setting('app.user_id',true),'') AS "userId",
         NULLIF(current_setting('app.auth_subject',true),'') AS subject,
         NULLIF(current_setting('app.user_role',true),'') AS role`,
    );
    const row = result.rows[0]!;
    expect(row.userId).toBeNull();
    expect(row.subject).toBeNull();
    expect(row.role).toBeNull();
    if (expectedPid !== undefined) expect(row.pid).toBe(expectedPid);
    return row.pid;
  }

  beforeAll(async () => {
    const database = assertLoopbackDisposable(process.env.DATABASE_URL, 'DATABASE_URL');
    const rateLimitDatabase = assertLoopbackDisposable(process.env.RATE_LIMIT_DATABASE_URL, 'RATE_LIMIT_DATABASE_URL');
    const workerDatabase = assertLoopbackDisposable(process.env.MEDIA_REVOCATION_DATABASE_URL, 'MEDIA_REVOCATION_DATABASE_URL');
    const controlDatabase = assertLoopbackDisposable(process.env.RLS_CONTROL_DATABASE_URL, 'RLS_CONTROL_DATABASE_URL');
    if (database !== rateLimitDatabase || database !== workerDatabase || database !== controlDatabase) {
      throw new Error('Runtime, limiter, and worker URLs must point to the same named disposable database');
    }
    const addresses = [process.env.DATABASE_URL, process.env.RATE_LIMIT_DATABASE_URL,
      process.env.MEDIA_REVOCATION_DATABASE_URL, process.env.RLS_CONTROL_DATABASE_URL]
      .map((url) => new URL(url!).host);
    if (!addresses.every((address) => address === addresses[0])) {
      throw new Error('Runtime, limiter, worker, and control URLs must point to the same loopback PostgreSQL server');
    }
    controlPool = new Pool({ connectionString: process.env.RLS_CONTROL_DATABASE_URL, max: 1 });
    const controlPrincipal = await controlPool.query<{ role: string; login: string }>('SELECT current_user AS role,session_user AS login');
    expect(controlPrincipal.rows[0]).toEqual({ role: 'postgres', login: 'postgres' });
    if (process.env.DATABASE_POOL_MAX !== '1') {
      throw new Error('Set DATABASE_POOL_MAX=1 to prove context reset on physical connection reuse');
    }

    const version = await pool.query<{ version: string }>('SELECT current_setting(\'server_version_num\') AS version');
    if (!version.rows[0] || Number(version.rows[0].version) < 170000 || Number(version.rows[0].version) >= 180000) {
      throw new Error('RUN_RLS_FASTIFY_E2E requires PostgreSQL 17');
    }
    const runtimePrincipal = await pool.query<{
      role: string; login: string; hasRateLimitSelect: boolean; hasRateLimitInsert: boolean;
      hasRateLimitUpdate: boolean; hasRateLimitDelete: boolean; canCallRateLimitCounter: boolean; canUpdateStoryStatus: boolean;
      canInsertModerationAction: boolean; canInsertRevocation: boolean; wrapperCanDeleteStories: boolean;
      wrapperCanUpdateStoryStatus: boolean; wrapperCanInsertAction: boolean; wrapperCanInsertRevocation: boolean;
      canCallModerationProcedure: boolean; canCallEnqueueProcedure: boolean;
      canBootstrapIdentity: boolean; canInsertUsers: boolean; canInsertAnyUsersColumn: boolean;
      canSelectAuthSubject: boolean; canInsertAuthSubject: boolean;
    }>(
      `SELECT current_user AS role, session_user AS login,
         has_table_privilege(current_user,'public.rate_limit_buckets','SELECT') AS "hasRateLimitSelect",
         has_table_privilege(current_user,'public.rate_limit_buckets','INSERT') AS "hasRateLimitInsert",
         has_table_privilege(current_user,'public.rate_limit_buckets','UPDATE') AS "hasRateLimitUpdate",
         has_table_privilege(current_user,'public.rate_limit_buckets','DELETE') AS "hasRateLimitDelete",
         has_function_privilege(current_user,'public.nova_rate_limit_record(text,timestamptz)','EXECUTE') AS "canCallRateLimitCounter",
         has_column_privilege(current_user,'public.stories','status','UPDATE') AS "canUpdateStoryStatus",
         has_table_privilege(current_user,'public.moderation_actions','INSERT') AS "canInsertModerationAction",
         has_table_privilege(current_user,'public.media_key_revocations','INSERT') AS "canInsertRevocation",
         has_table_privilege(session_user,'public.stories','DELETE') AS "wrapperCanDeleteStories",
         has_column_privilege(session_user,'public.stories','status','UPDATE') AS "wrapperCanUpdateStoryStatus",
         has_column_privilege(session_user,'public.moderation_actions','reason','INSERT') AS "wrapperCanInsertAction",
         has_column_privilege(session_user,'public.media_key_revocations','media_id','INSERT') AS "wrapperCanInsertRevocation",
         has_function_privilege(current_user,'public.nova_moderate_hide_story(uuid,text)','EXECUTE') AS "canCallModerationProcedure",
         has_function_privilege(current_user,'public.nova_enqueue_media_key_revocation(uuid,uuid,text,text)','EXECUTE') AS "canCallEnqueueProcedure",
         has_function_privilege(current_user,'public.nova_auth_bootstrap_identity(text)','EXECUTE') AS "canBootstrapIdentity",
         has_table_privilege(current_user,'public.users','INSERT') AS "canInsertUsers",
         has_any_column_privilege(current_user,'public.users','INSERT') AS "canInsertAnyUsersColumn",
         has_column_privilege(current_user,'public.users','auth_subject','SELECT') AS "canSelectAuthSubject",
         has_column_privilege(current_user,'public.users','auth_subject','INSERT') AS "canInsertAuthSubject"`,
    );
    expect(runtimePrincipal.rows[0]).toEqual({
      role: 'nova_fastify_runtime', login: loginName(process.env.DATABASE_URL!), hasRateLimitSelect: false,
      hasRateLimitInsert: false, hasRateLimitUpdate: false, hasRateLimitDelete: false, canCallRateLimitCounter: false,
      canUpdateStoryStatus: true, canInsertModerationAction: false, canInsertRevocation: false,
      wrapperCanDeleteStories: false, wrapperCanUpdateStoryStatus: false, wrapperCanInsertAction: false,
      wrapperCanInsertRevocation: false, canCallModerationProcedure: true, canCallEnqueueProcedure: true,
      canBootstrapIdentity: true, canInsertUsers: false, canInsertAnyUsersColumn: false,
      canSelectAuthSubject: false, canInsertAuthSubject: false,
    });
    const limiterPrincipal = await rateLimitPool.query<{ role: string; login: string; hasSelect: boolean; hasInsert: boolean; hasUpdate: boolean; hasDelete: boolean; canCallCounter: boolean; canBootstrapIdentity: boolean; canDeleteStories: boolean; wrapperCanInsert: boolean; wrapperCanUpdate: boolean }>(
      `SELECT current_user AS role, session_user AS login,
         has_table_privilege(current_user,'public.rate_limit_buckets','SELECT') AS "hasSelect",
         has_table_privilege(current_user,'public.rate_limit_buckets','INSERT') AS "hasInsert",
         has_table_privilege(current_user,'public.rate_limit_buckets','UPDATE') AS "hasUpdate",
         has_table_privilege(current_user,'public.rate_limit_buckets','DELETE') AS "hasDelete",
         has_function_privilege(current_user,'public.nova_rate_limit_record(text,timestamptz)','EXECUTE') AS "canCallCounter",
         has_function_privilege(current_user,'public.nova_auth_bootstrap_identity(text)','EXECUTE') AS "canBootstrapIdentity",
         has_table_privilege(current_user,'public.stories','DELETE') AS "canDeleteStories",
         has_table_privilege(session_user,'public.rate_limit_buckets','INSERT') AS "wrapperCanInsert",
         has_table_privilege(session_user,'public.rate_limit_buckets','UPDATE') AS "wrapperCanUpdate"`,
    );
    expect(limiterPrincipal.rows[0]).toEqual({
      role: 'nova_rate_limiter_runtime', login: loginName(process.env.RATE_LIMIT_DATABASE_URL!),
      hasSelect: false, hasInsert: false, hasUpdate: false, hasDelete: false, canCallCounter: true,
      canBootstrapIdentity: false, canDeleteStories: false, wrapperCanInsert: false, wrapperCanUpdate: false,
    });
    const workerPrincipal = await mediaRevocationPool.query<{
      role: string; login: string; canReadId: boolean; canReadMediaId: boolean; canReadSourceKey: boolean;
      canReadActionId: boolean; canReadAttemptCount: boolean; canReadRetryAfter: boolean; canReadCreatedAt: boolean;
      canReadEscalatedAt: boolean; canUpdateAttemptCount: boolean; canUpdateRetryAfter: boolean;
      canUpdateEscalatedAt: boolean; canDelete: boolean; canUpdateActions: boolean;
      wrapperCanUpdateRetry: boolean; canBootstrapIdentity: boolean;
    }>(
      `SELECT current_user AS role,
         session_user AS login,
         has_column_privilege(current_user,'public.media_key_revocations','id','SELECT') AS "canReadId",
         has_column_privilege(current_user,'public.media_key_revocations','media_id','SELECT') AS "canReadMediaId",
         has_column_privilege(current_user,'public.media_key_revocations','source_key','SELECT') AS "canReadSourceKey",
         has_column_privilege(current_user,'public.media_key_revocations','moderation_action_id','SELECT') AS "canReadActionId",
         has_column_privilege(current_user,'public.media_key_revocations','attempt_count','SELECT') AS "canReadAttemptCount",
         has_column_privilege(current_user,'public.media_key_revocations','retry_after','SELECT') AS "canReadRetryAfter",
         has_column_privilege(current_user,'public.media_key_revocations','created_at','SELECT') AS "canReadCreatedAt",
         has_column_privilege(current_user,'public.media_key_revocations','escalated_at','SELECT') AS "canReadEscalatedAt",
         has_column_privilege(current_user,'public.media_key_revocations','attempt_count','UPDATE') AS "canUpdateAttemptCount",
         has_column_privilege(current_user,'public.media_key_revocations','retry_after','UPDATE') AS "canUpdateRetryAfter",
         has_column_privilege(current_user,'public.media_key_revocations','escalated_at','UPDATE') AS "canUpdateEscalatedAt",
         has_column_privilege(session_user,'public.media_key_revocations','attempt_count','UPDATE') AS "wrapperCanUpdateRetry",
         has_table_privilege(current_user,'public.media_key_revocations','DELETE') AS "canDelete",
         has_table_privilege(current_user,'public.moderation_actions','UPDATE') AS "canUpdateActions",
         has_function_privilege(current_user,'public.nova_auth_bootstrap_identity(text)','EXECUTE') AS "canBootstrapIdentity"`,
    );
    expect(workerPrincipal.rows[0]).toEqual({
      role: 'nova_media_revocation_worker', login: loginName(process.env.MEDIA_REVOCATION_DATABASE_URL!),
      canReadId: true, canReadMediaId: true, canReadSourceKey: true, canReadActionId: true,
      canReadAttemptCount: true, canReadRetryAfter: true, canReadCreatedAt: true, canReadEscalatedAt: true,
      canUpdateAttemptCount: true, canUpdateRetryAfter: true, canUpdateEscalatedAt: true,
      canDelete: false, canUpdateActions: false, wrapperCanUpdateRetry: false, canBootstrapIdentity: false,
    });
    const principalBoundaries = await Promise.all([
      principalMembershipProbe(pool, 'nova_fastify_runtime'),
      principalMembershipProbe(rateLimitPool, 'nova_rate_limiter_runtime'),
      principalMembershipProbe(mediaRevocationPool, 'nova_media_revocation_worker'),
    ]);
    expect(principalBoundaries).toEqual([
      {
        role: 'nova_fastify_runtime', login: loginName(process.env.DATABASE_URL!),
        principalInherit: false, principalDirectMemberships: 0, principalMembershipClosure: 0, principalAdminOptionCount: 0, principalMemberCount: 1,
        loginInherit: false, loginDirectMemberships: 1, loginMembershipClosure: 1, loginExpectedMembershipCount: 1,
        loginMembershipInheritOption: false, loginMembershipSetOption: true, loginMembershipAdminOption: false,
        loginAdminOptionCount: 0, canSetExpected: true,
        principalCreateRole: false, principalCreateDb: false, principalReplication: false,
        loginCreateRole: false, loginCreateDb: false, loginReplication: false,
        loginCanLogin: true, loginBootstrapExecute: false, loginUsersInsert: false,
        loginUsersAnyInsert: false, loginAuthSubjectSelect: false, loginAuthSubjectInsert: false,
        principalSchemaUsage: true, principalSchemaCreate: false, loginSchemaUsage: false,
        loginSchemaCreate: false, publicSchemaGrant: false,
      },
      {
        role: 'nova_rate_limiter_runtime', login: loginName(process.env.RATE_LIMIT_DATABASE_URL!),
        principalInherit: false, principalDirectMemberships: 0, principalMembershipClosure: 0, principalAdminOptionCount: 0, principalMemberCount: 1,
        loginInherit: false, loginDirectMemberships: 1, loginMembershipClosure: 1, loginExpectedMembershipCount: 1,
        loginMembershipInheritOption: false, loginMembershipSetOption: true, loginMembershipAdminOption: false,
        loginAdminOptionCount: 0, canSetExpected: true,
        principalCreateRole: false, principalCreateDb: false, principalReplication: false,
        loginCreateRole: false, loginCreateDb: false, loginReplication: false,
        loginCanLogin: true, loginBootstrapExecute: false, loginUsersInsert: false,
        loginUsersAnyInsert: false, loginAuthSubjectSelect: false, loginAuthSubjectInsert: false,
        principalSchemaUsage: true, principalSchemaCreate: false, loginSchemaUsage: false,
        loginSchemaCreate: false, publicSchemaGrant: false,
      },
      {
        role: 'nova_media_revocation_worker', login: loginName(process.env.MEDIA_REVOCATION_DATABASE_URL!),
        principalInherit: false, principalDirectMemberships: 0, principalMembershipClosure: 0, principalAdminOptionCount: 0, principalMemberCount: 1,
        loginInherit: false, loginDirectMemberships: 1, loginMembershipClosure: 1, loginExpectedMembershipCount: 1,
        loginMembershipInheritOption: false, loginMembershipSetOption: true, loginMembershipAdminOption: false,
        loginAdminOptionCount: 0, canSetExpected: true,
        principalCreateRole: false, principalCreateDb: false, principalReplication: false,
        loginCreateRole: false, loginCreateDb: false, loginReplication: false,
        loginCanLogin: true, loginBootstrapExecute: false, loginUsersInsert: false,
        loginUsersAnyInsert: false, loginAuthSubjectSelect: false, loginAuthSubjectInsert: false,
        principalSchemaUsage: true, principalSchemaCreate: false, loginSchemaUsage: false,
        loginSchemaCreate: false, publicSchemaGrant: false,
      },
    ]);
    const forbiddenRoleSwitches: Array<[typeof pool, string]> = [
      [pool, 'nova_rate_limiter_runtime'], [pool, 'nova_media_revocation_worker'],
      [rateLimitPool, 'nova_fastify_runtime'], [rateLimitPool, 'nova_media_revocation_worker'],
      [mediaRevocationPool, 'nova_fastify_runtime'], [mediaRevocationPool, 'nova_rate_limiter_runtime'],
    ];
    for (const [databasePool, targetRole] of forbiddenRoleSwitches) {
      expect(await attemptSetRole(databasePool, targetRole)).toBe('42501');
    }
    const forcedRls = await pool.query<{ tableCount: string; forcedCount: string }>(
      `SELECT count(*)::text AS "tableCount",
         count(*) FILTER (WHERE c.relrowsecurity AND c.relforcerowsecurity)::text AS "forcedCount"
       FROM pg_catalog.pg_class c
       WHERE c.oid IN ('public.stories'::regclass,'public.moderation_actions'::regclass,'public.media_key_revocations'::regclass)`,
    );
    expect(forcedRls.rows[0]).toEqual({ tableCount: '3', forcedCount: '3' });

    const { publicKey, privateKey: signer } = await generateKeyPair('RS256');
    privateKey = signer;
    const jwk = await exportJWK(publicKey);
    Object.assign(jwk, { kid: 'rls-fastify-e2e', alg: 'RS256', use: 'sig' });
    jwksServer = createServer((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ keys: [jwk] }));
    });
    await new Promise<void>((resolve, reject) => {
      jwksServer.once('error', reject);
      jwksServer.listen(0, '127.0.0.1', resolve);
    });
    const port = (jwksServer.address() as AddressInfo).port;
    appConfig = loadConfig({
      ...process.env,
      NODE_ENV: 'test',
      RATE_LIMIT_HMAC_KEY: randomBytes(32).toString('hex'),
      LOG_LEVEL: 'error',
      AUTH_JWKS_URL: `http://127.0.0.1:${port}/jwks`,
      AUTH_ISSUER: issuer,
      AUTH_AUDIENCE: 'nova-api',
      CORS_ORIGINS: 'https://app.nova.test',
    });
    storageDependency = { close: async () => undefined } as unknown as MediaStorage;
    app = await buildAppWithPrincipalValidation();
  }, 30_000);

  afterAll(async () => {
    if (app) await app.close();
    if (jwksServer) await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
    if (controlPool) await controlPool.end();
    await closePool();
  }, 30_000);

  it('rejects administrative memberships, unsafe helper metadata, and each missing worker queue column privilege at startup', async () => {
    if (!controlPool) throw new Error('RLS control connection is not initialized');
    const roleNames = [
      'nova_fastify_runtime', 'nova_rate_limiter_runtime', 'nova_media_revocation_worker',
      loginName(process.env.DATABASE_URL!), loginName(process.env.RATE_LIMIT_DATABASE_URL!),
      loginName(process.env.MEDIA_REVOCATION_DATABASE_URL!),
    ];
    for (const role of roleNames) {
      for (const attribute of ['SUPERUSER', 'BYPASSRLS', 'CREATEROLE', 'CREATEDB', 'REPLICATION', 'INHERIT'] as const) {
        await controlPool.query(`ALTER ROLE ${quoteRoleName(role)} ${attribute}`);
        try {
          await expect(buildAppWithPrincipalValidation()).rejects.toThrow(/Database principal verification failed for/);
        } finally {
          await Promise.all([pool.query('SELECT 1'), rateLimitPool.query('SELECT 1'), mediaRevocationPool.query('SELECT 1')]);
          await controlPool.query(`ALTER ROLE ${quoteRoleName(role)} NO${attribute}`);
        }
      }
    }

    const expectRejectedStartupMutation = async (statement: string, restore: string) => {
      await controlPool!.query(statement);
      try {
        await expect(buildAppWithPrincipalValidation()).rejects.toThrow(/Database principal verification failed for (runtime|limiter|worker) pool/);
      } finally {
        await Promise.all([pool.query('SELECT 1'), rateLimitPool.query('SELECT 1'), mediaRevocationPool.query('SELECT 1')]);
        await controlPool!.query(restore);
      }
    };
    // PostgreSQL 17 reserves every user-created `pg_` namespace, even for the local superuser.
    // Record that server invariant; the grant probes below use a creatable non-system schema.
    await expect(controlPool.query('CREATE SCHEMA pg_private')).rejects.toThrow(/unacceptable schema name/i);
    const extraSchema = 'nova_security_owner_extra_schema_probe';
    await controlPool.query(`
      CREATE SCHEMA ${extraSchema};
      CREATE TABLE ${extraSchema}.grant_probe (id integer);
      CREATE SEQUENCE ${extraSchema}.sequence_probe;
      CREATE FUNCTION ${extraSchema}.function_probe() RETURNS integer LANGUAGE sql AS 'SELECT 1';
      REVOKE ALL ON FUNCTION ${extraSchema}.function_probe() FROM PUBLIC`);
    try {
      for (const owner of ['nova_auth_identity_owner', 'nova_rate_limit_counter_owner']) {
        const role = quoteRoleName(owner);
        await expectRejectedStartupMutation(
          `GRANT USAGE ON SCHEMA ${extraSchema} TO ${role}`,
          `REVOKE USAGE ON SCHEMA ${extraSchema} FROM ${role}`,
        );
        await expectRejectedStartupMutation(
          `GRANT CREATE ON SCHEMA ${extraSchema} TO ${role}`,
          `REVOKE CREATE ON SCHEMA ${extraSchema} FROM ${role}`,
        );
        await expectRejectedStartupMutation(
          `GRANT SELECT ON TABLE ${extraSchema}.grant_probe TO ${role}`,
          `REVOKE SELECT ON TABLE ${extraSchema}.grant_probe FROM ${role}`,
        );
        await expectRejectedStartupMutation(
          `GRANT SELECT (id) ON TABLE ${extraSchema}.grant_probe TO ${role}`,
          `REVOKE SELECT (id) ON TABLE ${extraSchema}.grant_probe FROM ${role}`,
        );
        await expectRejectedStartupMutation(
          `GRANT USAGE ON SEQUENCE ${extraSchema}.sequence_probe TO ${role}`,
          `REVOKE USAGE ON SEQUENCE ${extraSchema}.sequence_probe FROM ${role}`,
        );
        await expectRejectedStartupMutation(
          `GRANT EXECUTE ON FUNCTION ${extraSchema}.function_probe() TO ${role}`,
          `REVOKE EXECUTE ON FUNCTION ${extraSchema}.function_probe() FROM ${role}`,
        );
      }
      for (const owner of [
        'nova_story_moderation_manager', 'nova_revocation_enqueuer_owner',
        'nova_media_state_predicate_owner', 'nova_action_predicate_owner',
        'nova_actor_predicate_owner', 'nova_media_predicate_owner',
      ]) {
        const role = quoteRoleName(owner);
        const schemaUsage = await controlPool.query<{ hasUsage: boolean }>(
          'SELECT pg_catalog.has_schema_privilege($1,$2,\'USAGE\') AS "hasUsage"', [owner, extraSchema],
        );
        expect(schemaUsage.rows[0]?.hasUsage).toBe(false);
        await expectRejectedStartupMutation(
          `GRANT USAGE ON SCHEMA ${extraSchema} TO ${role}`,
          `REVOKE USAGE ON SCHEMA ${extraSchema} FROM ${role}`,
        );
        await expectRejectedStartupMutation(
          `GRANT CREATE ON SCHEMA ${extraSchema} TO ${role}`,
          `REVOKE CREATE ON SCHEMA ${extraSchema} FROM ${role}`,
        );
        const schemaUsageAfter = await controlPool.query<{ hasUsage: boolean }>(
          'SELECT pg_catalog.has_schema_privilege($1,$2,\'USAGE\') AS "hasUsage"', [owner, extraSchema],
        );
        expect(schemaUsageAfter.rows[0]?.hasUsage).toBe(false);
        await expectRejectedStartupMutation(
          `GRANT SELECT ON TABLE ${extraSchema}.grant_probe TO ${role}`,
          `REVOKE SELECT ON TABLE ${extraSchema}.grant_probe FROM ${role}`,
        );
        await expectRejectedStartupMutation(
          `GRANT SELECT (id) ON TABLE ${extraSchema}.grant_probe TO ${role}`,
          `REVOKE SELECT (id) ON TABLE ${extraSchema}.grant_probe FROM ${role}`,
        );
        await expectRejectedStartupMutation(
          `GRANT USAGE ON SEQUENCE ${extraSchema}.sequence_probe TO ${role}`,
          `REVOKE USAGE ON SEQUENCE ${extraSchema}.sequence_probe FROM ${role}`,
        );
        await expectRejectedStartupMutation(
          `GRANT EXECUTE ON FUNCTION ${extraSchema}.function_probe() TO ${role}`,
          `REVOKE EXECUTE ON FUNCTION ${extraSchema}.function_probe() FROM ${role}`,
        );
      }
    } finally {
      await controlPool.query(`DROP SCHEMA ${extraSchema} CASCADE`);
    }
    const expectRejectedOwner = async (routine: string, owner: string, restoreOwner: string) => {
      const quotedOwner = quoteRoleName(owner);
      await controlPool!.query(`GRANT CREATE ON SCHEMA public TO ${quotedOwner}`);
      try {
        await controlPool!.query(`ALTER FUNCTION ${routine} OWNER TO ${quotedOwner}`);
      } finally {
        await controlPool!.query(`REVOKE CREATE ON SCHEMA public FROM ${quotedOwner}`);
      }
      try {
        await expect(buildAppWithPrincipalValidation()).rejects.toThrow(/Database principal verification failed for (runtime|limiter|worker) pool/);
      } finally {
        await Promise.all([pool.query('SELECT 1'), rateLimitPool.query('SELECT 1'), mediaRevocationPool.query('SELECT 1')]);
        await controlPool!.query(`ALTER FUNCTION ${routine} OWNER TO ${quoteRoleName(restoreOwner)}`);
        const allowedRole = routine.includes('nova_auth_bootstrap_identity')
          ? 'nova_fastify_runtime'
          : 'nova_rate_limiter_runtime';
        await controlPool!.query(
          `REVOKE ALL ON FUNCTION ${routine} FROM PUBLIC, anon, authenticated, nova_unrelated_acl_probe,
             nova_fastify_runtime, nova_rate_limiter_runtime, nova_media_revocation_worker`,
        );
        await controlPool!.query(`GRANT EXECUTE ON FUNCTION ${routine} TO ${quoteRoleName(allowedRole)}`);
      }
    };
    const moderationHelpers = [
      { routine: 'public.nova_moderate_hide_story(uuid,text)', owner: 'nova_story_moderation_manager', executors: ['nova_fastify_runtime'] },
      { routine: 'public.nova_moderate_restore_story(uuid,uuid,text)', owner: 'nova_story_moderation_manager', executors: ['nova_fastify_runtime'] },
      { routine: 'public.nova_enqueue_media_key_revocation(uuid,uuid,text,text)', owner: 'nova_revocation_enqueuer_owner', executors: ['nova_fastify_runtime'] },
      { routine: 'public.nova_rls_own_media_revocation_pending(uuid)', owner: 'nova_media_state_predicate_owner', executors: ['nova_fastify_runtime'] },
      { routine: 'public.nova_rls_valid_moderation_action(uuid)', owner: 'nova_action_predicate_owner', executors: ['nova_revocation_enqueuer_owner'] },
      { routine: 'public.nova_rls_actor_active()', owner: 'nova_actor_predicate_owner', executors: [
        'nova_fastify_runtime', 'nova_media_state_predicate_owner', 'nova_revocation_enqueuer_owner',
        'nova_story_moderation_manager', 'nova_story_lifecycle_manager', 'nova_media_lifecycle_manager',
      ] },
      { routine: 'public.nova_rls_actor_has_role(text[])', owner: 'nova_actor_predicate_owner', executors: [
        'nova_fastify_runtime', 'nova_media_state_predicate_owner', 'nova_revocation_enqueuer_owner',
        'nova_story_moderation_manager', 'nova_story_lifecycle_manager', 'nova_media_lifecycle_manager',
      ] },
      { routine: 'public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)', owner: 'nova_media_predicate_owner', executors: [
        'nova_media_revocation_worker', 'nova_reports_predicate_owner', 'nova_media_purge_verifier',
        'nova_media_purge_attester', 'nova_media_removal_authority',
      ] },
    ] as const;
    const moderationOwners = [...new Set(moderationHelpers.map((helper) => helper.owner))];
    const restoreModerationHelper = async (routine: string, owner: string, executors: readonly string[]) => {
      await controlPool!.query(`GRANT CREATE ON SCHEMA public TO ${quoteRoleName(owner)}`);
      try {
        await controlPool!.query(`ALTER FUNCTION ${routine} OWNER TO ${quoteRoleName(owner)}`);
      } finally {
        await controlPool!.query(`REVOKE CREATE ON SCHEMA public FROM ${quoteRoleName(owner)}`);
      }
      const possibleGrantees = [
        'PUBLIC', 'anon', 'authenticated', 'nova_unrelated_acl_probe', 'nova_fastify_runtime',
        'nova_rate_limiter_runtime', 'nova_media_revocation_worker', 'nova_media_state_predicate_owner',
        'nova_revocation_enqueuer_owner', 'nova_story_moderation_manager', 'nova_story_lifecycle_manager',
        'nova_media_lifecycle_manager', 'nova_actor_predicate_owner', 'nova_media_predicate_owner',
        'nova_reports_predicate_owner', 'nova_media_purge_verifier', 'nova_media_purge_attester',
        'nova_media_removal_authority',
      ].filter((grantee) => grantee === 'PUBLIC' || grantee !== owner);
      const sqlGrantees = possibleGrantees.map((grantee) => grantee === 'PUBLIC' ? 'PUBLIC' : quoteRoleName(grantee)).join(', ');
      await controlPool!.query(
        `REVOKE ALL ON FUNCTION ${routine} FROM ${sqlGrantees}`,
      );
      for (const executor of executors.filter((candidate) => candidate !== owner)) {
        await controlPool!.query(`GRANT EXECUTE ON FUNCTION ${routine} TO ${quoteRoleName(executor)}`);
      }
    };
    for (const helper of moderationHelpers) {
      await controlPool!.query('GRANT CREATE ON SCHEMA public TO nova_fastify_runtime');
      try {
        await controlPool!.query(`ALTER FUNCTION ${helper.routine} OWNER TO nova_fastify_runtime`);
      } finally {
        await controlPool!.query('REVOKE CREATE ON SCHEMA public FROM nova_fastify_runtime');
      }
      try {
        await expect(buildAppWithPrincipalValidation()).rejects.toThrow(/Database principal verification failed for runtime pool/);
      } finally {
        await Promise.all([pool.query('SELECT 1'), rateLimitPool.query('SELECT 1'), mediaRevocationPool.query('SELECT 1')]);
        await restoreModerationHelper(helper.routine, helper.owner, helper.executors);
      }

      for (const grantee of ['PUBLIC', 'anon', 'authenticated', 'nova_unrelated_acl_probe']) {
        const sqlGrantee = grantee === 'PUBLIC' ? 'PUBLIC' : quoteRoleName(grantee);
        await expectRejectedStartupMutation(
          `GRANT EXECUTE ON FUNCTION ${helper.routine} TO ${sqlGrantee}`,
          `REVOKE EXECUTE ON FUNCTION ${helper.routine} FROM ${sqlGrantee}`,
        );
      }
      for (const executor of helper.executors.filter((candidate) => candidate !== helper.owner)) {
        await expectRejectedStartupMutation(
          `REVOKE EXECUTE ON FUNCTION ${helper.routine} FROM ${quoteRoleName(executor)}`,
          `GRANT EXECUTE ON FUNCTION ${helper.routine} TO ${quoteRoleName(executor)}`,
        );
      }
      await expectRejectedStartupMutation(
        `ALTER FUNCTION ${helper.routine} SET search_path TO pg_catalog, public`,
        `ALTER FUNCTION ${helper.routine} SET search_path TO pg_catalog`,
      );
    }
    const actionPredicateRoutine = 'public.nova_rls_valid_moderation_action(uuid)';
    const actionPredicateBaseline = await controlPool!.query<{ definition: string }>(
      'SELECT pg_catalog.pg_get_functiondef($1::regprocedure) AS definition', [actionPredicateRoutine],
    );
    const restoreActionPredicateBody = actionPredicateBaseline.rows[0]?.definition;
    if (!restoreActionPredicateBody) throw new Error('Expected action-predicate definition is unavailable');
    await expectRejectedStartupMutation(
      `CREATE OR REPLACE FUNCTION public.nova_rls_valid_moderation_action(p_action_id uuid)
         RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT true $$`,
      `GRANT CREATE ON SCHEMA public TO nova_action_predicate_owner;
       ${restoreActionPredicateBody};
       ALTER FUNCTION ${actionPredicateRoutine} OWNER TO nova_action_predicate_owner;
       REVOKE CREATE ON SCHEMA public FROM nova_action_predicate_owner;
       REVOKE ALL ON FUNCTION ${actionPredicateRoutine} FROM PUBLIC, anon, authenticated, nova_unrelated_acl_probe,
         nova_fastify_runtime, nova_rate_limiter_runtime, nova_media_revocation_worker, nova_reports_worker,
         nova_media_predicate_owner, nova_reports_predicate_owner;
       GRANT EXECUTE ON FUNCTION ${actionPredicateRoutine} TO nova_revocation_enqueuer_owner`,
    );
    for (const owner of moderationOwners) {
      await expectRejectedStartupMutation(`ALTER ROLE ${quoteRoleName(owner)} LOGIN`, `ALTER ROLE ${quoteRoleName(owner)} NOLOGIN`);
      await expectRejectedStartupMutation(`ALTER ROLE ${quoteRoleName(owner)} INHERIT`, `ALTER ROLE ${quoteRoleName(owner)} NOINHERIT`);
      await expectRejectedStartupMutation(`ALTER ROLE ${quoteRoleName(owner)} BYPASSRLS`, `ALTER ROLE ${quoteRoleName(owner)} NOBYPASSRLS`);
      await expectRejectedStartupMutation(`ALTER ROLE ${quoteRoleName(owner)} CREATEROLE`, `ALTER ROLE ${quoteRoleName(owner)} NOCREATEROLE`);
      await expectRejectedStartupMutation(`GRANT CREATE ON SCHEMA public TO ${quoteRoleName(owner)}`, `REVOKE CREATE ON SCHEMA public FROM ${quoteRoleName(owner)}`);
      await expectRejectedStartupMutation(
        `GRANT nova_fastify_runtime TO ${quoteRoleName(owner)} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE`,
        `REVOKE nova_fastify_runtime FROM ${quoteRoleName(owner)}`,
      );
      await expectRejectedStartupMutation(
        `GRANT ${quoteRoleName(owner)} TO nova_fastify_runtime WITH INHERIT FALSE, SET TRUE, ADMIN FALSE`,
        `REVOKE ${quoteRoleName(owner)} FROM nova_fastify_runtime`,
      );
      const protectedTable = owner === 'nova_story_moderation_manager'
        ? 'public.stories'
        : owner === 'nova_revocation_enqueuer_owner' ? 'public.media_assets'
          : owner === 'nova_media_state_predicate_owner' || owner === 'nova_media_predicate_owner'
            ? 'public.media_key_revocations'
            : owner === 'nova_actor_predicate_owner' ? 'public.users' : 'public.stories';
      const restoreColumnGrants = owner === 'nova_story_moderation_manager'
        ? 'GRANT UPDATE (status,visibility,comments_open,published_at,version,updated_at) ON public.stories TO nova_story_moderation_manager'
        : owner === 'nova_revocation_enqueuer_owner'
          ? 'GRANT UPDATE (object_key,updated_at) ON public.media_assets TO nova_revocation_enqueuer_owner'
          : owner === 'nova_media_state_predicate_owner'
            ? 'GRANT SELECT (media_id) ON public.media_key_revocations TO nova_media_state_predicate_owner'
            : owner === 'nova_media_predicate_owner'
              ? 'GRANT SELECT (id,media_id,source_key,moderation_action_id) ON public.media_key_revocations TO nova_media_predicate_owner' : '';
      await expectRejectedStartupMutation(
        `GRANT UPDATE ON ${protectedTable} TO ${quoteRoleName(owner)}`,
        `REVOKE UPDATE ON ${protectedTable} FROM ${quoteRoleName(owner)}; ${restoreColumnGrants}`,
      );
    }
    const wrapperMemberships: Array<[string, string]> = [
      [loginName(process.env.DATABASE_URL!), 'nova_fastify_runtime'],
      [loginName(process.env.RATE_LIMIT_DATABASE_URL!), 'nova_rate_limiter_runtime'],
      [loginName(process.env.MEDIA_REVOCATION_DATABASE_URL!), 'nova_media_revocation_worker'],
    ];
    await controlPool!.query('CREATE ROLE nova_nested_wrapper_probe NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION');
    try {
      for (const [wrapper, principal] of wrapperMemberships) {
        await expectRejectedStartupMutation(
          `GRANT ${quoteRoleName(wrapper)} TO nova_unrelated_acl_probe WITH INHERIT FALSE, SET TRUE, ADMIN FALSE`,
          `REVOKE ${quoteRoleName(wrapper)} FROM nova_unrelated_acl_probe`,
        );
        await expectRejectedStartupMutation(
          `GRANT ${quoteRoleName(wrapper)} TO nova_nested_wrapper_probe WITH INHERIT FALSE, SET TRUE, ADMIN FALSE; GRANT nova_nested_wrapper_probe TO nova_unrelated_acl_probe WITH INHERIT FALSE, SET TRUE, ADMIN FALSE`,
          `REVOKE nova_nested_wrapper_probe FROM nova_unrelated_acl_probe; REVOKE ${quoteRoleName(wrapper)} FROM nova_nested_wrapper_probe`,
        );
      await expectRejectedStartupMutation(
        `GRANT ${quoteRoleName(principal)} TO ${quoteRoleName(wrapper)} WITH INHERIT FALSE, SET TRUE, ADMIN TRUE`,
        `GRANT ${quoteRoleName(principal)} TO ${quoteRoleName(wrapper)} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE`,
      );
      await expectRejectedStartupMutation(
        `GRANT ${quoteRoleName(principal)} TO ${quoteRoleName(wrapper)} WITH INHERIT TRUE, SET TRUE, ADMIN FALSE`,
        `GRANT ${quoteRoleName(principal)} TO ${quoteRoleName(wrapper)} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE`,
      );
      await expectRejectedStartupMutation(
        `GRANT ${quoteRoleName(principal)} TO ${quoteRoleName(wrapper)} WITH INHERIT FALSE, SET FALSE, ADMIN FALSE`,
        `GRANT ${quoteRoleName(principal)} TO ${quoteRoleName(wrapper)} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE`,
      );
      await expectRejectedStartupMutation(
        `GRANT nova_tag_catalog_writer TO ${quoteRoleName(wrapper)} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE`,
        `REVOKE nova_tag_catalog_writer FROM ${quoteRoleName(wrapper)}`,
      );
      await expectRejectedStartupMutation(
        `GRANT nova_tag_catalog_writer TO ${quoteRoleName(principal)} WITH INHERIT FALSE, SET TRUE, ADMIN FALSE`,
        `REVOKE nova_tag_catalog_writer FROM ${quoteRoleName(principal)}`,
      );
      }
    } finally {
      await controlPool!.query('DROP ROLE nova_nested_wrapper_probe');
    }
    for (const role of roleNames) {
      await expectRejectedStartupMutation(
        `GRANT CREATE ON SCHEMA public TO ${quoteRoleName(role)}`,
        `REVOKE CREATE ON SCHEMA public FROM ${quoteRoleName(role)}`,
      );
    }
    const runtimeLogin = loginName(process.env.DATABASE_URL!);
    await expectRejectedStartupMutation(
      `GRANT USAGE ON SCHEMA public TO ${quoteRoleName(runtimeLogin)}`,
      `REVOKE USAGE ON SCHEMA public FROM ${quoteRoleName(runtimeLogin)}`,
    );
    await expectRejectedStartupMutation('GRANT CREATE ON SCHEMA public TO PUBLIC', 'REVOKE CREATE ON SCHEMA public FROM PUBLIC');
    await expectRejectedStartupMutation('GRANT USAGE ON SCHEMA public TO PUBLIC', 'REVOKE USAGE ON SCHEMA public FROM PUBLIC');
    await expectRejectedStartupMutation(
      'REVOKE USAGE ON SCHEMA public FROM nova_fastify_runtime',
      'GRANT USAGE ON SCHEMA public TO nova_fastify_runtime',
    );

    for (const column of ['id', 'media_id', 'source_key', 'moderation_action_id', 'attempt_count', 'retry_after', 'created_at', 'escalated_at']) {
      await expectRejectedStartupMutation(
        `REVOKE SELECT (${column}) ON public.media_key_revocations FROM nova_media_revocation_worker`,
        `GRANT SELECT (${column}) ON public.media_key_revocations TO nova_media_revocation_worker`,
      );
    }
    for (const column of ['attempt_count', 'retry_after', 'escalated_at']) {
      await expectRejectedStartupMutation(
        `REVOKE UPDATE (${column}) ON public.media_key_revocations FROM nova_media_revocation_worker`,
        `GRANT UPDATE (${column}) ON public.media_key_revocations TO nova_media_revocation_worker`,
      );
    }
    await expectRejectedStartupMutation(
      'GRANT UPDATE ON public.media_key_revocations TO nova_media_revocation_worker',
      'REVOKE UPDATE ON public.media_key_revocations FROM nova_media_revocation_worker; GRANT UPDATE (attempt_count,retry_after,escalated_at) ON public.media_key_revocations TO nova_media_revocation_worker',
    );
    for (const column of ['id', 'media_id', 'source_key', 'moderation_action_id', 'created_at']) {
      await expectRejectedStartupMutation(
        `GRANT UPDATE (${column}) ON public.media_key_revocations TO nova_media_revocation_worker`,
        `REVOKE UPDATE (${column}) ON public.media_key_revocations FROM nova_media_revocation_worker`,
      );
    }

    await expectRejectedStartupMutation(
      'GRANT UPDATE ON public.rate_limit_buckets TO nova_media_revocation_worker',
      'REVOKE UPDATE ON public.rate_limit_buckets FROM nova_media_revocation_worker',
    );
    await expectRejectedStartupMutation(
      'GRANT UPDATE (bucket_key) ON public.rate_limit_buckets TO nova_media_revocation_worker',
      'REVOKE UPDATE (bucket_key) ON public.rate_limit_buckets FROM nova_media_revocation_worker',
    );
    const workerUpdateBoundary = await controlPool.query<{
      outOfQueueTableUpdate: boolean; queueTableUpdate: boolean;
      retryMetadataUpdateColumns: number; sensitiveQueueUpdateColumns: number;
    }>(
      `SELECT pg_catalog.has_table_privilege('nova_media_revocation_worker','public.rate_limit_buckets','UPDATE') AS "outOfQueueTableUpdate",
         pg_catalog.has_table_privilege('nova_media_revocation_worker','public.media_key_revocations','UPDATE') AS "queueTableUpdate",
         (SELECT count(*)::int FROM unnest(ARRAY['attempt_count','retry_after','escalated_at']) AS allowed(column_name)
           WHERE pg_catalog.has_column_privilege('nova_media_revocation_worker','public.media_key_revocations',allowed.column_name,'UPDATE')) AS "retryMetadataUpdateColumns",
         (SELECT count(*)::int FROM unnest(ARRAY['id','media_id','source_key','moderation_action_id','created_at']) AS sensitive(column_name)
           WHERE pg_catalog.has_column_privilege('nova_media_revocation_worker','public.media_key_revocations',sensitive.column_name,'UPDATE')) AS "sensitiveQueueUpdateColumns"`,
    );
    expect(workerUpdateBoundary.rows[0]).toEqual({
      outOfQueueTableUpdate: false, queueTableUpdate: false,
      retryMetadataUpdateColumns: 3, sensitiveQueueUpdateColumns: 0,
    });
    console.log('SAFE_WORKER_UPDATE_BOUNDARY', JSON.stringify({
      outOfQueueTableGrantRejected: true, outOfQueueColumnGrantRejected: true,
      ...workerUpdateBoundary.rows[0],
    }));

    await expectRejectedStartupMutation(
      'ALTER FUNCTION public.nova_auth_bootstrap_identity(text) SECURITY INVOKER',
      'ALTER FUNCTION public.nova_auth_bootstrap_identity(text) SECURITY DEFINER',
    );
    await expectRejectedStartupMutation(
      'ALTER FUNCTION public.nova_auth_bootstrap_identity(text) SET search_path TO pg_catalog, public',
      'ALTER FUNCTION public.nova_auth_bootstrap_identity(text) SET search_path TO pg_catalog',
    );
    await expectRejectedStartupMutation('ALTER ROLE nova_auth_identity_owner LOGIN', 'ALTER ROLE nova_auth_identity_owner NOLOGIN');
    await expectRejectedStartupMutation('ALTER ROLE nova_auth_identity_owner INHERIT', 'ALTER ROLE nova_auth_identity_owner NOINHERIT');
    await expectRejectedStartupMutation('ALTER ROLE nova_rate_limit_counter_owner LOGIN', 'ALTER ROLE nova_rate_limit_counter_owner NOLOGIN');
    await expectRejectedStartupMutation('ALTER ROLE nova_rate_limit_counter_owner INHERIT', 'ALTER ROLE nova_rate_limit_counter_owner NOINHERIT');
    await expectRejectedStartupMutation(
      'GRANT EXECUTE ON FUNCTION public.nova_auth_bootstrap_identity(text) TO PUBLIC',
      'REVOKE EXECUTE ON FUNCTION public.nova_auth_bootstrap_identity(text) FROM PUBLIC',
    );
    await expectRejectedStartupMutation(
      'GRANT EXECUTE ON FUNCTION public.nova_rate_limit_record(text,timestamptz) TO PUBLIC',
      'REVOKE EXECUTE ON FUNCTION public.nova_rate_limit_record(text,timestamptz) FROM PUBLIC',
    );
    for (const role of ['anon', 'authenticated', 'nova_unrelated_acl_probe']) {
      for (const [routine, signature] of [
        ['public.nova_auth_bootstrap_identity(text)', 'public.nova_auth_bootstrap_identity(text)'],
        ['public.nova_rate_limit_record(text,timestamptz)', 'public.nova_rate_limit_record(text,timestamptz)'],
      ] as const) {
        await expectRejectedStartupMutation(
          `GRANT EXECUTE ON FUNCTION ${routine} TO ${quoteRoleName(role)}`,
          `REVOKE EXECUTE ON FUNCTION ${signature} FROM ${quoteRoleName(role)}`,
        );
      }
    }
    for (const target of [
      'nova_fastify_runtime', runtimeLogin, 'nova_rate_limiter_runtime', 'nova_media_revocation_worker',
    ]) {
      await expectRejectedOwner('public.nova_auth_bootstrap_identity(text)', target, 'nova_auth_identity_owner');
    }
    for (const target of [
      'nova_rate_limiter_runtime', loginName(process.env.RATE_LIMIT_DATABASE_URL!),
      'nova_fastify_runtime', 'nova_media_revocation_worker',
    ]) {
      await expectRejectedOwner('public.nova_rate_limit_record(text,timestamptz)', target, 'nova_rate_limit_counter_owner');
    }
    await expectRejectedStartupMutation(
      'GRANT nova_fastify_runtime TO nova_auth_identity_owner',
      'REVOKE nova_fastify_runtime FROM nova_auth_identity_owner',
    );
    await expectRejectedStartupMutation(
      'GRANT nova_auth_identity_owner TO nova_fastify_runtime',
      'REVOKE nova_auth_identity_owner FROM nova_fastify_runtime',
    );
    await expectRejectedStartupMutation(
      'GRANT nova_rate_limiter_runtime TO nova_rate_limit_counter_owner',
      'REVOKE nova_rate_limiter_runtime FROM nova_rate_limit_counter_owner',
    );
    await expectRejectedStartupMutation(
      'GRANT nova_rate_limit_counter_owner TO nova_rate_limiter_runtime',
      'REVOKE nova_rate_limit_counter_owner FROM nova_rate_limiter_runtime',
    );
    const workerUpdateSurface = await mediaRevocationPool.query<{
      attemptCount: boolean; retryAfter: boolean; escalatedAt: boolean; tableUpdate: boolean; sensitiveUpdate: boolean;
    }>(
      `SELECT has_column_privilege(current_user,'public.media_key_revocations','attempt_count','UPDATE') AS "attemptCount",
         has_column_privilege(current_user,'public.media_key_revocations','retry_after','UPDATE') AS "retryAfter",
         has_column_privilege(current_user,'public.media_key_revocations','escalated_at','UPDATE') AS "escalatedAt",
         has_table_privilege(current_user,'public.media_key_revocations','UPDATE') AS "tableUpdate",
         (has_column_privilege(current_user,'public.media_key_revocations','id','UPDATE')
           OR has_column_privilege(current_user,'public.media_key_revocations','source_key','UPDATE')
           OR has_column_privilege(current_user,'public.media_key_revocations','media_id','UPDATE')
           OR has_column_privilege(current_user,'public.media_key_revocations','moderation_action_id','UPDATE')
           OR has_column_privilege(current_user,'public.media_key_revocations','created_at','UPDATE')) AS "sensitiveUpdate"`,
    );
    expect(workerUpdateSurface.rows[0]).toEqual({
      attemptCount: true, retryAfter: true, escalatedAt: true, tableUpdate: false, sensitiveUpdate: false,
    });
    const restoredApp = await buildAppWithPrincipalValidation();
    await restoredApp.close();
  }, 60_000);

  it('rejects exact SECURITY DEFINER body drift and restores the known-good helper fingerprints', async () => {
    if (!controlPool) throw new Error('RLS control connection is not initialized');
    const baseline = await buildAppWithPrincipalValidation();
    await baseline.close();
    const signatures = [
      'public.nova_auth_bootstrap_identity(text)',
      'public.nova_rate_limit_record(text,timestamptz)',
      'public.nova_moderate_hide_story(uuid,text)',
      'public.nova_moderate_restore_story(uuid,uuid,text)',
      'public.nova_enqueue_media_key_revocation(uuid,uuid,text,text)',
      'public.nova_rls_own_media_revocation_pending(uuid)',
      'public.nova_rls_valid_moderation_action(uuid)',
      'public.nova_rls_actor_active()',
      'public.nova_rls_actor_has_role(text[])',
      'public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)',
    ];
    for (const signature of signatures) {
      const source = await controlPool.query<{ definition: string; fingerprint: string }>(
        `SELECT pg_catalog.pg_get_functiondef(helper.oid) AS definition,
           pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(helper.prosrc,'UTF8')),'hex') AS fingerprint
         FROM pg_catalog.pg_proc helper WHERE helper.oid=$1::regprocedure`, [signature],
      );
      const originalDefinition = source.rows[0]?.definition;
      const knownGoodFingerprint = source.rows[0]?.fingerprint;
      if (!originalDefinition || !knownGoodFingerprint) throw new Error('Expected helper body fingerprint is unavailable');
      const delimiterMatch = /AS (\$[A-Za-z0-9_]*\$)/.exec(originalDefinition);
      if (!delimiterMatch || delimiterMatch.index === undefined) throw new Error('Could not locate helper body delimiter');
      const delimiter = delimiterMatch[1]!;
      const bodyEnd = originalDefinition.lastIndexOf(delimiter);
      const bodyStart = delimiterMatch.index + delimiterMatch[0].length;
      if (bodyEnd < bodyStart) throw new Error('Could not locate helper body end');
      const driftedDefinition = `${originalDefinition.slice(0, bodyEnd)}\n-- startup body-fingerprint drift probe\n${originalDefinition.slice(bodyEnd)}`;
      await controlPool.query(driftedDefinition);
      try {
        await expect(buildAppWithPrincipalValidation()).rejects.toThrow(
          /Database principal verification failed for (runtime|limiter|worker) pool/,
        );
      } finally {
        await controlPool.query(originalDefinition);
      }
      const restored = await controlPool.query<{ fingerprint: string }>(
        `SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(helper.prosrc,'UTF8')),'hex') AS fingerprint
         FROM pg_catalog.pg_proc helper WHERE helper.oid=$1::regprocedure`, [signature],
      );
      expect(restored.rows[0]?.fingerprint).toBe(knownGoodFingerprint);
    }
    console.log('SAFE_HELPER_BODY_DRIFT_REJECTION', JSON.stringify({ helpersTested: signatures.length, mutationsRejected: true, knownGoodFingerprintsRestored: true }));
    const helperMetadata = [
      { signature: 'public.nova_auth_bootstrap_identity(text)', language: 'plpgsql', volatility: 'v' },
      { signature: 'public.nova_rate_limit_record(text,timestamptz)', language: 'plpgsql', volatility: 'v' },
      { signature: 'public.nova_moderate_hide_story(uuid,text)', language: 'plpgsql', volatility: 'v' },
      { signature: 'public.nova_moderate_restore_story(uuid,uuid,text)', language: 'plpgsql', volatility: 'v' },
      { signature: 'public.nova_enqueue_media_key_revocation(uuid,uuid,text,text)', language: 'plpgsql', volatility: 'v' },
      { signature: 'public.nova_rls_own_media_revocation_pending(uuid)', language: 'sql', volatility: 's' },
      { signature: 'public.nova_rls_valid_moderation_action(uuid)', language: 'plpgsql', volatility: 'v' },
      { signature: 'public.nova_rls_actor_active()', language: 'sql', volatility: 's' },
      { signature: 'public.nova_rls_actor_has_role(text[])', language: 'sql', volatility: 's' },
      { signature: 'public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)', language: 'plpgsql', volatility: 'v' },
    ] as const;
    for (const helper of helperMetadata) {
      const changedVolatility = helper.volatility === 'v' ? 'STABLE' : 'VOLATILE';
      const restoredVolatility = helper.volatility === 'v' ? 'VOLATILE' : 'STABLE';
      await controlPool.query(`ALTER FUNCTION ${helper.signature} ${changedVolatility}`);
      try {
        await expect(buildAppWithPrincipalValidation()).rejects.toThrow(
          /Database principal verification failed for (runtime|limiter|worker) pool/,
        );
      } finally {
        await Promise.all([pool.query('SELECT 1'), rateLimitPool.query('SELECT 1'), mediaRevocationPool.query('SELECT 1')]);
        await controlPool.query(`ALTER FUNCTION ${helper.signature} ${restoredVolatility}`);
      }
      const restoredMetadata = await controlPool.query<{ language: string; volatility: string }>(
        `SELECT helper_language.lanname AS language, helper.provolatile::text AS volatility
         FROM pg_catalog.pg_proc helper
         JOIN pg_catalog.pg_language helper_language ON helper_language.oid=helper.prolang
         WHERE helper.oid=$1::regprocedure`, [helper.signature],
      );
      expect(restoredMetadata.rows[0]).toEqual({ language: helper.language, volatility: helper.volatility });
    }

    const rejectLanguageDrift = async (
      signature: string,
      alternateLanguage: string,
      expectedVolatility: string,
      replacement: string,
    ) => {
      const source = await controlPool!.query<{ definition: string }>(
        'SELECT pg_catalog.pg_get_functiondef($1::regprocedure) AS definition', [signature],
      );
      const originalDefinition = source.rows[0]?.definition;
      if (!originalDefinition) throw new Error(`Expected helper definition is unavailable for ${signature}`);
      await controlPool!.query(replacement);
      try {
        const changedMetadata = await controlPool!.query<{ language: string; volatility: string }>(
          `SELECT helper_language.lanname AS language, helper.provolatile::text AS volatility
           FROM pg_catalog.pg_proc helper
           JOIN pg_catalog.pg_language helper_language ON helper_language.oid=helper.prolang
           WHERE helper.oid=$1::regprocedure`, [signature],
        );
        expect(changedMetadata.rows[0]).toEqual({ language: alternateLanguage, volatility: expectedVolatility });
        await expect(buildAppWithPrincipalValidation()).rejects.toThrow(
          /Database principal verification failed for (runtime|limiter|worker) pool/,
        );
      } finally {
        await Promise.all([pool.query('SELECT 1'), rateLimitPool.query('SELECT 1'), mediaRevocationPool.query('SELECT 1')]);
        await controlPool!.query(originalDefinition);
      }
    };
    await rejectLanguageDrift(
      'public.nova_auth_bootstrap_identity(text)', 'sql', 'v',
      `CREATE OR REPLACE FUNCTION public.nova_auth_bootstrap_identity(p_generated_username text)
       RETURNS TABLE(id uuid, subject text, username text, role text, status text)
       LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog
       AS $language_probe$ SELECT NULL::uuid,NULL::text,NULL::text,NULL::text,NULL::text WHERE false $language_probe$`,
    );
    await rejectLanguageDrift(
      'public.nova_rls_actor_active()', 'plpgsql', 's',
      `CREATE OR REPLACE FUNCTION public.nova_rls_actor_active()
       RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog
       AS $language_probe$ BEGIN RETURN false; END $language_probe$`,
    );
    const restored = await buildAppWithPrincipalValidation();
    await restored.close();
    console.log('SAFE_HELPER_METADATA_DRIFT_REJECTION', JSON.stringify({
      helpersPinned: helperMetadata.length,
      volatilityMutationsRejected: helperMetadata.length,
      plpgsqlToSqlLanguageDriftRejected: true,
      sqlToPlpgsqlLanguageDriftRejected: true,
      knownGoodMetadataRestored: true,
    }));
  }, 60_000);

  it('rejects media-revocation worker policy scope drift at startup', async () => {
    if (!controlPool) throw new Error('RLS control connection is not initialized');
    const baseline = await buildAppWithPrincipalValidation();
    await baseline.close();
    const expectRejectedPolicyMutation = async (statement: string, restore: string) => {
      await controlPool!.query(statement);
      try {
        await expect(buildAppWithPrincipalValidation()).rejects.toThrow(
          /Database principal verification failed for worker pool/,
        );
      } finally {
        await Promise.all([pool.query('SELECT 1'), rateLimitPool.query('SELECT 1'), mediaRevocationPool.query('SELECT 1')]);
        await controlPool!.query(restore);
      }
    };
    await expectRejectedPolicyMutation(
      'ALTER POLICY media_revocations_worker_read ON public.media_key_revocations USING (true)',
      `ALTER POLICY media_revocations_worker_read ON public.media_key_revocations USING (
        current_user='nova_media_revocation_worker' AND attempt_count BETWEEN 0 AND 5
        AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id))`,
    );
    await expectRejectedPolicyMutation(
      'ALTER POLICY media_revocations_worker_update ON public.media_key_revocations USING (true) WITH CHECK (true)',
      `ALTER POLICY media_revocations_worker_update ON public.media_key_revocations
        USING (current_user='nova_media_revocation_worker' AND retry_after<=pg_catalog.statement_timestamp()
          AND attempt_count<5 AND escalated_at IS NULL
          AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id))
        WITH CHECK (current_user='nova_media_revocation_worker' AND attempt_count BETWEEN 1 AND 5
          AND ((attempt_count<5 AND escalated_at IS NULL) OR (attempt_count=5 AND escalated_at IS NOT NULL))
          AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id))`,
    );
    await expectRejectedPolicyMutation(
      'ALTER POLICY media_revocations_worker_read ON public.media_key_revocations TO PUBLIC',
      'ALTER POLICY media_revocations_worker_read ON public.media_key_revocations TO nova_media_revocation_worker',
    );
    await expectRejectedPolicyMutation(
      `CREATE POLICY media_revocations_worker_broad_probe ON public.media_key_revocations
         FOR SELECT TO nova_media_revocation_worker USING (true)`,
      'DROP POLICY media_revocations_worker_broad_probe ON public.media_key_revocations',
    );
    const restored = await buildAppWithPrincipalValidation();
    await restored.close();
    console.log('SAFE_WORKER_POLICY_SCOPE_DRIFT_REJECTION', JSON.stringify({
      readPredicateBroadeningRejected: true,
      updateUsingAndCheckBroadeningRejected: true,
      roleBroadeningRejected: true,
      extraApplicablePolicyRejected: true,
      knownGoodPolicyScopeRestored: true,
    }));
  });

  it('fails closed on a missing public runtime contract even when a private fixture decoy exists', async () => {
    if (!controlPool) throw new Error('RLS control connection is not initialized');
    const decoy = await controlPool.query<{ present: boolean }>(
      "SELECT pg_catalog.to_regclass('nova_security_fixture.media_no_media_required') IS NOT NULL AS present",
    );
    expect(decoy.rows[0]?.present).toBe(true);
    await controlPool.query('ALTER TABLE public.media_no_media_required RENAME TO media_no_media_contract_probe_missing');
    try {
      await expect(buildAppWithPrincipalValidation()).rejects.toThrow(
        /Missing runtime database contract: .*public\.media_no_media_required/,
      );
    } finally {
      await controlPool.query('ALTER TABLE public.media_no_media_contract_probe_missing RENAME TO media_no_media_required');
    }
    await controlPool.query('ALTER FUNCTION public.nova_rls_valid_moderation_action(uuid) RENAME TO nova_rls_valid_moderation_action_contract_probe_missing');
    try {
      await expect(buildAppWithPrincipalValidation()).rejects.toThrow(
        /Missing runtime database contract: .*public\.nova_rls_valid_moderation_action\(uuid\)/,
      );
    } finally {
      await controlPool.query('ALTER FUNCTION public.nova_rls_valid_moderation_action_contract_probe_missing(uuid) RENAME TO nova_rls_valid_moderation_action');
    }
    const baseline = await buildAppWithPrincipalValidation();
    await baseline.close();
  });

  it('executes identity bootstrap only through its runtime wrapper and blocks forged-GUC helper calls from other roles', async () => {
    const subject = `${prefix}:identity-helper-contract`;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SELECT set_config('app.auth_subject',$1,true)", [subject]);
      const first = await client.query<{ id: string; subject: string; username: string; role: string; status: string }>(
        'SELECT id,subject,username,role,status FROM public.nova_auth_bootstrap_identity($1)',
        ['reader_0123456789abcdef0123'],
      );
      const second = await client.query<{ id: string; subject: string; username: string; role: string; status: string }>(
        'SELECT id,subject,username,role,status FROM public.nova_auth_bootstrap_identity($1)',
        ['reader_fedcba9876543210abcd'],
      );
      expect(first.rows[0]).toMatchObject({ subject, username: 'reader_0123456789abcdef0123', role: 'reader', status: 'active' });
      expect(second.rows[0]).toEqual(first.rows[0]);
    } finally {
      await client.query('ROLLBACK').catch(() => undefined);
      client.release();
    }

    if (!controlPool) throw new Error('RLS control connection is not initialized');
    for (const probeRole of ['anon', 'authenticated']) {
      const probe = quoteRoleName(probeRole);
      await controlPool.query(`GRANT USAGE ON SCHEMA public TO ${probe}`);
      await controlPool.query(`GRANT EXECUTE ON FUNCTION public.nova_auth_bootstrap_identity(text) TO ${probe}`);
      await controlPool.query(`GRANT EXECUTE ON FUNCTION public.nova_rate_limit_record(text,timestamptz) TO ${probe}`);
      try {
        for (const [sql, parameters] of [
          [
            'SELECT id,subject,username,role,status FROM public.nova_auth_bootstrap_identity($1)',
            ['reader_aaaaaaaaaaaaaaaaaaaa'],
          ],
          [
            'SELECT public.nova_rate_limit_record($1,statement_timestamp())',
            ['a'.repeat(64)],
          ],
        ] as const) {
          const probeClient = await controlPool.connect();
          try {
            await probeClient.query('BEGIN');
            await probeClient.query(`SET LOCAL ROLE ${probe}`);
            await probeClient.query("SELECT set_config('app.auth_subject',$1,true)", ['nova-rls-e2e:moderator']);
            await expect(probeClient.query(sql, [...parameters])).rejects.toMatchObject({ code: '42501' });
          } finally {
            await probeClient.query('ROLLBACK').catch(() => undefined);
            probeClient.release();
          }
        }
      } finally {
        await controlPool.query(`REVOKE EXECUTE ON FUNCTION public.nova_auth_bootstrap_identity(text) FROM ${probe}`);
        await controlPool.query(`REVOKE EXECUTE ON FUNCTION public.nova_rate_limit_record(text,timestamptz) FROM ${probe}`);
        await controlPool.query(`REVOKE USAGE ON SCHEMA public FROM ${probe}`);
      }
      const acl = await controlPool.query<{ auth_allowed: boolean; limiter_allowed: boolean }>(
        `SELECT pg_catalog.has_function_privilege($1::name,'public.nova_auth_bootstrap_identity(text)','EXECUTE') AS auth_allowed,
                pg_catalog.has_function_privilege($1::name,'public.nova_rate_limit_record(text,timestamptz)','EXECUTE') AS limiter_allowed`,
        [probeRole],
      );
      expect(acl.rows[0]).toEqual({ auth_allowed: false, limiter_allowed: false });
    }

    await expect(pool.query('SELECT auth_subject FROM public.users LIMIT 1')).rejects.toMatchObject({ code: '42501' });
    await expect(pool.query(
      `INSERT INTO public.users(auth_subject,username,username_normalized)
       VALUES($1,'reader_direct_insert','reader_direct_insert')`, [`${prefix}:direct-insert-denied`],
    )).rejects.toMatchObject({ code: '42501' });
  });

  it('fails startup and returns only a neutral 503 when identity bootstrap is missing', async () => {
    if (!controlPool) throw new Error('RLS control connection is not initialized');
    await controlPool.query('ALTER FUNCTION public.nova_auth_bootstrap_identity(text) RENAME TO nova_auth_bootstrap_identity_temporarily_missing');
    try {
      await expect(buildAppWithPrincipalValidation()).rejects.toThrow(/Database principal verification failed for (runtime|limiter|worker) pool/);
      const token = await tokenFor(`${prefix}:identity-helper-missing`);
      const response = await request('GET', '/api/v1/me', token);
      expect(response.statusCode).toBe(503);
      const payload = response.json();
      expect(payload.error).toMatchObject({
        code: 'IDENTITY_UNAVAILABLE',
        message: 'Layanan identitas sementara tidak tersedia.',
        retryable: false,
      });
      expect(payload.data).toBeUndefined();
      expect(JSON.stringify(payload)).not.toMatch(/nova_auth_bootstrap_identity|42883|42501|permission denied|INSERT INTO users/i);
      expect(response.headers?.['retry-after']).toBeUndefined();
    } finally {
      await controlPool.query('ALTER FUNCTION public.nova_auth_bootstrap_identity_temporarily_missing(text) RENAME TO nova_auth_bootstrap_identity');
    }
  });

  it('provisions first-login identity through GET /me and maps bootstrap timeout to neutral 503 without partial user', async () => {
    if (!controlPool) throw new Error('RLS control connection is not initialized');
    const anon = await request('GET', '/api/v1/me');
    expect(anon.statusCode).toBe(401);
    const pid = await expectContextClearedAndPoolReused();

    const ownerSubject = subjects[0]!;
    const ownerBefore = await controlPool.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM public.users WHERE auth_subject=$1', [ownerSubject],
    );
    expect(ownerBefore.rows[0]?.count).toBe('0');
    const ownerToken = await tokenFor(subjects[0]!, { role: 'admin', user_id: 'forged-user-id' });
    const ownerResponse = await request('GET', '/api/v1/me', ownerToken);
    expect(ownerResponse.statusCode).toBe(200);
    const owner = ownerResponse.json().data;
    expect(owner.role).toBe('reader');
    expect(owner.id).toMatch(/^[0-9a-f-]{36}$/i);
    expect(owner.id).not.toBe('forged-user-id');
    const provisionedOwner = await controlPool.query<{ id: string; username: string; role: string; status: string }>(
      `SELECT id::text AS id, username, role::text AS role, status::text AS status
       FROM public.users WHERE auth_subject=$1`, [ownerSubject],
    );
    expect(provisionedOwner.rows).toHaveLength(1);
    expect(provisionedOwner.rows[0]).toMatchObject({ id: owner.id, role: 'reader', status: 'active' });
    expect(provisionedOwner.rows[0]?.username).toMatch(/^reader_[a-f0-9]{20}$/);
    actors.set('owner', { subject: subjects[0]!, token: ownerToken, id: owner.id as string });
    await expectContextClearedAndPoolReused(pid);

    const otherBefore = await controlPool.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM public.users WHERE auth_subject=$1', [subjects[1]],
    );
    expect(otherBefore.rows[0]?.count).toBe('0');
    const otherToken = await tokenFor(subjects[1]!, { role: 'moderator' });
    const otherResponse = await request('GET', '/api/v1/me', otherToken);
    expect(otherResponse.statusCode).toBe(200);
    const other = otherResponse.json().data;
    expect(other.role).toBe('reader');
    expect(other.id).not.toBe(owner.id);
    const provisionedOther = await controlPool.query<{ id: string; role: string; status: string }>(
      `SELECT id::text AS id, role::text AS role, status::text AS status
       FROM public.users WHERE auth_subject=$1`, [subjects[1]],
    );
    expect(provisionedOther.rows).toEqual([{ id: other.id, role: 'reader', status: 'active' }]);
    actors.set('other', { subject: subjects[1]!, token: otherToken, id: other.id as string });
    await expectContextClearedAndPoolReused(pid);

    const timeoutSubject = `${prefix}:identity-statement-timeout`;
    const timeoutSubjectBefore = await controlPool.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM public.users WHERE auth_subject=$1', [timeoutSubject],
    );
    expect(timeoutSubjectBefore.rows[0]?.count).toBe('0');
    const helperSource = await controlPool.query<{ definition: string }>(
      `SELECT pg_catalog.pg_get_functiondef('public.nova_auth_bootstrap_identity(text)'::regprocedure) AS definition`,
    );
    const originalHelperDefinition = helperSource.rows[0]?.definition;
    if (!originalHelperDefinition) throw new Error('Identity bootstrap helper definition is unavailable');
    const bodyDelimiter = /AS (\$[A-Za-z0-9_]*\$)/.exec(originalHelperDefinition);
    if (!bodyDelimiter || bodyDelimiter.index === undefined) throw new Error('Identity bootstrap body delimiter is unavailable');
    const bodyStart = bodyDelimiter.index + bodyDelimiter[0].length;
    const beginToken = '\nBEGIN\n';
    const beginAt = originalHelperDefinition.indexOf(beginToken, bodyStart);
    if (beginAt < 0) throw new Error('Identity bootstrap PL/pgSQL BEGIN block is unavailable');
    const beginEnd = beginAt + beginToken.length;
    const delayedHelperDefinition = `${originalHelperDefinition.slice(0, beginEnd)}  PERFORM pg_catalog.pg_sleep(0.250);\n${originalHelperDefinition.slice(beginEnd)}`;
    try {
      await controlPool.query(delayedHelperDefinition);
      await pool.query("SELECT pg_catalog.set_config('statement_timeout','25ms',false)");
      const timeoutConfiguration = await pool.query<{ statementTimeout: string }>(
        `SELECT pg_catalog.current_setting('statement_timeout') AS "statementTimeout"`,
      );
      expect(timeoutConfiguration.rows[0]?.statementTimeout).toBe('25ms');
      const timeoutToken = await tokenFor(timeoutSubject);
      const timeoutResponse = await request('GET', '/api/v1/me', timeoutToken);
      expect(timeoutResponse.statusCode).toBe(503);
      expect(timeoutResponse.json().error).toMatchObject({
        code: 'IDENTITY_UNAVAILABLE',
        message: 'Layanan identitas sementara tidak tersedia.',
      });
      expect(JSON.stringify(timeoutResponse.json())).not.toMatch(/57014|statement_timeout|pg_sleep|nova_auth_bootstrap_identity|permission denied/i);
      const timeoutSubjectAfter = await controlPool.query<{ count: string }>(
        'SELECT count(*)::text AS count FROM public.users WHERE auth_subject=$1', [timeoutSubject],
      );
      expect(timeoutSubjectAfter.rows[0]?.count).toBe('0');
    } finally {
      await pool.query("SELECT pg_catalog.set_config('statement_timeout','15s',false)").catch(() => undefined);
      await controlPool.query(originalHelperDefinition);
      await controlPool.query('DELETE FROM public.users WHERE auth_subject=$1', [timeoutSubject]);
    }
    await expectContextClearedAndPoolReused(pid);
    console.log('SAFE_ME_FIRST_LOGIN_AND_TIMEOUT', JSON.stringify({
      successfulFirstLoginProvisioned: true,
      bootstrapStatementTimeoutMappedToNeutral503: true,
      partialUserAbsentAfterTimeout: true,
      requestContextCleared: true,
    }));

    const directInsert = await pool.connect();
    let deniedCode: string | undefined;
    try {
      await directInsert.query('BEGIN');
      await directInsert.query(
        `INSERT INTO rate_limit_buckets(bucket_key,window_start,hits) VALUES(repeat('a',64),now(),1)`,
      );
    } catch (error) {
      deniedCode = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : undefined;
    } finally {
      await directInsert.query('ROLLBACK').catch(() => undefined);
      directInsert.release();
    }
    expect(deniedCode).toBe('42501');

    const createStory = await request('POST', '/api/v1/stories', ownerToken, {
      title: 'Private owner-only draft', summary: 'RLS E2E', body: 'This draft belongs only to the verified owner.',
    });
    expect(createStory.statusCode).toBe(201);
    const storyId = createStory.json().data.id as string;
    await expectContextClearedAndPoolReused(pid);

    const crossUserRead = await request('GET', `/api/v1/stories/${storyId}`, otherToken);
    expect(crossUserRead.statusCode).toBe(404);
    await expectContextClearedAndPoolReused(pid);

    const ownerRead = await request('GET', `/api/v1/stories/${storyId}`, ownerToken);
    expect(ownerRead.statusCode).toBe(200);
    expect(ownerRead.json().data.authorId).toBe(owner.id);
    await expectContextClearedAndPoolReused(pid);

    const profilePatch = await request('PATCH', '/api/v1/me', ownerToken, { bio: 'transaction scoped' });
    expect(profilePatch.statusCode).toBe(200);
    expect(profilePatch.json().data.bio).toBe('transaction scoped');
    expect(profilePatch.json().data.role).toBe('reader');
    await expectContextClearedAndPoolReused(pid);

    const startMs = Math.floor(Date.now() / 60_000) * 60_000;
    const bucketA = 'a'.repeat(64);
    const bucketB = 'b'.repeat(64);
    const first = await rateLimitPool.query<{ hits: number }>(
      'SELECT public.nova_rate_limit_record($1,to_timestamp($2/1000.0)) AS hits', [bucketA, startMs],
    );
    expect(first.rows[0]?.hits).toBe(1);
    const second = await rateLimitPool.query<{ hits: number }>(
      'SELECT public.nova_rate_limit_record($1,to_timestamp($2/1000.0)) AS hits', [bucketB, startMs],
    );
    expect(second.rows[0]?.hits).toBe(1);
    let directBucketSqlstate: string | undefined;
    try {
      await rateLimitPool.query('SELECT hits FROM public.rate_limit_buckets WHERE bucket_key=$1', [bucketB]);
    } catch (error) {
      directBucketSqlstate = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : undefined;
    }
    expect(directBucketSqlstate).toBe('42501');
  }, 30_000);
});
