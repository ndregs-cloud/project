import { createServer, type Server } from 'node:http';
import { createHmac, randomBytes } from 'node:crypto';
import { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { Pool } from 'pg';
import type { MediaStorage } from '../src/storage/s3.js';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { closePool, mediaRevocationPool, pool, rateLimitPool } from '../src/db.js';
import { processPendingMediaKeyRevocations } from '../src/media-key-revocations.js';

const enabled = process.env.RUN_MODERATION_OUTBOX_E2E === '1';
type Response = { statusCode: number; json: () => any; headers: Record<string, string | number | string[] | undefined> };
const MODERATOR_SUBJECT = 'nova-rls-e2e:moderator';
const MODERATOR_ID = 'e1000000-0000-4000-8000-000000000001';
const OWNER_ID = 'e1000000-0000-4000-8000-000000000002';
const STORY_ID = 'e3000000-0000-4000-8000-000000000001';
const RESTORE_STORY_ID = 'e3000000-0000-4000-8000-000000000002';
const PUBLISH_STORY_ID = 'e3000000-0000-4000-8000-000000000003';
const MEDIA_ID = 'e2000000-0000-4000-8000-000000000001';
const COMMENT_ID = 'e5000000-0000-4000-8000-000000000001';
const REPORT_ID = 'e6000000-0000-4000-8000-000000000001';
const RESTORE_REPORT_ID = 'e6000000-0000-4000-8000-000000000002';
const ACK_LOSS_STORY_ID = 'e3000000-0000-4000-8000-000000000004';
const ACK_LOSS_MEDIA_ID = 'e2000000-0000-4000-8000-000000000002';
const ACK_LOSS_REPORT_ID = 'e6000000-0000-4000-8000-000000000003';
const ACK_UNKNOWN_STORY_ID = 'e3000000-0000-4000-8000-000000000005';
const ACK_UNKNOWN_MEDIA_ID = 'e2000000-0000-4000-8000-000000000003';
const ACK_UNKNOWN_REPORT_ID = 'e6000000-0000-4000-8000-000000000004';

function requireDisposableUrl(url: string | undefined, name: string): string {
  if (!url) throw new Error(`${name} is required for RUN_MODERATION_OUTBOX_E2E=1`);
  const parsed = new URL(url);
  if (!['127.0.0.1', 'localhost', '::1'].includes(parsed.hostname)) {
    throw new Error(`${name} must point to a loopback-only PostgreSQL 17 disposable database`);
  }
  const database = decodeURIComponent(parsed.pathname.replace(/^\//, ''));
  if (!database.startsWith('nova_rls_e2e_moderation_')) {
    throw new Error(`${name} must name a disposable database beginning with nova_rls_e2e_moderation_`);
  }
  return database;
}

async function within<T>(promise: Promise<T>, timeoutMs: number, description: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${description} exceeded ${timeoutMs}ms`)), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function loginName(url: string): string {
  return decodeURIComponent(new URL(url).username);
}

async function withLostCommitAcknowledgement<T>(operation: () => Promise<T>, failFreshWorkerRead = false): Promise<T> {
  const runtimePool = pool as unknown as { connect: () => Promise<{ query: (...args: unknown[]) => Promise<unknown> }> };
  const originalConnect = runtimePool.connect.bind(pool);
  const workerPool = mediaRevocationPool as unknown as { query: (...args: unknown[]) => Promise<unknown> };
  const originalWorkerQuery = workerPool.query.bind(mediaRevocationPool);
  runtimePool.connect = async () => {
    const client = await originalConnect();
    const mutableClient = client as unknown as { query: (...args: unknown[]) => Promise<unknown> };
    const originalQuery = mutableClient.query.bind(client);
    let interceptCommit = true;
    mutableClient.query = async (...args: unknown[]) => {
      const first = args[0];
      const sql = typeof first === 'string' ? first
        : typeof first === 'object' && first !== null && 'text' in first && typeof first.text === 'string' ? first.text
          : '';
      const result = await originalQuery(...args);
      if (interceptCommit && sql.trim().toUpperCase() === 'COMMIT') {
        interceptCommit = false;
        throw Object.assign(new Error('Synthetic COMMIT acknowledgement loss.'), { code: 'ECONNRESET' });
      }
      return result;
    };
    return client;
  };
  if (failFreshWorkerRead) {
    workerPool.query = async (...args: unknown[]) => {
      const first = args[0];
      const sql = typeof first === 'string' ? first
        : typeof first === 'object' && first !== null && 'text' in first && typeof first.text === 'string' ? first.text
          : '';
      if (sql.replace(/\s+/g, ' ').trim() === 'SELECT id,media_id,moderation_action_id FROM public.media_key_revocations WHERE id=$1') {
        throw Object.assign(new Error('Synthetic fresh-state read failure.'), { code: 'ECONNRESET' });
      }
      return originalWorkerQuery(...args);
    };
  }
  try {
    return await operation();
  } finally {
    runtimePool.connect = originalConnect;
    if (failFreshWorkerRead) workerPool.query = originalWorkerQuery;
  }
}

async function sqlstateOf(operation: Promise<unknown>): Promise<string | undefined> {
  try {
    await operation;
    return undefined;
  } catch (error) {
    return typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : undefined;
  }
}

describe.skipIf(!enabled)('moderation outbox (PostgreSQL 17 disposable Fastify E2E)', () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  let controlPool: Pool | undefined;
  let jwksServer: Server;
  let privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
  const issuer = 'https://issuer.moderation-e2e.test/';
  let failNextCopy = true;
  let successfulCopies = 0;
  const copiedDestinationKeys: string[] = [];
  const deletedObjectKeys: string[] = [];
  let blockWorkerDelete = false;
  let signalDeleteStarted!: () => void;
  let releaseDelete!: () => void;
  const deleteStarted = new Promise<void>((resolve) => { signalDeleteStarted = resolve; });
  const deleteGate = new Promise<void>((resolve) => { releaseDelete = resolve; });

  async function moderatorToken(): Promise<string> {
    return new SignJWT({ role: 'reader', user_id: 'forged-id' }).setProtectedHeader({ alg: 'RS256', kid: 'moderation-outbox-e2e' })
      .setIssuer(issuer).setAudience('nova-api').setSubject(MODERATOR_SUBJECT).setIssuedAt()
      .setExpirationTime('5m').sign(privateKey);
  }

  async function ownerToken(): Promise<string> {
    return new SignJWT({ role: 'reader' }).setProtectedHeader({ alg: 'RS256', kid: 'moderation-outbox-e2e' })
      .setIssuer(issuer).setAudience('nova-api').setSubject('nova-rls-e2e:cover-owner').setIssuedAt()
      .setExpirationTime('5m').sign(privateKey);
  }

  async function request(
    token: string,
    targetId = STORY_ID,
    action: 'hide_story' | 'restore_story' | 'remove_comment' | 'suspend_user' | 'unsuspend_user' = 'hide_story',
    targetType: 'story' | 'comment' | 'user' = 'story',
    expectedHideActionId?: string,
  ): Promise<Response> {
    const inject = app.inject.bind(app) as unknown as (options: {
      method: 'POST'; url: string; payload: unknown; headers: Record<string, string>;
    }) => Promise<Response>;
    return inject({ method: 'POST', url: '/api/v1/moderation/actions',
      payload: { targetType, targetId, action, reason: 'E2E policy violation',
        ...(expectedHideActionId ? { expectedHideActionId } : {}) },
      headers: { authorization: `Bearer ${token}` } });
  }

  async function requestReportStatus(token: string, status: 'reviewing' | 'closed'): Promise<Response> {
    const inject = app.inject.bind(app) as unknown as (options: {
      method: 'PATCH'; url: string; payload: unknown; headers: Record<string, string>;
    }) => Promise<Response>;
    return inject({ method: 'PATCH', url: `/api/v1/moderation/reports/${REPORT_ID}`,
      payload: { status }, headers: { authorization: `Bearer ${token}` } });
  }

  async function reporterReport(token: string, reportId: string): Promise<Response> {
    const inject = app.inject.bind(app) as unknown as (options: {
      method: 'GET'; url: string; headers: Record<string, string>;
    }) => Promise<Response>;
    return inject({ method: 'GET', url: `/api/v1/me/reports/${reportId}`,
      headers: { authorization: `Bearer ${token}` } });
  }

  async function unpublishStory(token: string, id: string): Promise<Response> {
    const inject = app.inject.bind(app) as unknown as (options: {
      method: 'POST'; url: string; payload: unknown; headers: Record<string, string>;
    }) => Promise<Response>;
    return inject({ method: 'POST', url: `/api/v1/stories/${id}/unpublish`, payload: {},
      headers: { authorization: `Bearer ${token}` } });
  }

  async function publishStory(token: string, id: string): Promise<Response> {
    const inject = app.inject.bind(app) as unknown as (options: {
      method: 'POST'; url: string; payload: unknown; headers: Record<string, string>;
    }) => Promise<Response>;
    return inject({ method: 'POST', url: `/api/v1/stories/${id}/publish`, payload: {},
      headers: { authorization: `Bearer ${token}` } });
  }

  async function deleteStory(token: string, id: string): Promise<Response> {
    const inject = app.inject.bind(app) as unknown as (options: {
      method: 'DELETE'; url: string; headers: Record<string, string>;
    }) => Promise<Response>;
    return inject({ method: 'DELETE', url: `/api/v1/stories/${id}`, headers: { authorization: `Bearer ${token}` } });
  }

  beforeAll(async () => {
    const databases = [
      requireDisposableUrl(process.env.DATABASE_URL, 'DATABASE_URL'),
      requireDisposableUrl(process.env.RATE_LIMIT_DATABASE_URL, 'RATE_LIMIT_DATABASE_URL'),
      requireDisposableUrl(process.env.MEDIA_REVOCATION_DATABASE_URL, 'MEDIA_REVOCATION_DATABASE_URL'),
      requireDisposableUrl(process.env.RLS_CONTROL_DATABASE_URL, 'RLS_CONTROL_DATABASE_URL'),
    ];
    if (!databases.every((name) => name === databases[0])) throw new Error('All URLs must point to the same disposable database');
    const addresses = [process.env.DATABASE_URL, process.env.RATE_LIMIT_DATABASE_URL,
      process.env.MEDIA_REVOCATION_DATABASE_URL, process.env.RLS_CONTROL_DATABASE_URL]
      .map((url) => new URL(url!).host);
    if (!addresses.every((address) => address === addresses[0])) throw new Error('All URLs must point to the same loopback PostgreSQL server');
    controlPool = new Pool({ connectionString: process.env.RLS_CONTROL_DATABASE_URL, max: 1, options: '-c default_transaction_read_only=on' });
    const controlPrincipal = await controlPool.query<{ role: string; login: string }>(
      'SELECT current_user AS role, session_user AS login',
    );
    expect(controlPrincipal.rows[0]).toEqual({ role: 'postgres', login: 'postgres' });
    if (process.env.DATABASE_POOL_MAX !== '1') throw new Error('Set DATABASE_POOL_MAX=1 for the deadlock regression test');
    const version = await pool.query<{ version: string }>('SELECT current_setting(\'server_version_num\') AS version');
    if (!version.rows[0] || Number(version.rows[0].version) < 170000 || Number(version.rows[0].version) >= 180000) {
      throw new Error('RUN_MODERATION_OUTBOX_E2E requires PostgreSQL 17');
    }
    const runtime = await pool.query<{
      role: string; login: string; canUpdateStoryStatus: boolean; canInsertAction: boolean;
      canInsertRevocation: boolean; canCallHideProcedure: boolean; canCallEnqueueProcedure: boolean;
      wrapperCanDeleteStories: boolean; wrapperCanUpdateStoryStatus: boolean;
      wrapperCanInsertAction: boolean; wrapperCanInsertRevocation: boolean;
    }>(
      `SELECT current_user AS role, session_user AS login,
         has_column_privilege(current_user,'public.stories','status','UPDATE') AS "canUpdateStoryStatus",
         has_table_privilege(current_user,'public.moderation_actions','INSERT') AS "canInsertAction",
         has_table_privilege(current_user,'public.media_key_revocations','INSERT') AS "canInsertRevocation",
         has_function_privilege(current_user,'public.nova_moderate_hide_story(uuid,text)','EXECUTE') AS "canCallHideProcedure",
         has_function_privilege(current_user,'public.nova_enqueue_media_key_revocation(uuid,uuid,text,text)','EXECUTE') AS "canCallEnqueueProcedure",
         has_table_privilege(session_user,'public.stories','DELETE') AS "wrapperCanDeleteStories",
         has_column_privilege(session_user,'public.stories','status','UPDATE') AS "wrapperCanUpdateStoryStatus",
         has_column_privilege(session_user,'public.moderation_actions','reason','INSERT') AS "wrapperCanInsertAction",
         has_column_privilege(session_user,'public.media_key_revocations','media_id','INSERT') AS "wrapperCanInsertRevocation"`,
    );
    expect(runtime.rows[0]).toEqual({
      role: 'nova_fastify_runtime', login: loginName(process.env.DATABASE_URL!),
      canUpdateStoryStatus: true, canInsertAction: false, canInsertRevocation: false,
      canCallHideProcedure: true, canCallEnqueueProcedure: true, wrapperCanDeleteStories: false,
      wrapperCanUpdateStoryStatus: false, wrapperCanInsertAction: false, wrapperCanInsertRevocation: false,
    });
    const limiter = await rateLimitPool.query<{
      role: string; login: string; canSelect: boolean; canInsert: boolean; canUpdate: boolean; canDelete: boolean;
      canCallCounter: boolean; canDeleteStories: boolean; wrapperCanSelect: boolean; wrapperCanInsert: boolean; wrapperCanUpdate: boolean;
    }>(
      `SELECT current_user AS role, session_user AS login,
         has_table_privilege(current_user,'public.rate_limit_buckets','SELECT') AS "canSelect",
         has_table_privilege(current_user,'public.rate_limit_buckets','INSERT') AS "canInsert",
         has_table_privilege(current_user,'public.rate_limit_buckets','UPDATE') AS "canUpdate",
         has_table_privilege(current_user,'public.rate_limit_buckets','DELETE') AS "canDelete",
         has_function_privilege(current_user,'public.nova_rate_limit_record(text,timestamptz)','EXECUTE') AS "canCallCounter",
         has_table_privilege(current_user,'public.stories','DELETE') AS "canDeleteStories",
         has_table_privilege(session_user,'public.rate_limit_buckets','SELECT') AS "wrapperCanSelect",
         has_table_privilege(session_user,'public.rate_limit_buckets','INSERT') AS "wrapperCanInsert",
         has_table_privilege(session_user,'public.rate_limit_buckets','UPDATE') AS "wrapperCanUpdate"`,
    );
    expect(limiter.rows[0]).toEqual({
      role: 'nova_rate_limiter_runtime', login: loginName(process.env.RATE_LIMIT_DATABASE_URL!),
      canSelect: false, canInsert: false, canUpdate: false, canDelete: false, canCallCounter: true,
      canDeleteStories: false, wrapperCanSelect: false, wrapperCanInsert: false, wrapperCanUpdate: false,
    });
    const forcedRls = await pool.query<{ forced: boolean }>(
      `SELECT bool_and(relrowsecurity AND relforcerowsecurity) AS forced FROM pg_catalog.pg_class
       WHERE oid IN ('public.stories'::regclass,'public.moderation_actions'::regclass,'public.media_key_revocations'::regclass)`,
    );
    expect(forcedRls.rows[0]?.forced).toBe(true);
    const worker = await mediaRevocationPool.query<{
      role: string; login: string; canDelete: boolean; canUpdateActions: boolean; canUpdateRetry: boolean;
      canUpdateQueueTable: boolean; canUpdateSensitiveColumn: boolean;
    }>(
      `SELECT current_user AS role,
         session_user AS login,
         has_table_privilege(current_user,'public.media_key_revocations','DELETE') AS "canDelete",
         has_column_privilege(current_user,'public.media_key_revocations','attempt_count','UPDATE') AS "canUpdateRetry",
         has_table_privilege(current_user,'public.moderation_actions','UPDATE') AS "canUpdateActions",
         has_table_privilege(current_user,'public.media_key_revocations','UPDATE') AS "canUpdateQueueTable",
         (has_column_privilege(current_user,'public.media_key_revocations','id','UPDATE')
           OR has_column_privilege(current_user,'public.media_key_revocations','media_id','UPDATE')
           OR has_column_privilege(current_user,'public.media_key_revocations','source_key','UPDATE')
           OR has_column_privilege(current_user,'public.media_key_revocations','moderation_action_id','UPDATE')
           OR has_column_privilege(current_user,'public.media_key_revocations','created_at','UPDATE')) AS "canUpdateSensitiveColumn"`,
    );
    expect(worker.rows[0]).toEqual({
      role: 'nova_media_revocation_worker', login: loginName(process.env.MEDIA_REVOCATION_DATABASE_URL!),
      canDelete: false, canUpdateRetry: true, canUpdateActions: false, canUpdateQueueTable: false,
      canUpdateSensitiveColumn: false,
    });

    const { publicKey, privateKey: signer } = await generateKeyPair('RS256');
    privateKey = signer;
    const jwk = await exportJWK(publicKey);
    Object.assign(jwk, { kid: 'moderation-outbox-e2e', alg: 'RS256', use: 'sig' });
    jwksServer = createServer((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ keys: [jwk] }));
    });
    await new Promise<void>((resolve, reject) => {
      jwksServer.once('error', reject);
      jwksServer.listen(0, '127.0.0.1', resolve);
    });
    const port = (jwksServer.address() as AddressInfo).port;
    const config = loadConfig({
      ...process.env,
      NODE_ENV: 'test',
      RATE_LIMIT_HMAC_KEY: randomBytes(32).toString('hex'),
      LOG_LEVEL: 'error',
      AUTH_JWKS_URL: `http://127.0.0.1:${port}/jwks`,
      AUTH_ISSUER: issuer,
      AUTH_AUDIENCE: 'nova-api',
      CORS_ORIGINS: 'https://app.nova.test',
    });
    const storage = {
      close: async () => undefined,
      copyObjectToKey: async (_sourceKey: string, destinationKey: string) => {
        if (failNextCopy) {
          failNextCopy = false;
          throw new Error('simulated copy failure before enqueue');
        }
        successfulCopies += 1;
        copiedDestinationKeys.push(destinationKey);
      },
      deleteObject: async (objectKey: string) => {
        deletedObjectKeys.push(objectKey);
        if (!blockWorkerDelete) return;
        signalDeleteStarted();
        await deleteGate;
      },
    } as unknown as MediaStorage;
    app = await buildApp({ config, pg: pool, rateLimitPg: rateLimitPool, mediaRevocationPg: mediaRevocationPool, mediaStorage: storage, validatePrincipalStartup: true });
  }, 30_000);

  afterAll(async () => {
    releaseDelete?.();
    if (app) await app.close();
    if (jwksServer) await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
    await controlPool?.end();
    await closePool();
  }, 30_000);

  it('limits the limiter to its atomic supplied-key counter, blocks hash probing, and isolates key rotation', async () => {
    const keyA = randomBytes(32).toString('hex');
    const keyB = randomBytes(32).toString('hex');
    const keyC = randomBytes(32).toString('hex');
    const windowStartMs = Math.floor(Date.now() / 60_000) * 60_000;
    const record = async (key: string) => rateLimitPool.query<{ hits: number }>(
      'SELECT public.nova_rate_limit_record($1,to_timestamp($2/1000.0)) AS hits', [key, windowStartMs],
    );
    expect((await record(keyA)).rows[0]?.hits).toBe(1);
    expect((await record(keyB)).rows[0]?.hits).toBe(1);
    expect((await record(keyA)).rows[0]?.hits).toBe(2);
    expect((await record(keyA)).rows[0]?.hits).toBe(3);

    const material = 'ip:203.0.113.42:/api/v1/stories';
    const firstPepper = randomBytes(32);
    const rotatedPepper = randomBytes(32);
    const beforeRotationKey = createHmac('sha256', firstPepper).update(material).digest('hex');
    const afterRotationKey = createHmac('sha256', rotatedPepper).update(material).digest('hex');
    expect(afterRotationKey).not.toBe(beforeRotationKey);
    expect((await record(beforeRotationKey)).rows[0]?.hits).toBe(1);
    expect((await record(afterRotationKey)).rows[0]?.hits).toBe(1);

    const directCodes = [
      await sqlstateOf(rateLimitPool.query('SELECT hits FROM public.rate_limit_buckets WHERE bucket_key=$1', [keyB])),
      await sqlstateOf(rateLimitPool.query('SELECT count(*) FROM public.rate_limit_buckets')),
      await sqlstateOf(rateLimitPool.query('UPDATE public.rate_limit_buckets SET hits=99 WHERE bucket_key=$1', [keyB])),
      await sqlstateOf(rateLimitPool.query('DELETE FROM public.rate_limit_buckets WHERE bucket_key=$1', [keyB])),
      await sqlstateOf(rateLimitPool.query(
        'INSERT INTO public.rate_limit_buckets(bucket_key,window_start,hits) VALUES($1,to_timestamp($2/1000.0),1)',
        [keyC, windowStartMs],
      )),
    ];
    expect(directCodes).toEqual(['42501', '42501', '42501', '42501', '42501']);
    const inspected = await controlPool!.query<{ bucket_key: string; hits: number }>(
      'SELECT bucket_key,hits FROM public.rate_limit_buckets WHERE bucket_key=ANY($1::text[]) ORDER BY bucket_key', [[keyA, keyB]],
    );
    expect(inspected.rows).toEqual(
      [{ bucket_key: keyA, hits: 3 }, { bucket_key: keyB, hits: 1 }].sort((a, b) => a.bucket_key.localeCompare(b.bucket_key)),
    );
    const rotated = await controlPool!.query<{ bucket_key: string; hits: number }>(
      'SELECT bucket_key,hits FROM public.rate_limit_buckets WHERE bucket_key=ANY($1::text[]) ORDER BY bucket_key',
      [[beforeRotationKey, afterRotationKey]],
    );
    expect(rotated.rows).toEqual([{ bucket_key: afterRotationKey, hits: 1 }, { bucket_key: beforeRotationKey, hits: 1 }].sort((a, b) => a.bucket_key.localeCompare(b.bucket_key)));
  });

  it('returns 501 without side effects for unintegrated moderation writes and rejects direct status DML', async () => {
    const token = await moderatorToken();
    const unavailableMessage = 'Tindakan ini belum tersedia. Tidak ada perubahan yang dibuat dan kasus tetap terbuka.';
    const unsupported = [
      await request(token, COMMENT_ID, 'remove_comment', 'comment'),
      await request(token, OWNER_ID, 'suspend_user', 'user'),
      await request(token, OWNER_ID, 'unsuspend_user', 'user'),
      await requestReportStatus(token, 'closed'),
    ];
    for (const response of unsupported) {
      expect(response.statusCode).toBe(501);
      expect(response.json().error).toMatchObject({ code: 'NOT_INTEGRATED', message: unavailableMessage, retryable: false });
      expect(response.headers['retry-after']).toBeUndefined();
    }

    const direct = await pool.connect();
    const directDmlCodes: Array<string | undefined> = [];
    try {
      await direct.query('BEGIN');
      await direct.query(
        "SELECT set_config('app.user_id',$1,true),set_config('app.auth_subject',$2,true),set_config('app.user_role','moderator',true)",
        [MODERATOR_ID, MODERATOR_SUBJECT],
      );
      const forbiddenWrites: Array<[string, string, unknown[]]> = [
        ['comment_status', "UPDATE public.comments SET status='removed',deleted_at=now(),updated_at=now() WHERE id=$1", [COMMENT_ID]],
        ['comment_insert', "INSERT INTO public.comments(story_id,author_id,body,status) VALUES($1,$2,'Direct insert denied','visible')", [STORY_ID, OWNER_ID]],
        ['comment_delete', 'DELETE FROM public.comments WHERE id=$1', [COMMENT_ID]],
        ['user_status', "UPDATE public.users SET status='suspended',updated_at=now() WHERE id=$1", [OWNER_ID]],
        ['report_status', "UPDATE public.reports SET status='closed',updated_at=now() WHERE id=$1", [REPORT_ID]],
        ['action_insert', "INSERT INTO public.moderation_actions(moderator_id,target_type,target_id,action,reason) VALUES($1,'comment',$2,'remove_comment','Direct insert denied')", [MODERATOR_ID, COMMENT_ID]],
      ];
      for (const [savepoint, statement, parameters] of forbiddenWrites) {
        await direct.query(`SAVEPOINT ${savepoint}`);
        try {
          await direct.query(statement, parameters);
          directDmlCodes.push(undefined);
        } catch (error) {
          directDmlCodes.push(typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : undefined);
        }
        await direct.query(`ROLLBACK TO SAVEPOINT ${savepoint}`);
      }
    } finally {
      await direct.query('ROLLBACK').catch(() => undefined);
      direct.release();
    }
    expect(directDmlCodes).toEqual(['42501', '42501', '42501', '42501', '42501', '42501']);

    const state = await controlPool!.query<{
      commentStatus: string; userStatus: string; reportStatus: string; removalPending: boolean; storyStatus: string;
      actionCount: string; queueCount: string;
    }>(
      `SELECT c.status::text AS "commentStatus",u.status::text AS "userStatus",r.status::text AS "reportStatus",
         r.removal_pending AS "removalPending",s.status::text AS "storyStatus",
         (SELECT count(*)::text FROM moderation_actions WHERE target_id IN ($1,$2,$3)) AS "actionCount",
         (SELECT count(*)::text FROM media_key_revocations WHERE media_id=$4) AS "queueCount"
       FROM public.comments c CROSS JOIN public.users u CROSS JOIN public.reports r CROSS JOIN public.stories s
       WHERE c.id=$5 AND u.id=$2 AND r.id=$6 AND s.id=$1`,
      [STORY_ID, OWNER_ID, COMMENT_ID, MEDIA_ID, COMMENT_ID, REPORT_ID],
    );
    expect(state.rows[0]).toEqual({
      commentStatus: 'visible', userStatus: 'active', reportStatus: 'received', removalPending: false,
      storyStatus: 'published', actionCount: '0', queueCount: '0',
    });
  }, 15_000);

  it('returns explicit 501 for owner publish, unpublish, and delete with no side effects', async () => {
    const owner = await ownerToken();
    const readState = async (id: string) => controlPool!.query<{
      story: Record<string, unknown>; comments: unknown; actionCount: string; outboxCount: string;
    }>(
      `SELECT pg_catalog.to_jsonb(s) AS story,
         COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
           'id',c.id,'status',c.status::text,'body',c.body,'deletedAt',c.deleted_at,'updatedAt',c.updated_at) ORDER BY c.id)
           FROM public.comments c WHERE c.story_id=s.id),'[]'::jsonb) AS comments,
         (SELECT count(*)::text FROM moderation_actions a WHERE a.target_type='story' AND a.target_id=s.id) AS "actionCount",
         (SELECT count(*)::text FROM media_key_revocations q
           JOIN moderation_actions a ON a.id=q.moderation_action_id
           WHERE a.target_type='story' AND a.target_id=s.id) AS "outboxCount"
       FROM public.stories s WHERE s.id=$1`, [id],
    );
    const beforeDraft = (await readState(PUBLISH_STORY_ID)).rows[0];
    const beforePublished = (await readState(STORY_ID)).rows[0];
    expect(beforeDraft).toMatchObject({
      story: { status: 'draft', visibility: 'private', version: 1, published_at: null, comments_open: false, deleted_at: null },
      comments: [], actionCount: '0', outboxCount: '0',
    });
    expect(beforePublished).toMatchObject({
      story: { status: 'published', visibility: 'public', version: 1, published_at: expect.any(String), comments_open: true, deleted_at: null },
      actionCount: '0', outboxCount: '0',
    });
    expect(beforePublished?.comments).toEqual([
      expect.objectContaining({ id: COMMENT_ID, status: 'visible', body: 'Disposable comment for moderation guard' }),
    ]);

    const unavailableResponses = [
      [await within(publishStory(owner, PUBLISH_STORY_ID), 1_500, 'owner publish unavailable response'),
        'Publish is unavailable for the MVP. No changes were made.'],
      [await within(unpublishStory(owner, STORY_ID), 1_500, 'owner unpublish unavailable response'),
        'Unpublish is unavailable for the MVP. No changes were made.'],
      [await within(deleteStory(owner, STORY_ID), 1_500, 'owner delete unavailable response'),
        'Delete is unavailable for the MVP. No changes were made.'],
    ] as const;
    for (const [response, message] of unavailableResponses) {
      expect(response.statusCode).toBe(501);
      expect(response.json().error).toMatchObject({ code: 'NOT_INTEGRATED', message, retryable: false });
      expect(JSON.stringify(response.json())).not.toMatch(/42501|SQLSTATE|permission denied/i);
    }

    expect((await readState(PUBLISH_STORY_ID)).rows[0]).toEqual(beforeDraft);
    expect((await readState(STORY_ID)).rows[0]).toEqual(beforePublished);
  }, 10_000);

  it('commits action+enqueue atomically, never waits for the worker, and reuses one pending case on retry', async () => {
    const token = await moderatorToken();

    const direct = await pool.connect();
    let directStoryCode: string | undefined;
    let directActionCode: string | undefined;
    try {
      await direct.query('BEGIN');
      await direct.query(
        "SELECT set_config('app.user_id',$1,true),set_config('app.auth_subject',$2,true),set_config('app.user_role','moderator',true)",
        ['e1000000-0000-4000-8000-000000000001', MODERATOR_SUBJECT],
      );
      await direct.query('SAVEPOINT direct_story_update');
      try {
        await direct.query("UPDATE public.stories SET status='removed' WHERE id=$1", [STORY_ID]);
      } catch (error) {
        directStoryCode = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : undefined;
        await direct.query('ROLLBACK TO SAVEPOINT direct_story_update');
      }
      await direct.query('SAVEPOINT direct_action_insert');
      try {
        await direct.query(
          "INSERT INTO public.moderation_actions(moderator_id,target_type,target_id,action,reason) VALUES($1,'story',$2,'hide_story','Direct insert must be denied')",
          ['e1000000-0000-4000-8000-000000000001', STORY_ID],
        );
      } catch (error) {
        directActionCode = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : undefined;
        await direct.query('ROLLBACK TO SAVEPOINT direct_action_insert');
      }
    } finally {
      await direct.query('ROLLBACK').catch(() => undefined);
      direct.release();
    }
    expect(directStoryCode).toBe('42501');
    expect(directActionCode).toBe('42501');

    const failedCopy = await within(request(token), 1_500, 'failed-copy moderation request');
    expect(failedCopy.statusCode).toBe(503);
    expect(failedCopy.json().error).toMatchObject({ code: 'MEDIA_REVOCATION_UNAVAILABLE', retryable: true });
    expect(failedCopy.headers['retry-after']).toBe('5');
    const rolledBack = await controlPool!.query<{ status: string; actionCount: string; queueCount: string; reportStatus: string; removalPending: boolean }>(
      `SELECT s.status::text AS status,
         (SELECT count(*)::text FROM moderation_actions WHERE target_id=$1) AS "actionCount",
         (SELECT count(*)::text FROM media_key_revocations WHERE media_id=$2) AS "queueCount",
         r.status::text AS "reportStatus",r.removal_pending AS "removalPending"
       FROM stories s CROSS JOIN public.reports r WHERE s.id=$1 AND r.id=$3`, [STORY_ID, MEDIA_ID, REPORT_ID],
    );
    expect(rolledBack.rows[0]).toEqual({ status: 'published', actionCount: '0', queueCount: '0', reportStatus: 'received', removalPending: false });

    const first = await within(request(token), 1_500, 'moderation enqueue request');
    expect(first.statusCode).toBe(202);
    const firstBody = first.json();
    expect(firstBody.removal.status).toBe('pending');
    const actionId = firstBody.data.id as string;
    expect(actionId).toMatch(/^[0-9a-f-]{36}$/i);

    const firstQueue = await mediaRevocationPool.query<{ id: string; attempt_count: number; moderation_action_id: string }>(
      'SELECT id,attempt_count,moderation_action_id FROM media_key_revocations WHERE media_id=$1', [MEDIA_ID],
    );
    expect(firstQueue.rows).toHaveLength(1);
    const queueId = firstQueue.rows[0]!.id;
    expect(firstQueue.rows[0]!.moderation_action_id).toBe(actionId);
    const openCase = await controlPool!.query<{ status: string; removal_pending: boolean; first_response_at: Date | null }>(
      'SELECT status::text AS status,removal_pending,first_response_at FROM public.reports WHERE id=$1', [REPORT_ID],
    );
    const reporterView = await reporterReport(await ownerToken(), REPORT_ID);
    const reporterData = reporterView.json().data;
    const safePendingMetadata = {
      database: {
        workflowStatus: openCase.rows[0]?.status ?? null,
        removalPending: openCase.rows[0]?.removal_pending === true,
        firstResponseAtPresent: openCase.rows[0]?.first_response_at instanceof Date,
      },
      queue: {
        rowCount: firstQueue.rows.length,
        actionLinkMatches: firstQueue.rows[0]?.moderation_action_id === actionId,
      },
      api: {
        httpStatus: reporterView.statusCode,
        workflowStatus: reporterData?.status ?? null,
        removalStatus: reporterData?.removal?.status ?? null,
        removalPending: reporterData?.removalPending === true,
      },
    };
    console.log('SAFE_OUTBOX_REPORT_PENDING_METADATA', JSON.stringify(safePendingMetadata));
    expect(safePendingMetadata).toEqual({
      database: { workflowStatus: 'reviewing', removalPending: true, firstResponseAtPresent: true },
      queue: { rowCount: 1, actionLinkMatches: true },
      api: { httpStatus: 200, workflowStatus: 'reviewing', removalStatus: 'pending', removalPending: true },
    });
    expect(reporterData.removal.label).toBe('Removal pending — cleanup could not be confirmed');
    expect(openCase.rows[0]).toMatchObject({
      status: 'reviewing', removal_pending: true, first_response_at: expect.any(Date),
    });

    blockWorkerDelete = true;
    const retryWhileWorkerIsBlocked = processPendingMediaKeyRevocations(app, [queueId]);
    await within(deleteStarted, 1_000, 'outbox worker start');
    const retry = await within(request(token), 1_200, 'HTTP retry while outbox worker is blocked');
    expect(retry.statusCode).toBe(202);
    expect(retry.json().removal.status).toBe('pending');
    expect(retry.json().data.id).toBe(actionId);
    expect(successfulCopies).toBe(1);

    releaseDelete();
    await within(retryWhileWorkerIsBlocked, 3_000, 'outbox worker completion');
    blockWorkerDelete = false;
    const afterWorker = await mediaRevocationPool.query<{ id: string; attempt_count: number; retry_after: Date }>(
      'SELECT id,attempt_count,retry_after FROM media_key_revocations WHERE media_id=$1', [MEDIA_ID],
    );
    expect(afterWorker.rows).toHaveLength(1);
    expect(afterWorker.rows[0]!.id).toBe(queueId);
    expect(afterWorker.rows[0]!.attempt_count).toBe(1);

    const state = await controlPool!.query<{ action_id: string; removal_status: string; report_status: string; removal_pending: boolean }>(
      `SELECT a.id AS action_id, a.metadata->>'removalStatus' AS removal_status,
         r.status::text AS report_status,r.removal_pending
       FROM moderation_actions a CROSS JOIN public.reports r WHERE a.id=$1 AND r.id=$2`, [actionId, REPORT_ID],
    );
    expect(state.rows[0]).toEqual({
      action_id: actionId, removal_status: 'pending', report_status: 'reviewing', removal_pending: true,
    });
  }, 15_000);

  it('confirms a committed hide after a lost COMMIT acknowledgement through the fresh worker outbox read', async () => {
    if (!controlPool) throw new Error('RLS control connection is not initialized');
    const token = await moderatorToken();
    const source = await controlPool.query<{ object_key: string }>(
      'SELECT object_key FROM public.media_assets WHERE id=$1', [ACK_LOSS_MEDIA_ID],
    );
    const sourceKey = source.rows[0]?.object_key;
    if (!sourceKey) throw new Error('Acknowledgement-loss media fixture is missing');
    const copiesBefore = copiedDestinationKeys.length;
    const deletesBefore = deletedObjectKeys.length;
    const response = await within(
      withLostCommitAcknowledgement(() => request(token, ACK_LOSS_STORY_ID)),
      3_000,
      'committed acknowledgement-loss hide request',
    );
    expect(response.statusCode).toBe(202);
    const body = response.json();
    expect(body.removal.status).toBe('pending');
    const actionId = body.data.id as string;
    const destinationKey = copiedDestinationKeys[copiesBefore];
    if (!destinationKey) throw new Error('Acknowledgement-loss storage copy was not recorded');
    expect(JSON.stringify(body)).not.toContain(sourceKey);
    expect(JSON.stringify(body)).not.toContain(destinationKey);
    expect(deletedObjectKeys.slice(deletesBefore)).not.toContain(destinationKey);

    const persisted = await controlPool.query<{
      story_status: string; report_status: string; removal_pending: boolean;
      queue_count: number; queue_link_count: number; destination_is_current: boolean;
    }>(
      `SELECT s.status::text AS story_status,r.status::text AS report_status,r.removal_pending,
         (SELECT count(*)::int FROM public.media_key_revocations WHERE media_id=$2) AS queue_count,
         (SELECT count(*)::int FROM public.media_key_revocations WHERE media_id=$2 AND moderation_action_id=$3) AS queue_link_count,
         (SELECT object_key=$4 FROM public.media_assets WHERE id=$2) AS destination_is_current
       FROM public.stories s JOIN public.reports r ON r.id=$5 WHERE s.id=$1`,
      [ACK_LOSS_STORY_ID, ACK_LOSS_MEDIA_ID, actionId, destinationKey, ACK_LOSS_REPORT_ID],
    );
    const reporter = await reporterReport(await ownerToken(), ACK_LOSS_REPORT_ID);
    const reportData = reporter.json().data;
    const safeOutcome = {
      response: { httpStatus: response.statusCode, removalStatus: body.removal.status, objectKeyExposed: false },
      database: {
        storyStatus: persisted.rows[0]?.story_status ?? null,
        reportStatus: persisted.rows[0]?.report_status ?? null,
        removalPending: persisted.rows[0]?.removal_pending === true,
        queueCount: persisted.rows[0]?.queue_count ?? 0,
        queueLinkCount: persisted.rows[0]?.queue_link_count ?? 0,
        destinationIsCurrent: persisted.rows[0]?.destination_is_current === true,
      },
      reporterApi: {
        httpStatus: reporter.statusCode,
        workflowStatus: reportData?.status ?? null,
        removalStatus: reportData?.removal?.status ?? null,
        removalPending: reportData?.removalPending === true,
      },
      storage: { destinationPreserved: !deletedObjectKeys.slice(deletesBefore).includes(destinationKey) },
    };
    console.log('SAFE_COMMIT_ACK_LOST_CONFIRMED_METADATA', JSON.stringify(safeOutcome));
    expect(safeOutcome).toEqual({
      response: { httpStatus: 202, removalStatus: 'pending', objectKeyExposed: false },
      database: {
        storyStatus: 'removed', reportStatus: 'reviewing', removalPending: true,
        queueCount: 1, queueLinkCount: 1, destinationIsCurrent: true,
      },
      reporterApi: { httpStatus: 200, workflowStatus: 'reviewing', removalStatus: 'pending', removalPending: true },
      storage: { destinationPreserved: true },
    });
  }, 10_000);

  it('returns a neutral refresh response and preserves the copy when a lost COMMIT cannot be resolved', async () => {
    if (!controlPool) throw new Error('RLS control connection is not initialized');
    const token = await moderatorToken();
    const source = await controlPool.query<{ object_key: string }>(
      'SELECT object_key FROM public.media_assets WHERE id=$1', [ACK_UNKNOWN_MEDIA_ID],
    );
    const sourceKey = source.rows[0]?.object_key;
    if (!sourceKey) throw new Error('Unresolved acknowledgement fixture is missing');
    const copiesBefore = copiedDestinationKeys.length;
    const deletesBefore = deletedObjectKeys.length;
    const response = await within(
      withLostCommitAcknowledgement(() => request(token, ACK_UNKNOWN_STORY_ID), true),
      3_000,
      'unresolved acknowledgement-loss hide request',
    );
    const body = response.json();
    expect(response.statusCode).toBe(503);
    expect(body.error).toMatchObject({
      code: 'TRANSACTION_OUTCOME_UNCONFIRMED',
      message: "We couldn't confirm the status. Refresh before trying again.",
    });
    expect(body.removal).toBeUndefined();
    const destinationKey = copiedDestinationKeys[copiesBefore];
    if (!destinationKey) throw new Error('Unresolved acknowledgement storage copy was not recorded');
    expect(JSON.stringify(body)).not.toContain(sourceKey);
    expect(JSON.stringify(body)).not.toContain(destinationKey);
    expect(deletedObjectKeys.slice(deletesBefore)).not.toContain(destinationKey);

    const reporter = await reporterReport(await ownerToken(), ACK_UNKNOWN_REPORT_ID);
    const reportData = reporter.json().data;
    const persisted = await controlPool.query<{
      story_status: string; report_status: string; removal_pending: boolean; queue_count: number;
    }>(
      `SELECT s.status::text AS story_status,r.status::text AS report_status,r.removal_pending,
         (SELECT count(*)::int FROM public.media_key_revocations WHERE media_id=$2) AS queue_count
       FROM public.stories s JOIN public.reports r ON r.id=$3 WHERE s.id=$1`,
      [ACK_UNKNOWN_STORY_ID, ACK_UNKNOWN_MEDIA_ID, ACK_UNKNOWN_REPORT_ID],
    );
    const safeOutcome = {
      response: { httpStatus: response.statusCode, errorCode: body.error?.code ?? null, removalFieldPresent: body.removal !== undefined },
      storage: { destinationPreserved: !deletedObjectKeys.slice(deletesBefore).includes(destinationKey), objectKeyExposed: false },
      refreshApi: {
        httpStatus: reporter.statusCode,
        workflowStatus: reportData?.status ?? null,
        removalStatus: reportData?.removal?.status ?? null,
        removalPending: reportData?.removalPending === true,
      },
      database: {
        storyStatus: persisted.rows[0]?.story_status ?? null,
        reportStatus: persisted.rows[0]?.report_status ?? null,
        removalPending: persisted.rows[0]?.removal_pending === true,
        queueCount: persisted.rows[0]?.queue_count ?? 0,
      },
    };
    console.log('SAFE_COMMIT_ACK_LOST_UNRESOLVED_METADATA', JSON.stringify(safeOutcome));
    expect(safeOutcome).toEqual({
      response: { httpStatus: 503, errorCode: 'TRANSACTION_OUTCOME_UNCONFIRMED', removalFieldPresent: false },
      storage: { destinationPreserved: true, objectKeyExposed: false },
      refreshApi: { httpStatus: 200, workflowStatus: 'reviewing', removalStatus: 'pending', removalPending: true },
      database: { storyStatus: 'removed', reportStatus: 'reviewing', removalPending: true, queueCount: 1 },
    });
  }, 10_000);

  it('retains attempt five as escalated and pending without claiming verified purge', async () => {
    if (!controlPool) throw new Error('RLS control connection is not initialized');
    const initial = await controlPool.query<{ id: string; attempt_count: number }>(
      'SELECT id,attempt_count FROM public.media_key_revocations WHERE media_id=$1', [MEDIA_ID],
    );
    expect(initial.rows).toHaveLength(1);
    const queueId = initial.rows[0]!.id;
    const controlWriter = new Pool({ connectionString: process.env.RLS_CONTROL_DATABASE_URL, max: 1 });
    try {
      let attempt = initial.rows[0]!.attempt_count;
      while (attempt < 5) {
        await controlWriter.query(
          "UPDATE public.media_key_revocations SET retry_after=statement_timestamp()-interval '1 second' WHERE id=$1",
          [queueId],
        );
        await processPendingMediaKeyRevocations(app, [queueId]);
        const current = await controlPool.query<{ attempt_count: number }>(
          'SELECT attempt_count FROM public.media_key_revocations WHERE id=$1', [queueId],
        );
        expect(current.rows[0]?.attempt_count).toBe(attempt + 1);
        attempt = current.rows[0]!.attempt_count;
      }
    } finally {
      await controlWriter.end();
    }

    const terminal = await controlPool.query<{
      attempt_count: number; escalated_at: Date | null; removal_status: string; verified_at: Date | null; queue_rows: string;
    }>(
      `SELECT q.attempt_count,q.escalated_at,a.metadata->>'removalStatus' AS removal_status,
         (a.metadata->>'removalVerifiedAt')::timestamptz AS verified_at,
         (SELECT count(*)::text FROM public.media_key_revocations WHERE id=q.id) AS queue_rows
       FROM public.media_key_revocations q JOIN public.moderation_actions a ON a.id=q.moderation_action_id
       WHERE q.id=$1`, [queueId],
    );
    expect(terminal.rows[0]).toMatchObject({
      attempt_count: 5, removal_status: 'pending', verified_at: null, queue_rows: '1',
    });
    expect(terminal.rows[0]?.escalated_at).toBeInstanceOf(Date);
    const token = await moderatorToken();
    const stillPending = await within(request(token), 1_500, 'attempt-five pending moderation response');
    expect(stillPending.statusCode).toBe(202);
    expect(stillPending.json().removal.status).toBe('pending');
  }, 15_000);

  it('rejects stale restore without side effects and restores only the latest hide state', async () => {
    const token = await moderatorToken();
    const hidden = await within(request(token, RESTORE_STORY_ID), 1_500, 'no-media hide action');
    expect(hidden.statusCode).toBe(201);
    expect(hidden.json().removal.status).toBe('no_media_required');
    const firstHideActionId = hidden.json().data.id as string;
    expect(firstHideActionId).toMatch(/^[0-9a-f-]{36}$/i);
    const hiddenState = await controlPool!.query<{
      status: string; removalStatus: string; commentsOpen: boolean; priorCommentsOpen: string;
    }>(
      `SELECT s.status::text AS status, a.metadata->>'removalStatus' AS "removalStatus",
         s.comments_open AS "commentsOpen", a.metadata->>'priorCommentsOpen' AS "priorCommentsOpen"
       FROM stories s JOIN moderation_actions a ON a.target_id=s.id AND a.action='hide_story'
       WHERE s.id=$1`, [RESTORE_STORY_ID],
    );
    expect(hiddenState.rows[0]).toEqual({
      status: 'removed', removalStatus: 'no_media_required', commentsOpen: false, priorCommentsOpen: 'false',
    });

    const firstRestore = await within(request(token, RESTORE_STORY_ID, 'restore_story', 'story', firstHideActionId), 1_500,
      'first no-media restore action');
    expect(firstRestore.statusCode).toBe(201);
    expect(firstRestore.json().data.action).toBe('restore_story');
    expect(firstRestore.json().data.commentsOpen).toBe(false);

    const beforeChangedStatusConflict = await controlPool!.query<{
      status: string; visibility: string; commentsOpen: boolean; version: number;
      reportStatus: string; removalPending: boolean; restoreActions: string;
    }>(
      `SELECT s.status::text AS status, s.visibility::text AS visibility, s.comments_open AS "commentsOpen", s.version,
         r.status::text AS "reportStatus", r.removal_pending AS "removalPending",
         (SELECT count(*)::text FROM moderation_actions a WHERE a.target_id=s.id AND a.action='restore_story') AS "restoreActions"
       FROM stories s JOIN reports r ON r.target_id=s.id WHERE s.id=$1 AND r.id=$2`,
      [RESTORE_STORY_ID, RESTORE_REPORT_ID],
    );
    expect(beforeChangedStatusConflict.rows[0]).toMatchObject({
      status: 'published', visibility: 'public', commentsOpen: false, reportStatus: 'reviewing',
      removalPending: false, restoreActions: '1',
    });
    const staleAfterStatusChange = await within(
      request(token, RESTORE_STORY_ID, 'restore_story', 'story', firstHideActionId), 1_500,
      'stale restore after Story status changed',
    );
    expect(staleAfterStatusChange.statusCode).toBe(409);
    expect(staleAfterStatusChange.json().error).toMatchObject({
      code: 'STALE_STORY_STATE',
      message: 'Story status changed. Reload the latest status before trying again.',
    });
    const afterChangedStatusConflict = await controlPool!.query(
      `SELECT s.status::text AS status, s.visibility::text AS visibility, s.comments_open AS "commentsOpen", s.version,
         r.status::text AS "reportStatus", r.removal_pending AS "removalPending",
         (SELECT count(*)::text FROM moderation_actions a WHERE a.target_id=s.id AND a.action='restore_story') AS "restoreActions"
       FROM stories s JOIN reports r ON r.target_id=s.id WHERE s.id=$1 AND r.id=$2`,
      [RESTORE_STORY_ID, RESTORE_REPORT_ID],
    );
    expect(afterChangedStatusConflict.rows[0]).toEqual(beforeChangedStatusConflict.rows[0]);

    await controlPool!.query('SELECT pg_catalog.pg_sleep(0.02)');

    const secondHide = await within(request(token, RESTORE_STORY_ID), 1_500, 'second no-media hide action');
    expect(secondHide.statusCode).toBe(201);
    const secondHideActionId = secondHide.json().data.id as string;
    expect(secondHideActionId).not.toBe(firstHideActionId);
    const beforeStaleRestore = await controlPool!.query<{
      status: string; visibility: string; commentsOpen: boolean; version: number;
      reportStatus: string; removalPending: boolean; restoreActions: string;
    }>(
      `SELECT s.status::text AS status, s.visibility::text AS visibility, s.comments_open AS "commentsOpen", s.version,
         r.status::text AS "reportStatus", r.removal_pending AS "removalPending",
         (SELECT count(*)::text FROM moderation_actions a WHERE a.target_id=s.id AND a.action='restore_story') AS "restoreActions"
       FROM stories s JOIN reports r ON r.target_id=s.id WHERE s.id=$1 AND r.id=$2`,
      [RESTORE_STORY_ID, RESTORE_REPORT_ID],
    );
    expect(beforeStaleRestore.rows[0]).toMatchObject({
      status: 'removed', visibility: 'private', commentsOpen: false, reportStatus: 'reviewing',
      removalPending: false, restoreActions: '1',
    });

    const staleRestore = await within(request(token, RESTORE_STORY_ID, 'restore_story', 'story', firstHideActionId), 1_500,
      'stale restore conflict');
    expect(staleRestore.statusCode).toBe(409);
    expect(staleRestore.json().error).toMatchObject({
      code: 'STALE_STORY_STATE',
      message: 'Story status changed. Reload the latest status before trying again.',
    });
    const afterStaleRestore = await controlPool!.query<{
      status: string; visibility: string; commentsOpen: boolean; version: number;
      reportStatus: string; removalPending: boolean; restoreActions: string;
    }>(
      `SELECT s.status::text AS status, s.visibility::text AS visibility, s.comments_open AS "commentsOpen", s.version,
         r.status::text AS "reportStatus", r.removal_pending AS "removalPending",
         (SELECT count(*)::text FROM moderation_actions a WHERE a.target_id=s.id AND a.action='restore_story') AS "restoreActions"
       FROM stories s JOIN reports r ON r.target_id=s.id WHERE s.id=$1 AND r.id=$2`,
      [RESTORE_STORY_ID, RESTORE_REPORT_ID],
    );
    expect(afterStaleRestore.rows[0]).toEqual(beforeStaleRestore.rows[0]);

    const restored = await within(request(token, RESTORE_STORY_ID, 'restore_story', 'story', secondHideActionId), 1_500,
      'restore latest no-media hide action');
    expect(restored.statusCode).toBe(201);
    expect(restored.json().data.action).toBe('restore_story');
    expect(restored.json().data.commentsOpen).toBe(false);
    const restoredState = await controlPool!.query<{
      status: string; visibility: string; commentsOpen: boolean; restoreActions: string;
      restoredStatus: string; restoredCommentsOpen: string; restoreFromHideActionId: string; reportStatus: string;
    }>(
      `SELECT s.status::text AS status, s.visibility::text AS visibility,
         s.comments_open AS "commentsOpen",
         (SELECT count(*)::text FROM moderation_actions a WHERE a.target_id=s.id AND a.action='restore_story') AS "restoreActions",
         (SELECT a.metadata->>'restoreStatus' FROM moderation_actions a
           WHERE a.target_id=s.id AND a.action='restore_story' ORDER BY a.created_at DESC,a.id DESC LIMIT 1) AS "restoredStatus",
         (SELECT a.metadata->>'restoredCommentsOpen' FROM moderation_actions a
           WHERE a.target_id=s.id AND a.action='restore_story' ORDER BY a.created_at DESC,a.id DESC LIMIT 1) AS "restoredCommentsOpen",
         (SELECT a.metadata->>'restoreFromHideActionId' FROM moderation_actions a
           WHERE a.target_id=s.id AND a.action='restore_story' ORDER BY a.created_at DESC,a.id DESC LIMIT 1) AS "restoreFromHideActionId",
         r.status::text AS "reportStatus"
       FROM stories s JOIN reports r ON r.target_id=s.id WHERE s.id=$1 AND r.id=$2`,
      [RESTORE_STORY_ID, RESTORE_REPORT_ID],
    );
    expect(restoredState.rows[0]).toEqual({
      status: 'published', visibility: 'public', commentsOpen: false, restoreActions: '2',
      restoredStatus: 'published', restoredCommentsOpen: 'false', restoreFromHideActionId: secondHideActionId,
      reportStatus: 'reviewing',
    });

    const commentsOpenWriter = new Pool({ connectionString: process.env.RLS_CONTROL_DATABASE_URL, max: 1 });
    try {
      await commentsOpenWriter.query('UPDATE public.stories SET comments_open=true WHERE id=$1', [RESTORE_STORY_ID]);
    } finally {
      await commentsOpenWriter.end();
    }
    const commentsOpenBefore = await controlPool!.query<{
      status: string; visibility: string; comments_open: boolean; published_epoch: string;
    }>(
      `SELECT status::text,visibility::text,comments_open,
         extract(epoch FROM published_at)::numeric(30,6)::text AS published_epoch
       FROM public.stories WHERE id=$1`, [RESTORE_STORY_ID],
    );
    expect(commentsOpenBefore.rows[0]).toMatchObject({ status: 'published', visibility: 'public', comments_open: true });
    expect(Number(commentsOpenBefore.rows[0]?.published_epoch)).toBeGreaterThan(0);
    const openHide = await within(request(token, RESTORE_STORY_ID), 1_500, 'comments-open no-media hide action');
    expect(openHide.statusCode).toBe(201);
    const openHideActionId = openHide.json().data.id as string;
    const commentsOpenHidden = await controlPool!.query<{
      status: string; visibility: string; comments_open: boolean; published_epoch: string;
      prior_visibility: string; prior_published_epoch: string; prior_comments_open: string;
    }>(
      `SELECT s.status::text,s.visibility::text,s.comments_open,
         extract(epoch FROM s.published_at)::numeric(30,6)::text AS published_epoch,
         a.metadata->>'priorVisibility' AS prior_visibility,
         extract(epoch FROM (a.metadata->>'priorPublishedAt')::timestamptz)::numeric(30,6)::text AS prior_published_epoch,
         a.metadata->>'priorCommentsOpen' AS prior_comments_open
       FROM public.stories s JOIN public.moderation_actions a ON a.target_id=s.id
       WHERE s.id=$1 AND a.id=$2`, [RESTORE_STORY_ID, openHideActionId],
    );
    expect(commentsOpenHidden.rows[0]).toEqual({
      status: 'removed', visibility: 'private', comments_open: false,
      published_epoch: commentsOpenBefore.rows[0]?.published_epoch,
      prior_visibility: 'public', prior_published_epoch: commentsOpenBefore.rows[0]?.published_epoch,
      prior_comments_open: 'true',
    });
    const openRestore = await within(
      request(token, RESTORE_STORY_ID, 'restore_story', 'story', openHideActionId), 1_500,
      'restore comments-open published Story',
    );
    expect(openRestore.statusCode).toBe(201);
    expect(openRestore.json().data.commentsOpen).toBe(true);
    const commentsOpenRestored = await controlPool!.query<{
      status: string; visibility: string; comments_open: boolean; published_epoch: string;
      restored_visibility: string; restored_published_epoch: string; restored_comments_open: string;
    }>(
      `SELECT s.status::text,s.visibility::text,s.comments_open,
         extract(epoch FROM s.published_at)::numeric(30,6)::text AS published_epoch,
         (SELECT a.metadata->>'restoredVisibility' FROM public.moderation_actions a
           WHERE a.target_id=s.id AND a.action='restore_story'
           ORDER BY a.created_at DESC,a.id DESC LIMIT 1) AS restored_visibility,
         (SELECT extract(epoch FROM (a.metadata->>'restoredPublishedAt')::timestamptz)::numeric(30,6)::text
           FROM public.moderation_actions a WHERE a.target_id=s.id AND a.action='restore_story'
           ORDER BY a.created_at DESC,a.id DESC LIMIT 1) AS restored_published_epoch,
         (SELECT a.metadata->>'restoredCommentsOpen' FROM public.moderation_actions a
           WHERE a.target_id=s.id AND a.action='restore_story'
           ORDER BY a.created_at DESC,a.id DESC LIMIT 1) AS restored_comments_open
       FROM public.stories s WHERE s.id=$1`, [RESTORE_STORY_ID],
    );
    expect(commentsOpenRestored.rows[0]).toEqual({
      status: 'published', visibility: 'public', comments_open: true,
      published_epoch: commentsOpenBefore.rows[0]?.published_epoch,
      restored_visibility: 'public', restored_published_epoch: commentsOpenBefore.rows[0]?.published_epoch,
      restored_comments_open: 'true',
    });
    console.log('SAFE_RESTORE_PUBLISHED_AT', JSON.stringify({
      originalPublishedAtPresent: Number(commentsOpenBefore.rows[0]?.published_epoch) > 0,
      hideAuditMatchesOriginal: commentsOpenHidden.rows[0]?.prior_published_epoch === commentsOpenBefore.rows[0]?.published_epoch,
      restoreMatchesOriginal: commentsOpenRestored.rows[0]?.published_epoch === commentsOpenBefore.rows[0]?.published_epoch,
      originalVisibilityRestored: commentsOpenRestored.rows[0]?.restored_visibility === 'public',
    }));
    console.log('SAFE_RESTORE_COMMENTS_OPEN_METADATA', JSON.stringify({
      initiallyOpen: commentsOpenBefore.rows[0]?.comments_open === true,
      closedWhileHidden: commentsOpenHidden.rows[0]?.comments_open === false,
      priorStateRecorded: commentsOpenHidden.rows[0]?.prior_comments_open === 'true',
      restoredOpen: commentsOpenRestored.rows[0]?.comments_open === true,
      restoredStateRecorded: commentsOpenRestored.rows[0]?.restored_comments_open === 'true',
    }));
  }, 10_000);
});
