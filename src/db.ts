import './env.js';
import pg from 'pg';
import type { FastifyRequest } from 'fastify';
import { loadConfig } from './config.js';

const { Pool } = pg;
const config = loadConfig();
// Pin the exact UTF-8 prosrc bodies installed by the local disposable runtime-contract fixture.
// Updating these hashes requires Security approval and an approved production migration; neither is implied here.
const securityDefinerBodySha256 = {
  authBootstrap: '702baf03cb51f608f256a4c26e7a1d9f94f6c2ca18dab4254d3c094d8034b75c',
  rateLimitCounter: '8ce6c41bcd6bbc577a5c7baa64301afb0b6c669b029528d2a1acadb28dcad5b3',
  moderateHideStory: 'eabee6bcb60fff0b001315438d0de3d1da7704c3d67cee96863fa38bb1b29d3c',
  moderateRestoreStory: '836e767c65f15261d7a446de23a66d4c768ae9bef0559fdeb267f4bc92e79647',
  enqueueMediaKeyRevocation: '2d5306b93aba0fcc839e315dfea5e54be4221e93cf7f73b0ac97ab82fd6e5463',
  ownMediaRevocationPending: '8ed8356aa0bef490bf754603dc57b55c802b9dc1dcd3494c9ebe210836f0b1fb',
  validModerationAction: '5b891ad8cb617dde544addc38d19f9a3f81e41afab1778fa9f059309d7d672dc',
  actorActive: 'a6ae6de2cd9e0da1f5285f36c4896f1672acccd1119540a034a7c969f93514d8',
  actorHasRole: 'd553e7a6da482824ee4b0de2b9bb18bbfe1ff448a4f62d874c70ae14b0c7d176',
  mediaRevocationWorkerPredicate: 'bd8b89f3b4394f8dc1b500ef7e5a5b71fa7d459a5e121124ce495642f2499563',
} as const;

export const pool = new Pool({
  connectionString: config.DATABASE_URL,
  ...(config.DATABASE_ROLE ? { options: `-c role=${config.DATABASE_ROLE}` } : {}),
  max: config.DATABASE_POOL_MAX,
  connectionTimeoutMillis: 5_000,
  idleTimeoutMillis: 30_000,
  statement_timeout: 15_000,
  application_name: 'nova-backend',
});

export const rateLimitPool = config.RATE_LIMIT_DATABASE_URL
  ? new Pool({
      connectionString: config.RATE_LIMIT_DATABASE_URL,
      ...(config.RATE_LIMIT_DATABASE_ROLE ? { options: `-c role=${config.RATE_LIMIT_DATABASE_ROLE}` } : {}),
      max: Math.min(config.DATABASE_POOL_MAX, 5),
      connectionTimeoutMillis: 5_000,
      idleTimeoutMillis: 30_000,
      statement_timeout: 5_000,
      application_name: 'nova-rate-limiter',
    })
  : pool;

export const mediaRevocationPool = config.MEDIA_REVOCATION_DATABASE_URL
  ? new Pool({
      connectionString: config.MEDIA_REVOCATION_DATABASE_URL,
      ...(config.MEDIA_REVOCATION_DATABASE_ROLE ? { options: `-c role=${config.MEDIA_REVOCATION_DATABASE_ROLE}` } : {}),
      max: Math.min(config.DATABASE_POOL_MAX, 2),
      connectionTimeoutMillis: 5_000,
      idleTimeoutMillis: 30_000,
      statement_timeout: 15_000,
      application_name: 'nova-media-revocation-worker',
    })
  : pool;

pool.on('error', (error) => {
  console.error('Unexpected idle PostgreSQL client error', { message: error.message });
});
if (rateLimitPool !== pool) {
  rateLimitPool.on('error', (error) => {
    console.error('Unexpected idle rate-limit PostgreSQL client error', { message: error.message });
  });
}
if (mediaRevocationPool !== pool && mediaRevocationPool !== rateLimitPool) {
  mediaRevocationPool.on('error', (error) => {
    console.error('Unexpected idle media-revocation PostgreSQL client error', { message: error.message });
  });
}

export function requestDatabase(request: FastifyRequest): pg.Pool | pg.PoolClient {
  return request.db ?? request.server.pg;
}

async function withTransaction<T>(database: pg.Pool, fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await database.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

// Use for non-request workers and existing internal jobs.
export async function inTransaction<T>(fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  return withTransaction(pool, fn);
}

// Authenticated request transactions are opened by the auth hook; route-level
// atomic blocks reuse that exact client and never issue a nested COMMIT.
export async function inRequestTransaction<T>(
  request: FastifyRequest,
  fn: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  if (request.db) return fn(request.db);
  return withTransaction(request.server.pg, fn);
}

export async function closePool(): Promise<void> {
  await Promise.all([...new Set([pool, rateLimitPool, mediaRevocationPool])].map((database) => database.end()));
}

type PrincipalProbe = {
  effectiveRole: string;
  loginRole: string;
  effectiveCanLogin: boolean;
  effectiveInherit: boolean;
  effectiveSuperuser: boolean;
  effectiveBypassRls: boolean;
  effectiveCreateRole: boolean;
  effectiveCreateDb: boolean;
  effectiveReplication: boolean;
  effectiveSchemaUsage: boolean;
  effectiveSchemaCreate: boolean;
  loginCanLogin: boolean;
  loginInherit: boolean;
  loginSuperuser: boolean;
  loginBypassRls: boolean;
  loginCreateRole: boolean;
  loginCreateDb: boolean;
  loginReplication: boolean;
  loginSchemaUsage: boolean;
  loginSchemaCreate: boolean;
  loginAuthBootstrapExecute: boolean;
  authBootstrapDefinerSafe: boolean;
  loginUsersInsert: boolean;
  loginUsersAnyInsert: boolean;
  loginAuthSubjectSelect: boolean;
  loginAuthSubjectInsert: boolean;
  mayAssumeRole: boolean;
  directMembershipCount: number;
  loginMemberCount: number;
  loginHasOtherSetRoleMembers: boolean;
  loginExpectedMembershipCount: number;
  loginMembershipOptionsSafe: boolean;
  effectiveMemberCount: number;
  effectiveAdminOptionCount: number;
  loginAdminOptionCount: number;
  loginMembershipClosureCount: number;
  effectiveMembershipClosureCount: number;
  rateLimitSelect: boolean;
  rateLimitInsert: boolean;
  rateLimitUpdate: boolean;
  rateLimitDelete: boolean;
  rateLimitCounterExecute: boolean;
  rateLimitCounterDefinerSafe: boolean;
  authBootstrapExecute: boolean;
  usersInsert: boolean;
  usersAnyInsert: boolean;
  authSubjectSelect: boolean;
  authSubjectInsert: boolean;
  actionInsert: boolean;
  actionReasonInsert: boolean;
  queueSelectId: boolean;
  queueSelectMediaId: boolean;
  queueSelectSourceKey: boolean;
  queueSelectActionId: boolean;
  queueSelectAttemptCount: boolean;
  queueSelectRetryAfter: boolean;
  queueSelectCreatedAt: boolean;
  queueSelectEscalatedAt: boolean;
  queueInsert: boolean;
  queueDelete: boolean;
  queueUpdateAttemptCount: boolean;
  queueUpdateRetryAfter: boolean;
  queueUpdateEscalatedAt: boolean;
  queueUpdateTable: boolean;
  queueUpdateUnexpected: boolean;
  workerHasUnexpectedUpdate: boolean;
  actionUpdate: boolean;
  canAssumeOtherRuntime: boolean;
  canSetOtherRuntime: boolean;
  publicSchemaPublicGrant: boolean;
};

export async function validateDatabasePrincipals(
  runtimePool: pg.Pool,
  limiterPool: pg.Pool,
  workerPool: pg.Pool,
): Promise<void> {
  const query = `SELECT current_user::text AS "effectiveRole", session_user::text AS "loginRole",
      effective.rolcanlogin AS "effectiveCanLogin",
      effective.rolinherit AS "effectiveInherit",
      effective.rolsuper AS "effectiveSuperuser", effective.rolbypassrls AS "effectiveBypassRls",
      effective.rolcreaterole AS "effectiveCreateRole", effective.rolcreatedb AS "effectiveCreateDb",
      effective.rolreplication AS "effectiveReplication",
      pg_catalog.has_schema_privilege(current_user,'public','USAGE') AS "effectiveSchemaUsage",
      pg_catalog.has_schema_privilege(current_user,'public','CREATE') AS "effectiveSchemaCreate",
      login.rolcanlogin AS "loginCanLogin", login.rolinherit AS "loginInherit",
      login.rolsuper AS "loginSuperuser", login.rolbypassrls AS "loginBypassRls",
      login.rolcreaterole AS "loginCreateRole", login.rolcreatedb AS "loginCreateDb",
      login.rolreplication AS "loginReplication",
      pg_catalog.has_schema_privilege(session_user,'public','USAGE') AS "loginSchemaUsage",
      pg_catalog.has_schema_privilege(session_user,'public','CREATE') AS "loginSchemaCreate",
      pg_catalog.has_function_privilege(session_user,'public.nova_auth_bootstrap_identity(text)','EXECUTE') AS "loginAuthBootstrapExecute",
      pg_catalog.has_table_privilege(session_user,'public.users','INSERT') AS "loginUsersInsert",
      pg_catalog.has_any_column_privilege(session_user,'public.users','INSERT') AS "loginUsersAnyInsert",
      pg_catalog.has_column_privilege(session_user,'public.users','auth_subject','SELECT') AS "loginAuthSubjectSelect",
      pg_catalog.has_column_privilege(session_user,'public.users','auth_subject','INSERT') AS "loginAuthSubjectInsert",
      pg_catalog.pg_has_role(session_user,$1,'SET') AS "mayAssumeRole",
      (SELECT count(*)::integer FROM pg_catalog.pg_auth_members memberships
       WHERE memberships.member=login.oid) AS "directMembershipCount",
      (SELECT count(*)::integer FROM pg_catalog.pg_auth_members memberships
       WHERE memberships.roleid=login.oid) AS "loginMemberCount",
      EXISTS (SELECT 1 FROM pg_catalog.pg_roles candidate
        WHERE candidate.oid<>login.oid AND NOT candidate.rolsuper
          AND pg_catalog.pg_has_role(candidate.oid,login.oid,'SET')) AS "loginHasOtherSetRoleMembers",
      (SELECT count(*)::integer FROM pg_catalog.pg_auth_members memberships
       WHERE memberships.member=login.oid AND memberships.roleid=effective.oid) AS "loginExpectedMembershipCount",
      COALESCE((SELECT pg_catalog.bool_and(NOT memberships.inherit_option AND memberships.set_option AND NOT memberships.admin_option)
       FROM pg_catalog.pg_auth_members memberships
       WHERE memberships.member=login.oid AND memberships.roleid=effective.oid),false) AS "loginMembershipOptionsSafe",
      (SELECT count(*)::integer FROM pg_catalog.pg_auth_members memberships
       WHERE memberships.roleid=effective.oid) AS "effectiveMemberCount",
      (SELECT count(*)::integer FROM pg_catalog.pg_auth_members memberships
       WHERE memberships.member=login.oid AND memberships.admin_option) AS "loginAdminOptionCount",
      (SELECT count(*)::integer FROM pg_catalog.pg_auth_members memberships
       WHERE memberships.member=effective.oid AND memberships.admin_option) AS "effectiveAdminOptionCount",
      (SELECT count(*)::integer FROM (
        WITH RECURSIVE role_closure(roleid) AS (
          SELECT memberships.roleid FROM pg_catalog.pg_auth_members memberships WHERE memberships.member=login.oid
          UNION
          SELECT memberships.roleid FROM pg_catalog.pg_auth_members memberships
          JOIN role_closure closure ON memberships.member=closure.roleid
        ) SELECT DISTINCT roleid FROM role_closure
      ) login_closure) AS "loginMembershipClosureCount",
      (SELECT count(*)::integer FROM (
        WITH RECURSIVE role_closure(roleid) AS (
          SELECT memberships.roleid FROM pg_catalog.pg_auth_members memberships WHERE memberships.member=effective.oid
          UNION
          SELECT memberships.roleid FROM pg_catalog.pg_auth_members memberships
          JOIN role_closure closure ON memberships.member=closure.roleid
        ) SELECT DISTINCT roleid FROM role_closure
      ) effective_closure) AS "effectiveMembershipClosureCount",
      pg_catalog.has_table_privilege(current_user,'public.rate_limit_buckets','SELECT') AS "rateLimitSelect",
      pg_catalog.has_table_privilege(current_user,'public.rate_limit_buckets','INSERT') AS "rateLimitInsert",
      pg_catalog.has_table_privilege(current_user,'public.rate_limit_buckets','UPDATE') AS "rateLimitUpdate",
      pg_catalog.has_table_privilege(current_user,'public.rate_limit_buckets','DELETE') AS "rateLimitDelete",
      pg_catalog.has_function_privilege(current_user,'public.nova_rate_limit_record(text,timestamptz)','EXECUTE') AS "rateLimitCounterExecute",
      pg_catalog.has_function_privilege(current_user,'public.nova_auth_bootstrap_identity(text)','EXECUTE') AS "authBootstrapExecute",
      EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc helper
        JOIN pg_catalog.pg_roles helper_owner ON helper_owner.oid=helper.proowner
        JOIN pg_catalog.pg_language helper_language ON helper_language.oid=helper.prolang
        JOIN pg_catalog.pg_roles allowed_runtime ON allowed_runtime.rolname='nova_fastify_runtime'
        WHERE helper.oid=pg_catalog.to_regprocedure('public.nova_auth_bootstrap_identity(text)')
          AND helper_language.lanname='plpgsql' AND helper.provolatile='v'
          AND helper.prosecdef AND helper.proconfig @> ARRAY['search_path=pg_catalog']
          AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(helper.prosrc,'UTF8')),'hex')='${securityDefinerBodySha256.authBootstrap}'
          AND helper_owner.rolname='nova_auth_identity_owner'
          AND NOT helper_owner.rolcanlogin AND NOT helper_owner.rolinherit
          AND NOT helper_owner.rolsuper AND NOT helper_owner.rolbypassrls
          AND NOT helper_owner.rolcreaterole AND NOT helper_owner.rolcreatedb AND NOT helper_owner.rolreplication
          AND pg_catalog.has_schema_privilege(helper_owner.oid,'public','USAGE')
          AND NOT pg_catalog.has_schema_privilege(helper_owner.oid,'public','CREATE')
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members memberships
            WHERE memberships.member=helper_owner.oid OR memberships.roleid=helper_owner.oid)
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_namespace extra_schema
            WHERE extra_schema.nspname NOT IN ('public','information_schema','pg_catalog','pg_toast')
              AND extra_schema.nspname !~ '^pg_temp_[0-9]+$'
              AND extra_schema.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND (pg_catalog.has_schema_privilege(helper_owner.oid,extra_schema.oid,'USAGE')
                OR pg_catalog.has_schema_privilege(helper_owner.oid,extra_schema.oid,'CREATE'))
          )
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_class extra_relation
            JOIN pg_catalog.pg_namespace extra_schema ON extra_schema.oid=extra_relation.relnamespace
            WHERE extra_schema.nspname NOT IN ('public','information_schema','pg_catalog','pg_toast')
              AND extra_schema.nspname !~ '^pg_temp_[0-9]+$'
              AND extra_schema.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND ((extra_relation.relkind='S' AND (
                    pg_catalog.has_sequence_privilege(helper_owner.oid,extra_relation.oid,'USAGE')
                    OR pg_catalog.has_sequence_privilege(helper_owner.oid,extra_relation.oid,'SELECT')
                    OR pg_catalog.has_sequence_privilege(helper_owner.oid,extra_relation.oid,'UPDATE')))
                OR (extra_relation.relkind IN ('r','p','v','m','f') AND (
                    pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'SELECT')
                    OR pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'INSERT')
                    OR pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'UPDATE')
                    OR pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'DELETE')
                    OR pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'TRUNCATE')
                    OR pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'REFERENCES')
                    OR pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'TRIGGER')
                    OR pg_catalog.has_any_column_privilege(helper_owner.oid,extra_relation.oid,'SELECT')
                    OR pg_catalog.has_any_column_privilege(helper_owner.oid,extra_relation.oid,'INSERT')
                    OR pg_catalog.has_any_column_privilege(helper_owner.oid,extra_relation.oid,'UPDATE')
                    OR pg_catalog.has_any_column_privilege(helper_owner.oid,extra_relation.oid,'REFERENCES'))))
          )
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_proc extra_function
            JOIN pg_catalog.pg_namespace extra_schema ON extra_schema.oid=extra_function.pronamespace
            WHERE extra_schema.nspname NOT IN ('public','information_schema','pg_catalog','pg_toast')
              AND extra_schema.nspname !~ '^pg_temp_[0-9]+$'
              AND extra_schema.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND pg_catalog.has_function_privilege(helper_owner.oid,extra_function.oid,'EXECUTE')
          )
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_class relation
            WHERE relation.relnamespace='public'::regnamespace
              AND relation.relkind IN ('r','p','v','m','f')
              AND (pg_catalog.has_table_privilege(helper_owner.oid,relation.oid,'SELECT')
                OR pg_catalog.has_table_privilege(helper_owner.oid,relation.oid,'INSERT')
                OR pg_catalog.has_table_privilege(helper_owner.oid,relation.oid,'UPDATE')
                OR pg_catalog.has_table_privilege(helper_owner.oid,relation.oid,'DELETE')
                OR pg_catalog.has_table_privilege(helper_owner.oid,relation.oid,'TRUNCATE')
                OR pg_catalog.has_table_privilege(helper_owner.oid,relation.oid,'REFERENCES')
                OR pg_catalog.has_table_privilege(helper_owner.oid,relation.oid,'TRIGGER')
                OR (relation.oid='public.users'::regclass AND (
                  pg_catalog.has_any_column_privilege(helper_owner.oid,relation.oid,'UPDATE')
                  OR pg_catalog.has_any_column_privilege(helper_owner.oid,relation.oid,'REFERENCES')
                  OR EXISTS (
                    SELECT 1 FROM pg_catalog.pg_attribute column_info
                    WHERE column_info.attrelid=relation.oid AND column_info.attnum>0 AND NOT column_info.attisdropped
                      AND ((column_info.attname NOT IN ('id','auth_subject','username','role','status')
                            AND pg_catalog.has_column_privilege(helper_owner.oid,relation.oid,column_info.attname,'SELECT'))
                        OR (column_info.attname NOT IN ('auth_subject','username','username_normalized')
                            AND pg_catalog.has_column_privilege(helper_owner.oid,relation.oid,column_info.attname,'INSERT')))
                  )
                ))
                OR (relation.oid<>'public.users'::regclass AND (
                  pg_catalog.has_any_column_privilege(helper_owner.oid,relation.oid,'SELECT')
                  OR pg_catalog.has_any_column_privilege(helper_owner.oid,relation.oid,'INSERT')
                  OR pg_catalog.has_any_column_privilege(helper_owner.oid,relation.oid,'UPDATE')
                  OR pg_catalog.has_any_column_privilege(helper_owner.oid,relation.oid,'REFERENCES')
                )))
          )
          AND pg_catalog.has_column_privilege(helper_owner.oid,'public.users','id','SELECT')
          AND pg_catalog.has_column_privilege(helper_owner.oid,'public.users','auth_subject','SELECT')
          AND pg_catalog.has_column_privilege(helper_owner.oid,'public.users','username','SELECT')
          AND pg_catalog.has_column_privilege(helper_owner.oid,'public.users','role','SELECT')
          AND pg_catalog.has_column_privilege(helper_owner.oid,'public.users','status','SELECT')
          AND pg_catalog.has_column_privilege(helper_owner.oid,'public.users','auth_subject','INSERT')
          AND pg_catalog.has_column_privilege(helper_owner.oid,'public.users','username','INSERT')
          AND pg_catalog.has_column_privilege(helper_owner.oid,'public.users','username_normalized','INSERT')
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_class sequence_relation
            WHERE sequence_relation.relnamespace='public'::regnamespace AND sequence_relation.relkind='S'
              AND (pg_catalog.has_sequence_privilege(helper_owner.oid,sequence_relation.oid,'USAGE')
                OR pg_catalog.has_sequence_privilege(helper_owner.oid,sequence_relation.oid,'SELECT')
                OR pg_catalog.has_sequence_privilege(helper_owner.oid,sequence_relation.oid,'UPDATE'))
          )
          AND EXISTS (
            SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
            WHERE acl.grantee=allowed_runtime.oid AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
          )
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.aclexplode(COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
            WHERE acl.privilege_type='EXECUTE'
              AND (acl.grantee NOT IN (helper.proowner,allowed_runtime.oid) OR acl.is_grantable)
          )
      ) AS "authBootstrapDefinerSafe",
      EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc counter
        JOIN pg_catalog.pg_roles counter_owner ON counter_owner.oid=counter.proowner
        JOIN pg_catalog.pg_language counter_language ON counter_language.oid=counter.prolang
        JOIN pg_catalog.pg_roles allowed_limiter ON allowed_limiter.rolname='nova_rate_limiter_runtime'
        WHERE counter.oid=pg_catalog.to_regprocedure('public.nova_rate_limit_record(text,timestamptz)')
          AND counter_language.lanname='plpgsql' AND counter.provolatile='v'
          AND counter.prosecdef AND counter.proconfig @> ARRAY['search_path=pg_catalog']
          AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(counter.prosrc,'UTF8')),'hex')='${securityDefinerBodySha256.rateLimitCounter}'
          AND counter_owner.rolname='nova_rate_limit_counter_owner'
          AND NOT counter_owner.rolcanlogin AND NOT counter_owner.rolinherit
          AND NOT counter_owner.rolsuper AND NOT counter_owner.rolbypassrls
          AND NOT counter_owner.rolcreaterole AND NOT counter_owner.rolcreatedb AND NOT counter_owner.rolreplication
          AND pg_catalog.has_schema_privilege(counter_owner.oid,'public','USAGE')
          AND NOT pg_catalog.has_schema_privilege(counter_owner.oid,'public','CREATE')
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members memberships
            WHERE memberships.member=counter_owner.oid OR memberships.roleid=counter_owner.oid)
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_namespace extra_schema
            WHERE extra_schema.nspname NOT IN ('public','information_schema','pg_catalog','pg_toast')
              AND extra_schema.nspname !~ '^pg_temp_[0-9]+$'
              AND extra_schema.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND (pg_catalog.has_schema_privilege(counter_owner.oid,extra_schema.oid,'USAGE')
                OR pg_catalog.has_schema_privilege(counter_owner.oid,extra_schema.oid,'CREATE'))
          )
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_class extra_relation
            JOIN pg_catalog.pg_namespace extra_schema ON extra_schema.oid=extra_relation.relnamespace
            WHERE extra_schema.nspname NOT IN ('public','information_schema','pg_catalog','pg_toast')
              AND extra_schema.nspname !~ '^pg_temp_[0-9]+$'
              AND extra_schema.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND ((extra_relation.relkind='S' AND (
                    pg_catalog.has_sequence_privilege(counter_owner.oid,extra_relation.oid,'USAGE')
                    OR pg_catalog.has_sequence_privilege(counter_owner.oid,extra_relation.oid,'SELECT')
                    OR pg_catalog.has_sequence_privilege(counter_owner.oid,extra_relation.oid,'UPDATE')))
                OR (extra_relation.relkind IN ('r','p','v','m','f') AND (
                    pg_catalog.has_table_privilege(counter_owner.oid,extra_relation.oid,'SELECT')
                    OR pg_catalog.has_table_privilege(counter_owner.oid,extra_relation.oid,'INSERT')
                    OR pg_catalog.has_table_privilege(counter_owner.oid,extra_relation.oid,'UPDATE')
                    OR pg_catalog.has_table_privilege(counter_owner.oid,extra_relation.oid,'DELETE')
                    OR pg_catalog.has_table_privilege(counter_owner.oid,extra_relation.oid,'TRUNCATE')
                    OR pg_catalog.has_table_privilege(counter_owner.oid,extra_relation.oid,'REFERENCES')
                    OR pg_catalog.has_table_privilege(counter_owner.oid,extra_relation.oid,'TRIGGER')
                    OR pg_catalog.has_any_column_privilege(counter_owner.oid,extra_relation.oid,'SELECT')
                    OR pg_catalog.has_any_column_privilege(counter_owner.oid,extra_relation.oid,'INSERT')
                    OR pg_catalog.has_any_column_privilege(counter_owner.oid,extra_relation.oid,'UPDATE')
                    OR pg_catalog.has_any_column_privilege(counter_owner.oid,extra_relation.oid,'REFERENCES'))))
          )
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_proc extra_function
            JOIN pg_catalog.pg_namespace extra_schema ON extra_schema.oid=extra_function.pronamespace
            WHERE extra_schema.nspname NOT IN ('public','information_schema','pg_catalog','pg_toast')
              AND extra_schema.nspname !~ '^pg_temp_[0-9]+$'
              AND extra_schema.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND pg_catalog.has_function_privilege(counter_owner.oid,extra_function.oid,'EXECUTE')
          )
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_class relation
            WHERE relation.relnamespace='public'::regnamespace
              AND relation.relkind IN ('r','p','v','m','f')
              AND (pg_catalog.has_table_privilege(counter_owner.oid,relation.oid,'SELECT')
                OR pg_catalog.has_table_privilege(counter_owner.oid,relation.oid,'INSERT')
                OR pg_catalog.has_table_privilege(counter_owner.oid,relation.oid,'UPDATE')
                OR pg_catalog.has_table_privilege(counter_owner.oid,relation.oid,'DELETE')
                OR pg_catalog.has_table_privilege(counter_owner.oid,relation.oid,'TRUNCATE')
                OR pg_catalog.has_table_privilege(counter_owner.oid,relation.oid,'REFERENCES')
                OR pg_catalog.has_table_privilege(counter_owner.oid,relation.oid,'TRIGGER')
                OR (relation.oid='public.rate_limit_buckets'::regclass AND (
                  pg_catalog.has_any_column_privilege(counter_owner.oid,relation.oid,'REFERENCES')
                  OR EXISTS (
                    SELECT 1 FROM pg_catalog.pg_attribute column_info
                    WHERE column_info.attrelid=relation.oid AND column_info.attnum>0 AND NOT column_info.attisdropped
                      AND ((column_info.attname NOT IN ('bucket_key','window_start','hits')
                            AND (pg_catalog.has_column_privilege(counter_owner.oid,relation.oid,column_info.attname,'SELECT')
                              OR pg_catalog.has_column_privilege(counter_owner.oid,relation.oid,column_info.attname,'INSERT')))
                        OR (column_info.attname NOT IN ('window_start','hits')
                            AND pg_catalog.has_column_privilege(counter_owner.oid,relation.oid,column_info.attname,'UPDATE')))
                  )
                ))
                OR (relation.oid<>'public.rate_limit_buckets'::regclass AND (
                  pg_catalog.has_any_column_privilege(counter_owner.oid,relation.oid,'SELECT')
                  OR pg_catalog.has_any_column_privilege(counter_owner.oid,relation.oid,'INSERT')
                  OR pg_catalog.has_any_column_privilege(counter_owner.oid,relation.oid,'UPDATE')
                  OR pg_catalog.has_any_column_privilege(counter_owner.oid,relation.oid,'REFERENCES')
                )))
          )
          AND pg_catalog.has_column_privilege(counter_owner.oid,'public.rate_limit_buckets','bucket_key','SELECT')
          AND pg_catalog.has_column_privilege(counter_owner.oid,'public.rate_limit_buckets','window_start','SELECT')
          AND pg_catalog.has_column_privilege(counter_owner.oid,'public.rate_limit_buckets','hits','SELECT')
          AND pg_catalog.has_column_privilege(counter_owner.oid,'public.rate_limit_buckets','bucket_key','INSERT')
          AND pg_catalog.has_column_privilege(counter_owner.oid,'public.rate_limit_buckets','window_start','INSERT')
          AND pg_catalog.has_column_privilege(counter_owner.oid,'public.rate_limit_buckets','hits','INSERT')
          AND pg_catalog.has_column_privilege(counter_owner.oid,'public.rate_limit_buckets','window_start','UPDATE')
          AND pg_catalog.has_column_privilege(counter_owner.oid,'public.rate_limit_buckets','hits','UPDATE')
          AND NOT pg_catalog.has_column_privilege(counter_owner.oid,'public.rate_limit_buckets','bucket_key','UPDATE')
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_class sequence_relation
            WHERE sequence_relation.relnamespace='public'::regnamespace AND sequence_relation.relkind='S'
              AND (pg_catalog.has_sequence_privilege(counter_owner.oid,sequence_relation.oid,'USAGE')
                OR pg_catalog.has_sequence_privilege(counter_owner.oid,sequence_relation.oid,'SELECT')
                OR pg_catalog.has_sequence_privilege(counter_owner.oid,sequence_relation.oid,'UPDATE'))
          )
          AND EXISTS (
            SELECT 1 FROM pg_catalog.aclexplode(COALESCE(counter.proacl,pg_catalog.acldefault('f',counter.proowner))) acl
            WHERE acl.grantee=allowed_limiter.oid AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
          )
          AND NOT EXISTS (
            SELECT 1 FROM pg_catalog.aclexplode(COALESCE(counter.proacl,pg_catalog.acldefault('f',counter.proowner))) acl
            WHERE acl.privilege_type='EXECUTE'
              AND (acl.grantee NOT IN (counter.proowner,allowed_limiter.oid) OR acl.is_grantable)
          )
      ) AS "rateLimitCounterDefinerSafe",
      pg_catalog.has_table_privilege(current_user,'public.users','INSERT') AS "usersInsert",
      pg_catalog.has_any_column_privilege(current_user,'public.users','INSERT') AS "usersAnyInsert",
      pg_catalog.has_column_privilege(current_user,'public.users','auth_subject','SELECT') AS "authSubjectSelect",
      pg_catalog.has_column_privilege(current_user,'public.users','auth_subject','INSERT') AS "authSubjectInsert",
      pg_catalog.has_table_privilege(current_user,'public.moderation_actions','INSERT') AS "actionInsert",
      pg_catalog.has_column_privilege(current_user,'public.moderation_actions','reason','INSERT') AS "actionReasonInsert",
      pg_catalog.has_column_privilege(current_user,'public.media_key_revocations','id','SELECT') AS "queueSelectId",
      pg_catalog.has_column_privilege(current_user,'public.media_key_revocations','media_id','SELECT') AS "queueSelectMediaId",
      pg_catalog.has_column_privilege(current_user,'public.media_key_revocations','source_key','SELECT') AS "queueSelectSourceKey",
      pg_catalog.has_column_privilege(current_user,'public.media_key_revocations','moderation_action_id','SELECT') AS "queueSelectActionId",
      pg_catalog.has_column_privilege(current_user,'public.media_key_revocations','attempt_count','SELECT') AS "queueSelectAttemptCount",
      pg_catalog.has_column_privilege(current_user,'public.media_key_revocations','retry_after','SELECT') AS "queueSelectRetryAfter",
      pg_catalog.has_column_privilege(current_user,'public.media_key_revocations','created_at','SELECT') AS "queueSelectCreatedAt",
      pg_catalog.has_column_privilege(current_user,'public.media_key_revocations','escalated_at','SELECT') AS "queueSelectEscalatedAt",
      pg_catalog.has_table_privilege(current_user,'public.media_key_revocations','INSERT') AS "queueInsert",
      pg_catalog.has_table_privilege(current_user,'public.media_key_revocations','DELETE') AS "queueDelete",
      pg_catalog.has_column_privilege(current_user,'public.media_key_revocations','attempt_count','UPDATE') AS "queueUpdateAttemptCount",
      pg_catalog.has_column_privilege(current_user,'public.media_key_revocations','retry_after','UPDATE') AS "queueUpdateRetryAfter",
      pg_catalog.has_column_privilege(current_user,'public.media_key_revocations','escalated_at','UPDATE') AS "queueUpdateEscalatedAt",
      pg_catalog.has_table_privilege(current_user,'public.media_key_revocations','UPDATE') AS "queueUpdateTable",
      EXISTS (SELECT 1 FROM pg_catalog.pg_attribute queue_column
        WHERE queue_column.attrelid='public.media_key_revocations'::regclass
          AND queue_column.attnum>0 AND NOT queue_column.attisdropped
          AND queue_column.attname NOT IN ('attempt_count','retry_after','escalated_at')
          AND pg_catalog.has_column_privilege(current_user,'public.media_key_revocations',queue_column.attname,'UPDATE'))
        AS "queueUpdateUnexpected",
      EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class worker_relation
        JOIN pg_catalog.pg_namespace worker_namespace ON worker_namespace.oid=worker_relation.relnamespace
        WHERE worker_namespace.nspname NOT IN ('information_schema','pg_catalog','pg_toast')
          AND worker_namespace.nspname !~ '^pg_temp_[0-9]+$'
          AND worker_namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
          AND worker_relation.relkind IN ('r','p','v','f')
          AND (
            pg_catalog.has_table_privilege(current_user,worker_relation.oid,'UPDATE')
            OR EXISTS (
              SELECT 1 FROM pg_catalog.pg_attribute worker_column
              WHERE worker_column.attrelid=worker_relation.oid
                AND worker_column.attnum>0 AND NOT worker_column.attisdropped
                AND pg_catalog.has_column_privilege(current_user,worker_relation.oid,worker_column.attname,'UPDATE')
                AND NOT (worker_relation.oid='public.media_key_revocations'::regclass
                  AND worker_column.attname IN ('attempt_count','retry_after','escalated_at'))
            )
          )
      ) AS "workerHasUnexpectedUpdate",
      pg_catalog.has_table_privilege(current_user,'public.moderation_actions','UPDATE') AS "actionUpdate",
      CASE WHEN current_user='nova_fastify_runtime' THEN
             pg_catalog.pg_has_role(current_user,'nova_rate_limiter_runtime','MEMBER') OR pg_catalog.pg_has_role(current_user,'nova_media_revocation_worker','MEMBER')
           WHEN current_user='nova_rate_limiter_runtime' THEN
             pg_catalog.pg_has_role(current_user,'nova_fastify_runtime','MEMBER') OR pg_catalog.pg_has_role(current_user,'nova_media_revocation_worker','MEMBER')
           WHEN current_user='nova_media_revocation_worker' THEN
             pg_catalog.pg_has_role(current_user,'nova_fastify_runtime','MEMBER') OR pg_catalog.pg_has_role(current_user,'nova_rate_limiter_runtime','MEMBER')
           ELSE true END AS "canAssumeOtherRuntime",
      CASE WHEN current_user='nova_fastify_runtime' THEN
             pg_catalog.pg_has_role(current_user,'nova_rate_limiter_runtime','SET') OR pg_catalog.pg_has_role(current_user,'nova_media_revocation_worker','SET')
           WHEN current_user='nova_rate_limiter_runtime' THEN
             pg_catalog.pg_has_role(current_user,'nova_fastify_runtime','SET') OR pg_catalog.pg_has_role(current_user,'nova_media_revocation_worker','SET')
           WHEN current_user='nova_media_revocation_worker' THEN
             pg_catalog.pg_has_role(current_user,'nova_fastify_runtime','SET') OR pg_catalog.pg_has_role(current_user,'nova_rate_limiter_runtime','SET')
           ELSE true END AS "canSetOtherRuntime",
      EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace namespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(
          COALESCE(namespace.nspacl,pg_catalog.acldefault('n',namespace.nspowner))
        ) acl
        WHERE namespace.nspname='public' AND acl.grantee=0
          AND acl.privilege_type IN ('USAGE','CREATE')
      ) AS "publicSchemaPublicGrant"
    FROM pg_catalog.pg_roles effective
    JOIN pg_catalog.pg_roles login ON login.rolname=session_user
      WHERE effective.rolname=current_user`;

  // This is the intended deployed public contract, not a claim that a canonical migration exists yet.
  // Disposable fixtures mirror it only so local validation can run; missing production objects fail closed.
  const moderationRuntimeContractQuery = `
    WITH required_functions(signature) AS (VALUES
      ('public.nova_moderate_hide_story(uuid,text)'),
      ('public.nova_moderate_restore_story(uuid,uuid,text)'),
      ('public.nova_enqueue_media_key_revocation(uuid,uuid,text,text)'),
      ('public.nova_rls_own_media_revocation_pending(uuid)'),
      ('public.nova_rls_valid_moderation_action(uuid)'),
      ('public.nova_rls_actor_active()'),
      ('public.nova_rls_actor_has_role(text[])'),
      ('public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)')
    ), required_columns(column_name) AS (VALUES
      ('action_id'),('target_story_id'),('result'),('recorded_by'),('recorded_at')
    ), runtime_relation AS (
      SELECT relation.oid,relation.relkind,relation.relrowsecurity,relation.relforcerowsecurity
      FROM pg_catalog.pg_class relation
      JOIN pg_catalog.pg_namespace relation_schema ON relation_schema.oid=relation.relnamespace
      WHERE relation_schema.nspname='public' AND relation.relname='media_no_media_required'
    ), missing(item) AS (
      SELECT signature FROM required_functions WHERE pg_catalog.to_regprocedure(signature) IS NULL
      UNION ALL
      SELECT 'public.media_no_media_required'
      WHERE NOT EXISTS (SELECT 1 FROM runtime_relation WHERE relkind IN ('r','p'))
      UNION ALL
      SELECT 'public.media_no_media_required (ENABLE/FORCE ROW LEVEL SECURITY)'
      WHERE EXISTS (SELECT 1 FROM runtime_relation WHERE relkind IN ('r','p')
        AND NOT (relrowsecurity AND relforcerowsecurity))
      UNION ALL
      SELECT 'public.media_no_media_required.'||required_columns.column_name
      FROM required_columns
      WHERE EXISTS (SELECT 1 FROM runtime_relation WHERE relkind IN ('r','p'))
        AND NOT EXISTS (SELECT 1 FROM runtime_relation
          JOIN pg_catalog.pg_attribute column_info ON column_info.attrelid=runtime_relation.oid
          WHERE column_info.attname=required_columns.column_name
            AND column_info.attnum>0 AND NOT column_info.attisdropped)
    )
    SELECT COALESCE(pg_catalog.array_agg(item ORDER BY item),ARRAY[]::text[]) AS missing
    FROM missing`;

  const moderationDefinerQuery = `
    WITH expected(signature,owner_name,executor_names,body_sha256,language_name,expected_volatility) AS (VALUES
      ('public.nova_moderate_hide_story(uuid,text)','nova_story_moderation_manager',ARRAY['nova_fastify_runtime']::text[],'${securityDefinerBodySha256.moderateHideStory}','plpgsql','v'),
      ('public.nova_moderate_restore_story(uuid,uuid,text)','nova_story_moderation_manager',ARRAY['nova_fastify_runtime']::text[],'${securityDefinerBodySha256.moderateRestoreStory}','plpgsql','v'),
      ('public.nova_enqueue_media_key_revocation(uuid,uuid,text,text)','nova_revocation_enqueuer_owner',ARRAY['nova_fastify_runtime']::text[],'${securityDefinerBodySha256.enqueueMediaKeyRevocation}','plpgsql','v'),
      ('public.nova_rls_own_media_revocation_pending(uuid)','nova_media_state_predicate_owner',ARRAY['nova_fastify_runtime']::text[],'${securityDefinerBodySha256.ownMediaRevocationPending}','sql','s'),
      ('public.nova_rls_valid_moderation_action(uuid)','nova_action_predicate_owner',ARRAY['nova_revocation_enqueuer_owner']::text[],'${securityDefinerBodySha256.validModerationAction}','plpgsql','v'),
      ('public.nova_rls_actor_active()','nova_actor_predicate_owner',ARRAY['nova_fastify_runtime','nova_media_state_predicate_owner','nova_revocation_enqueuer_owner','nova_story_moderation_manager','nova_story_lifecycle_manager','nova_media_lifecycle_manager']::text[],'${securityDefinerBodySha256.actorActive}','sql','s'),
      ('public.nova_rls_actor_has_role(text[])','nova_actor_predicate_owner',ARRAY['nova_fastify_runtime','nova_media_state_predicate_owner','nova_revocation_enqueuer_owner','nova_story_moderation_manager','nova_story_lifecycle_manager','nova_media_lifecycle_manager']::text[],'${securityDefinerBodySha256.actorHasRole}','sql','s'),
      ('public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)','nova_media_predicate_owner',ARRAY['nova_media_revocation_worker','nova_reports_predicate_owner','nova_media_purge_verifier','nova_media_purge_attester','nova_media_removal_authority']::text[],'${securityDefinerBodySha256.mediaRevocationWorkerPredicate}','plpgsql','v')
    ),
    allowed_application_schemas(schema_name) AS (VALUES ('public')),
    allowed_system_schemas(schema_name) AS (VALUES ('information_schema'),('pg_catalog'),('pg_toast')),
    allowed_columns(owner_name,schema_name,relation_name,column_name,privilege_name) AS (VALUES
      ('nova_actor_predicate_owner','public','users','id','SELECT'),
      ('nova_actor_predicate_owner','public','users','auth_subject','SELECT'),
      ('nova_actor_predicate_owner','public','users','status','SELECT'),
      ('nova_actor_predicate_owner','public','users','role','SELECT'),
      ('nova_story_moderation_manager','public','stories','id','SELECT'),
      ('nova_story_moderation_manager','public','stories','author_id','SELECT'),
      ('nova_story_moderation_manager','public','stories','status','SELECT'),
      ('nova_story_moderation_manager','public','stories','visibility','SELECT'),
      ('nova_story_moderation_manager','public','stories','deleted_at','SELECT'),
      ('nova_story_moderation_manager','public','stories','version','SELECT'),
      ('nova_story_moderation_manager','public','stories','published_at','SELECT'),
      ('nova_story_moderation_manager','public','stories','title','SELECT'),
      ('nova_story_moderation_manager','public','stories','body','SELECT'),
      ('nova_story_moderation_manager','public','stories','cover_media_id','SELECT'),
      ('nova_story_moderation_manager','public','stories','comments_open','SELECT'),
      ('nova_story_moderation_manager','public','stories','id','REFERENCES'),
      ('nova_story_moderation_manager','public','stories','status','UPDATE'),
      ('nova_story_moderation_manager','public','stories','visibility','UPDATE'),
      ('nova_story_moderation_manager','public','stories','comments_open','UPDATE'),
      ('nova_story_moderation_manager','public','stories','published_at','UPDATE'),
      ('nova_story_moderation_manager','public','stories','version','UPDATE'),
      ('nova_story_moderation_manager','public','stories','updated_at','UPDATE'),
      ('nova_story_moderation_manager','public','moderation_actions','id','SELECT'),
      ('nova_story_moderation_manager','public','moderation_actions','moderator_id','SELECT'),
      ('nova_story_moderation_manager','public','moderation_actions','target_type','SELECT'),
      ('nova_story_moderation_manager','public','moderation_actions','target_id','SELECT'),
      ('nova_story_moderation_manager','public','moderation_actions','action','SELECT'),
      ('nova_story_moderation_manager','public','moderation_actions','metadata','SELECT'),
      ('nova_story_moderation_manager','public','moderation_actions','created_at','SELECT'),
      ('nova_story_moderation_manager','public','moderation_actions','id','REFERENCES'),
      ('nova_story_moderation_manager','public','moderation_actions','id','INSERT'),
      ('nova_story_moderation_manager','public','moderation_actions','moderator_id','INSERT'),
      ('nova_story_moderation_manager','public','moderation_actions','target_type','INSERT'),
      ('nova_story_moderation_manager','public','moderation_actions','target_id','INSERT'),
      ('nova_story_moderation_manager','public','moderation_actions','action','INSERT'),
      ('nova_story_moderation_manager','public','moderation_actions','reason','INSERT'),
      ('nova_story_moderation_manager','public','moderation_actions','metadata','INSERT'),
      ('nova_story_moderation_manager','public','media_no_media_required','action_id','INSERT'),
      ('nova_story_moderation_manager','public','media_no_media_required','target_story_id','INSERT'),
      ('nova_story_moderation_manager','public','media_no_media_required','result','INSERT'),
      ('nova_story_moderation_manager','public','media_no_media_required','recorded_by','INSERT'),
      ('nova_story_moderation_manager','public','media_no_media_required','recorded_at','INSERT'),
      ('nova_media_state_predicate_owner','public','media_assets','id','SELECT'),
      ('nova_media_state_predicate_owner','public','media_assets','owner_id','SELECT'),
      ('nova_media_state_predicate_owner','public','media_key_revocations','media_id','SELECT'),
      ('nova_media_predicate_owner','public','moderation_actions','id','SELECT'),
      ('nova_media_predicate_owner','public','moderation_actions','action','SELECT'),
      ('nova_media_predicate_owner','public','moderation_actions','target_type','SELECT'),
      ('nova_media_predicate_owner','public','moderation_actions','target_id','SELECT'),
      ('nova_media_predicate_owner','public','media_assets','id','SELECT'),
      ('nova_media_predicate_owner','public','media_assets','owner_id','SELECT'),
      ('nova_media_predicate_owner','public','media_assets','purpose','SELECT'),
      ('nova_media_predicate_owner','public','media_assets','status','SELECT'),
      ('nova_media_predicate_owner','public','media_assets','mime_type','SELECT'),
      ('nova_media_predicate_owner','public','media_key_revocations','id','SELECT'),
      ('nova_media_predicate_owner','public','media_key_revocations','media_id','SELECT'),
      ('nova_media_predicate_owner','public','media_key_revocations','source_key','SELECT'),
      ('nova_media_predicate_owner','public','media_key_revocations','moderation_action_id','SELECT'),
      ('nova_media_predicate_owner','public','stories','id','SELECT'),
      ('nova_media_predicate_owner','public','stories','author_id','SELECT'),
      ('nova_media_predicate_owner','public','stories','cover_media_id','SELECT'),
      ('nova_media_predicate_owner','public','stories','status','SELECT'),
      ('nova_media_predicate_owner','public','stories','visibility','SELECT'),
      ('nova_media_predicate_owner','public','stories','deleted_at','SELECT'),
      ('nova_revocation_enqueuer_owner','public','moderation_actions','id','SELECT'),
      ('nova_revocation_enqueuer_owner','public','moderation_actions','moderator_id','SELECT'),
      ('nova_revocation_enqueuer_owner','public','moderation_actions','target_type','SELECT'),
      ('nova_revocation_enqueuer_owner','public','moderation_actions','target_id','SELECT'),
      ('nova_revocation_enqueuer_owner','public','moderation_actions','action','SELECT'),
      ('nova_revocation_enqueuer_owner','public','media_assets','id','SELECT'),
      ('nova_revocation_enqueuer_owner','public','media_assets','owner_id','SELECT'),
      ('nova_revocation_enqueuer_owner','public','media_assets','purpose','SELECT'),
      ('nova_revocation_enqueuer_owner','public','media_assets','object_key','SELECT'),
      ('nova_revocation_enqueuer_owner','public','media_assets','mime_type','SELECT'),
      ('nova_revocation_enqueuer_owner','public','media_assets','status','SELECT'),
      ('nova_revocation_enqueuer_owner','public','media_assets','object_key','UPDATE'),
      ('nova_revocation_enqueuer_owner','public','media_assets','updated_at','UPDATE'),
      ('nova_revocation_enqueuer_owner','public','stories','id','SELECT'),
      ('nova_revocation_enqueuer_owner','public','stories','author_id','SELECT'),
      ('nova_revocation_enqueuer_owner','public','stories','cover_media_id','SELECT'),
      ('nova_revocation_enqueuer_owner','public','stories','status','SELECT'),
      ('nova_revocation_enqueuer_owner','public','stories','visibility','SELECT'),
      ('nova_revocation_enqueuer_owner','public','stories','deleted_at','SELECT'),
      ('nova_revocation_enqueuer_owner','public','media_key_revocations','id','INSERT'),
      ('nova_revocation_enqueuer_owner','public','media_key_revocations','media_id','INSERT'),
      ('nova_revocation_enqueuer_owner','public','media_key_revocations','source_key','INSERT'),
      ('nova_revocation_enqueuer_owner','public','media_key_revocations','moderation_action_id','INSERT'),
      ('nova_revocation_enqueuer_owner','public','reports','id','SELECT'),
      ('nova_revocation_enqueuer_owner','public','reports','target_type','SELECT'),
      ('nova_revocation_enqueuer_owner','public','reports','target_id','SELECT'),
      ('nova_revocation_enqueuer_owner','public','reports','status','SELECT'),
      ('nova_revocation_enqueuer_owner','public','reports','removal_pending','SELECT'),
      ('nova_revocation_enqueuer_owner','public','reports','first_response_at','SELECT'),
      ('nova_revocation_enqueuer_owner','public','reports','closed_at','SELECT'),
      ('nova_revocation_enqueuer_owner','public','reports','reopen_count','SELECT'),
      ('nova_revocation_enqueuer_owner','public','reports','updated_at','SELECT'),
      ('nova_revocation_enqueuer_owner','public','reports','status','UPDATE'),
      ('nova_revocation_enqueuer_owner','public','reports','first_response_at','UPDATE'),
      ('nova_revocation_enqueuer_owner','public','reports','closed_at','UPDATE'),
      ('nova_revocation_enqueuer_owner','public','reports','reopen_count','UPDATE'),
      ('nova_revocation_enqueuer_owner','public','reports','updated_at','UPDATE'),
      ('nova_revocation_enqueuer_owner','public','reports','removal_pending','UPDATE')
      ,('nova_action_predicate_owner','public','moderation_actions','id','SELECT')
      ,('nova_action_predicate_owner','public','moderation_actions','action','SELECT')
      ,('nova_action_predicate_owner','public','moderation_actions','target_type','SELECT')
      ,('nova_action_predicate_owner','public','moderation_actions','target_id','SELECT')
      ,('nova_action_predicate_owner','public','stories','id','SELECT')
      ,('nova_action_predicate_owner','public','stories','status','SELECT')
      ,('nova_action_predicate_owner','public','stories','visibility','SELECT')
      ,('nova_action_predicate_owner','public','stories','deleted_at','SELECT')
    )
    SELECT NOT EXISTS (
      SELECT 1
      FROM expected specification
      LEFT JOIN pg_catalog.pg_proc helper ON helper.oid=pg_catalog.to_regprocedure(specification.signature)
      LEFT JOIN pg_catalog.pg_roles helper_owner ON helper_owner.oid=helper.proowner
      LEFT JOIN pg_catalog.pg_language helper_language ON helper_language.oid=helper.prolang
      CROSS JOIN pg_catalog.pg_roles runtime_role
      WHERE runtime_role.rolname='nova_fastify_runtime'
        AND (helper.oid IS NULL OR helper_owner.oid IS NULL
          OR EXISTS (SELECT 1 FROM pg_catalog.unnest(specification.executor_names) AS expected_executor(role_name)
            LEFT JOIN pg_catalog.pg_roles executor_role ON executor_role.rolname=expected_executor.role_name
            WHERE executor_role.oid IS NULL)
          OR helper_owner.rolname<>specification.owner_name
          OR helper.prosecdef IS NOT TRUE
          OR helper_language.lanname IS DISTINCT FROM specification.language_name
          OR helper.provolatile::text IS DISTINCT FROM specification.expected_volatility
          OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(helper.prosrc,'UTF8')),'hex') IS DISTINCT FROM specification.body_sha256
          OR helper.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']::text[]
          OR helper_owner.rolcanlogin OR helper_owner.rolinherit OR helper_owner.rolsuper OR helper_owner.rolbypassrls
          OR helper_owner.rolcreaterole OR helper_owner.rolcreatedb OR helper_owner.rolreplication
          OR NOT pg_catalog.has_schema_privilege(helper_owner.oid,'public','USAGE')
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace schema_info
            WHERE NOT EXISTS (SELECT 1 FROM allowed_application_schemas allowed_schema
                WHERE allowed_schema.schema_name=schema_info.nspname)
              AND NOT EXISTS (SELECT 1 FROM allowed_system_schemas system_schema
                WHERE system_schema.schema_name=schema_info.nspname)
              AND schema_info.nspname !~ '^pg_temp_[0-9]+$'
              AND schema_info.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND pg_catalog.has_schema_privilege(helper_owner.oid,schema_info.oid,'USAGE'))
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace schema_info
            WHERE pg_catalog.has_schema_privilege(helper_owner.oid,schema_info.oid,'CREATE'))
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_class extra_relation
            JOIN pg_catalog.pg_namespace extra_schema ON extra_schema.oid=extra_relation.relnamespace
            WHERE NOT EXISTS (SELECT 1 FROM allowed_application_schemas allowed_schema
                WHERE allowed_schema.schema_name=extra_schema.nspname)
              AND NOT EXISTS (SELECT 1 FROM allowed_system_schemas system_schema
                WHERE system_schema.schema_name=extra_schema.nspname)
              AND extra_schema.nspname !~ '^pg_temp_[0-9]+$'
              AND extra_schema.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND ((extra_relation.relkind='S' AND (
                    pg_catalog.has_sequence_privilege(helper_owner.oid,extra_relation.oid,'USAGE')
                    OR pg_catalog.has_sequence_privilege(helper_owner.oid,extra_relation.oid,'SELECT')
                    OR pg_catalog.has_sequence_privilege(helper_owner.oid,extra_relation.oid,'UPDATE')))
                OR (extra_relation.relkind IN ('r','p','v','m','f') AND (
                    pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'SELECT')
                    OR pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'INSERT')
                    OR pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'UPDATE')
                    OR pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'DELETE')
                    OR pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'TRUNCATE')
                    OR pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'REFERENCES')
                    OR pg_catalog.has_table_privilege(helper_owner.oid,extra_relation.oid,'TRIGGER')
                    OR pg_catalog.has_any_column_privilege(helper_owner.oid,extra_relation.oid,'SELECT')
                    OR pg_catalog.has_any_column_privilege(helper_owner.oid,extra_relation.oid,'INSERT')
                    OR pg_catalog.has_any_column_privilege(helper_owner.oid,extra_relation.oid,'UPDATE')
                    OR pg_catalog.has_any_column_privilege(helper_owner.oid,extra_relation.oid,'REFERENCES')))))
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc extra_function
            JOIN pg_catalog.pg_namespace extra_schema ON extra_schema.oid=extra_function.pronamespace
            WHERE NOT EXISTS (SELECT 1 FROM allowed_application_schemas allowed_schema
                WHERE allowed_schema.schema_name=extra_schema.nspname)
              AND NOT EXISTS (SELECT 1 FROM allowed_system_schemas system_schema
                WHERE system_schema.schema_name=extra_schema.nspname)
              AND extra_schema.nspname !~ '^pg_temp_[0-9]+$'
              AND extra_schema.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND pg_catalog.has_function_privilege(helper_owner.oid,extra_function.oid,'EXECUTE'))
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members memberships
            WHERE memberships.member=helper_owner.oid OR memberships.roleid=helper_owner.oid)
          OR (specification.signature NOT IN (
              'public.nova_rls_valid_moderation_action(uuid)',
              'public.nova_rls_actor_active()',
              'public.nova_rls_actor_has_role(text[])',
              'public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)') AND (
            pg_catalog.strpos(pg_catalog.regexp_replace(pg_catalog.lower(helper.prosrc),'[[:space:]]+','','g'),
              'pg_catalog.pg_has_role(session_user,''nova_fastify_runtime'',''set'')')=0
            OR pg_catalog.strpos(pg_catalog.regexp_replace(pg_catalog.lower(helper.prosrc),'[[:space:]]+','','g'),
              'public.nova_rls_actor_active()')=0
            OR pg_catalog.strpos(pg_catalog.regexp_replace(pg_catalog.lower(helper.prosrc),'[[:space:]]+','','g'),
              'public.nova_rls_actor_has_role(')=0))
          OR (specification.signature='public.nova_rls_valid_moderation_action(uuid)' AND (
            pg_catalog.strpos(pg_catalog.regexp_replace(pg_catalog.lower(helper.prosrc),'[[:space:]]+','','g'),
              'v_action.action=''hide_story''')=0
            OR pg_catalog.strpos(pg_catalog.regexp_replace(pg_catalog.lower(helper.prosrc),'[[:space:]]+','','g'),
              's.status::text=''removed''ands.visibility::text=''private''')=0))
          OR EXISTS (SELECT 1 FROM pg_catalog.unnest(specification.executor_names) AS expected_executor(role_name)
            JOIN pg_catalog.pg_roles executor_role ON executor_role.rolname=expected_executor.role_name
            WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(
                COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
              WHERE acl.grantee=executor_role.oid AND acl.privilege_type='EXECUTE'
                AND NOT acl.is_grantable))
          OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(
              COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
            WHERE acl.privilege_type='EXECUTE' AND acl.grantee<>helper.proowner
              AND (acl.is_grantable OR NOT EXISTS (
                  SELECT 1 FROM pg_catalog.unnest(specification.executor_names) AS expected_executor(role_name)
                  JOIN pg_catalog.pg_roles executor_role ON executor_role.rolname=expected_executor.role_name
                  WHERE executor_role.oid=acl.grantee)))
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_class relation
            JOIN pg_catalog.pg_namespace relation_schema ON relation_schema.oid=relation.relnamespace
            CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) table_privilege(privilege_name)
            WHERE relation_schema.nspname='public'
              AND relation.relkind IN ('r','p','v','m','f')
              AND pg_catalog.has_table_privilege(helper_owner.oid,relation.oid,table_privilege.privilege_name))
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_class relation
            JOIN pg_catalog.pg_namespace relation_schema ON relation_schema.oid=relation.relnamespace
            JOIN pg_catalog.pg_attribute column_info ON column_info.attrelid=relation.oid
            CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) column_privilege(privilege_name)
            WHERE relation_schema.nspname='public'
              AND relation.relkind IN ('r','p','v','m','f')
              AND column_info.attnum>0 AND NOT column_info.attisdropped
              AND pg_catalog.has_column_privilege(helper_owner.oid,relation.oid,column_info.attname,column_privilege.privilege_name)
              AND NOT EXISTS (SELECT 1 FROM allowed_columns allowed
                WHERE allowed.owner_name=helper_owner.rolname
                  AND allowed.schema_name=relation_schema.nspname
                  AND allowed.relation_name=relation.relname
                  AND allowed.column_name=column_info.attname
                  AND allowed.privilege_name=column_privilege.privilege_name))
          OR EXISTS (SELECT 1 FROM allowed_columns allowed
            LEFT JOIN pg_catalog.pg_namespace allowed_schema ON allowed_schema.nspname=allowed.schema_name
            LEFT JOIN pg_catalog.pg_class allowed_relation
              ON allowed_relation.relnamespace=allowed_schema.oid AND allowed_relation.relname=allowed.relation_name
            WHERE allowed.owner_name=helper_owner.rolname
              AND (allowed_relation.oid IS NULL
                OR NOT pg_catalog.has_column_privilege(helper_owner.oid,allowed_relation.oid,
                  allowed.column_name,allowed.privilege_name)))
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_class sequence_relation
            JOIN pg_catalog.pg_namespace sequence_schema ON sequence_schema.oid=sequence_relation.relnamespace
            WHERE sequence_schema.nspname='public' AND sequence_relation.relkind='S'
              AND (pg_catalog.has_sequence_privilege(helper_owner.oid,sequence_relation.oid,'USAGE')
                OR pg_catalog.has_sequence_privilege(helper_owner.oid,sequence_relation.oid,'SELECT')
                OR pg_catalog.has_sequence_privilege(helper_owner.oid,sequence_relation.oid,'UPDATE')))
        )
    ) AS safe`;

  const moderationActionPredicateQuery = `
    WITH allowed_application_schemas(schema_name) AS (VALUES ('public')),
    allowed_system_schemas(schema_name) AS (VALUES ('information_schema'),('pg_catalog'),('pg_toast')),
    allowed_columns(schema_name,relation_name,column_name,privilege_name) AS (VALUES
      ('public','moderation_actions','id','SELECT'),
      ('public','moderation_actions','action','SELECT'),
      ('public','moderation_actions','target_type','SELECT'),
      ('public','moderation_actions','target_id','SELECT'),
      ('public','stories','id','SELECT'),
      ('public','stories','status','SELECT'),
      ('public','stories','visibility','SELECT'),
      ('public','stories','deleted_at','SELECT')
    ), predicate AS (
      SELECT helper.oid,helper.prosrc,helper.prosecdef,helper.proconfig,helper.provolatile,
        helper_language.lanname AS language_name,
        helper.proacl,helper_owner.oid AS owner_oid,helper_owner.rolname AS owner_name,
        helper_owner.rolcanlogin,helper_owner.rolinherit,helper_owner.rolsuper,helper_owner.rolbypassrls,
        helper_owner.rolcreaterole,helper_owner.rolcreatedb,helper_owner.rolreplication,
        enqueuer.oid AS enqueuer_oid,
        pg_catalog.regexp_replace(pg_catalog.lower(helper.prosrc),'[[:space:]]+','','g') AS body
      FROM pg_catalog.pg_roles enqueuer
      LEFT JOIN pg_catalog.pg_proc helper
        ON helper.oid=pg_catalog.to_regprocedure('public.nova_rls_valid_moderation_action(uuid)')
      LEFT JOIN pg_catalog.pg_language helper_language ON helper_language.oid=helper.prolang
      LEFT JOIN pg_catalog.pg_roles helper_owner ON helper_owner.oid=helper.proowner
      WHERE enqueuer.rolname='nova_revocation_enqueuer_owner'
    )
    SELECT COALESCE(
      predicate.oid IS NOT NULL
      AND predicate.owner_name='nova_action_predicate_owner'
      AND predicate.prosecdef IS TRUE
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(predicate.prosrc,'UTF8')),'hex')='${securityDefinerBodySha256.validModerationAction}'
      AND predicate.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog']::text[]
      AND predicate.provolatile='v'
      AND predicate.language_name='plpgsql'
      AND NOT predicate.rolcanlogin AND NOT predicate.rolinherit
      AND NOT predicate.rolsuper AND NOT predicate.rolbypassrls
      AND NOT predicate.rolcreaterole AND NOT predicate.rolcreatedb AND NOT predicate.rolreplication
      AND pg_catalog.has_schema_privilege(predicate.owner_oid,'public','USAGE')
      AND NOT pg_catalog.has_schema_privilege(predicate.owner_oid,'public','CREATE')
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members memberships
        WHERE memberships.member=predicate.owner_oid OR memberships.roleid=predicate.owner_oid)
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace schema_info
        WHERE NOT EXISTS (SELECT 1 FROM allowed_application_schemas allowed_schema
            WHERE allowed_schema.schema_name=schema_info.nspname)
          AND NOT EXISTS (SELECT 1 FROM allowed_system_schemas system_schema
            WHERE system_schema.schema_name=schema_info.nspname)
          AND schema_info.nspname !~ '^pg_temp_[0-9]+$'
          AND schema_info.nspname !~ '^pg_toast_temp_[0-9]+$'
          AND pg_catalog.has_schema_privilege(predicate.owner_oid,schema_info.oid,'USAGE'))
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace schema_info
        WHERE pg_catalog.has_schema_privilege(predicate.owner_oid,schema_info.oid,'CREATE'))
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class extra_relation
        JOIN pg_catalog.pg_namespace extra_schema ON extra_schema.oid=extra_relation.relnamespace
        WHERE NOT EXISTS (SELECT 1 FROM allowed_application_schemas allowed_schema
            WHERE allowed_schema.schema_name=extra_schema.nspname)
          AND NOT EXISTS (SELECT 1 FROM allowed_system_schemas system_schema
            WHERE system_schema.schema_name=extra_schema.nspname)
          AND extra_schema.nspname !~ '^pg_temp_[0-9]+$'
          AND extra_schema.nspname !~ '^pg_toast_temp_[0-9]+$'
          AND ((extra_relation.relkind='S' AND (
                pg_catalog.has_sequence_privilege(predicate.owner_oid,extra_relation.oid,'USAGE')
                OR pg_catalog.has_sequence_privilege(predicate.owner_oid,extra_relation.oid,'SELECT')
                OR pg_catalog.has_sequence_privilege(predicate.owner_oid,extra_relation.oid,'UPDATE')))
            OR (extra_relation.relkind IN ('r','p','v','m','f') AND (
                pg_catalog.has_table_privilege(predicate.owner_oid,extra_relation.oid,'SELECT')
                OR pg_catalog.has_table_privilege(predicate.owner_oid,extra_relation.oid,'INSERT')
                OR pg_catalog.has_table_privilege(predicate.owner_oid,extra_relation.oid,'UPDATE')
                OR pg_catalog.has_table_privilege(predicate.owner_oid,extra_relation.oid,'DELETE')
                OR pg_catalog.has_table_privilege(predicate.owner_oid,extra_relation.oid,'TRUNCATE')
                OR pg_catalog.has_table_privilege(predicate.owner_oid,extra_relation.oid,'REFERENCES')
                OR pg_catalog.has_table_privilege(predicate.owner_oid,extra_relation.oid,'TRIGGER')
                OR pg_catalog.has_any_column_privilege(predicate.owner_oid,extra_relation.oid,'SELECT')
                OR pg_catalog.has_any_column_privilege(predicate.owner_oid,extra_relation.oid,'INSERT')
                OR pg_catalog.has_any_column_privilege(predicate.owner_oid,extra_relation.oid,'UPDATE')
                OR pg_catalog.has_any_column_privilege(predicate.owner_oid,extra_relation.oid,'REFERENCES')))))
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc extra_function
        JOIN pg_catalog.pg_namespace extra_schema ON extra_schema.oid=extra_function.pronamespace
        WHERE NOT EXISTS (SELECT 1 FROM allowed_application_schemas allowed_schema
            WHERE allowed_schema.schema_name=extra_schema.nspname)
          AND NOT EXISTS (SELECT 1 FROM allowed_system_schemas system_schema
            WHERE system_schema.schema_name=extra_schema.nspname)
          AND extra_schema.nspname !~ '^pg_temp_[0-9]+$'
          AND extra_schema.nspname !~ '^pg_toast_temp_[0-9]+$'
          AND pg_catalog.has_function_privilege(predicate.owner_oid,extra_function.oid,'EXECUTE'))
      AND EXISTS (SELECT 1 FROM pg_catalog.aclexplode(
          COALESCE(predicate.proacl,pg_catalog.acldefault('f',predicate.owner_oid))) acl
        WHERE acl.grantee=predicate.enqueuer_oid AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(
          COALESCE(predicate.proacl,pg_catalog.acldefault('f',predicate.owner_oid))) acl
        WHERE acl.privilege_type='EXECUTE'
          AND (acl.grantee NOT IN (predicate.owner_oid,predicate.enqueuer_oid) OR acl.is_grantable))
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class relation
        JOIN pg_catalog.pg_namespace relation_schema ON relation_schema.oid=relation.relnamespace
        CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) privilege
        WHERE relation_schema.nspname='public' AND relation.relkind IN ('r','p','v','m','f')
          AND pg_catalog.has_table_privilege(predicate.owner_oid,relation.oid,privilege.column1))
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class relation
        JOIN pg_catalog.pg_namespace relation_schema ON relation_schema.oid=relation.relnamespace
        JOIN pg_catalog.pg_attribute column_info ON column_info.attrelid=relation.oid
        CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) privilege
        WHERE relation_schema.nspname='public' AND relation.relkind IN ('r','p','v','m','f')
          AND column_info.attnum>0 AND NOT column_info.attisdropped
          AND pg_catalog.has_column_privilege(predicate.owner_oid,relation.oid,column_info.attname,privilege.column1)
          AND NOT EXISTS (SELECT 1 FROM allowed_columns allowed
            WHERE allowed.schema_name=relation_schema.nspname AND allowed.relation_name=relation.relname
              AND allowed.column_name=column_info.attname AND allowed.privilege_name=privilege.column1))
      AND NOT EXISTS (SELECT 1 FROM allowed_columns allowed
        LEFT JOIN pg_catalog.pg_namespace relation_schema ON relation_schema.nspname=allowed.schema_name
        LEFT JOIN pg_catalog.pg_class relation ON relation.relnamespace=relation_schema.oid AND relation.relname=allowed.relation_name
        WHERE relation.oid IS NULL OR NOT pg_catalog.has_column_privilege(
          predicate.owner_oid,relation.oid,allowed.column_name,allowed.privilege_name))
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class relation
        JOIN pg_catalog.pg_namespace relation_schema ON relation_schema.oid=relation.relnamespace
        WHERE relation_schema.nspname='public' AND relation.relkind='S'
          AND (pg_catalog.has_sequence_privilege(predicate.owner_oid,relation.oid,'USAGE')
            OR pg_catalog.has_sequence_privilege(predicate.owner_oid,relation.oid,'SELECT')
            OR pg_catalog.has_sequence_privilege(predicate.owner_oid,relation.oid,'UPDATE')))
      AND pg_catalog.strpos(predicate.body,'ifp_action_idisnullthenreturnfalse;endif;')>0
      AND pg_catalog.strpos(predicate.body,'set_config(''nova.fixture_action_predicate_id'',p_action_id::text,true)')>0
      AND pg_catalog.strpos(predicate.body,'selectid,action,target_type,target_idintov_actionfrompublic.moderation_actionswhereid=p_action_id')>0
      AND pg_catalog.strpos(predicate.body,'ifnotfoundthenreturnfalse;endif;')>0
      AND pg_catalog.strpos(predicate.body,'ifv_action.action=''hide_story''andv_action.target_type::text=''story''then')>0
      AND pg_catalog.strpos(predicate.body,'set_config(''nova.fixture_action_story_id'',v_action.target_id::text,true)')>0
      AND pg_catalog.strpos(predicate.body,'s.status::text=''removed''ands.visibility::text=''private''ands.deleted_atisnull')>0
      AND pg_catalog.strpos(predicate.body,'restore_story')=0
      AND pg_catalog.strpos(predicate.body,'execute')=0,
      false) AS safe
    FROM predicate`;

  const mediaRevocationWorkerPolicyQuery = `
    WITH worker_role AS (
      SELECT oid FROM pg_catalog.pg_roles WHERE rolname='nova_media_revocation_worker'
    ), queue AS (
      SELECT relation.oid,relation.relrowsecurity,relation.relforcerowsecurity
      FROM pg_catalog.pg_class relation
      WHERE relation.oid=pg_catalog.to_regclass('public.media_key_revocations')
    ), expected(policy_name,policy_command,using_expr,check_expr) AS (VALUES
      ('media_revocations_worker_read','r',
        'current_user=''nova_media_revocation_worker''::nameandattempt_count>=0andattempt_count<=5andnova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id)',
        NULL::text),
      ('media_revocations_worker_update','w',
        'current_user=''nova_media_revocation_worker''::nameandretry_after<=statement_timestamp()andattempt_count<5andescalated_atisnullandnova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id)',
        'current_user=''nova_media_revocation_worker''::nameandattempt_count>=1andattempt_count<=5and(attempt_count<5andescalated_atisnullorattempt_count=5andescalated_atisnotnull)andnova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id)')
    ), applicable AS (
      SELECT policy.oid
      FROM pg_catalog.pg_policy policy
      CROSS JOIN worker_role
      WHERE policy.polrelid=(SELECT oid FROM queue)
        AND (0::oid=ANY(policy.polroles) OR worker_role.oid=ANY(policy.polroles))
    )
    SELECT COALESCE(
      (SELECT relrowsecurity AND relforcerowsecurity FROM queue)
      AND EXISTS (SELECT 1 FROM worker_role)
      AND (SELECT count(*)=2 FROM applicable)
      AND NOT EXISTS (
        SELECT 1
        FROM expected specification
        LEFT JOIN pg_catalog.pg_policy actual
          ON actual.polrelid=(SELECT oid FROM queue) AND actual.polname=specification.policy_name
        CROSS JOIN worker_role
        WHERE actual.oid IS NULL
          OR actual.polcmd::text<>specification.policy_command
          OR actual.polpermissive IS DISTINCT FROM true
          OR actual.polroles IS DISTINCT FROM ARRAY[worker_role.oid]::oid[]
          OR actual.polqual IS NULL
          OR pg_catalog.regexp_replace(pg_catalog.lower(pg_catalog.pg_get_expr(actual.polqual,actual.polrelid,true)),'[[:space:]]+','','g')
            IS DISTINCT FROM specification.using_expr
          OR (specification.check_expr IS NULL AND actual.polwithcheck IS NOT NULL)
          OR (specification.check_expr IS NOT NULL AND (actual.polwithcheck IS NULL
            OR pg_catalog.regexp_replace(pg_catalog.lower(pg_catalog.pg_get_expr(actual.polwithcheck,actual.polrelid,true)),'[[:space:]]+','','g')
              IS DISTINCT FROM specification.check_expr))
      ),
      false) AS safe`;

  const verify = async (database: pg.Pool, expectedRole: string, kind: 'runtime' | 'limiter' | 'worker'): Promise<void> => {
    let principal: PrincipalProbe | undefined;
    try {
      principal = (await database.query<PrincipalProbe>(query, [expectedRole])).rows[0];
    } catch {
      throw new Error(`Database principal verification failed for ${kind} pool`);
    }
    if (!principal) throw new Error(`Database principal verification failed for ${kind} pool`);
    const commonValid = principal.effectiveRole === expectedRole &&
      !principal.effectiveCanLogin && !principal.effectiveInherit && !principal.loginInherit && principal.loginRole !== expectedRole &&
      !principal.effectiveSuperuser && !principal.effectiveBypassRls &&
      !principal.effectiveCreateRole && !principal.effectiveCreateDb && !principal.effectiveReplication &&
      principal.effectiveSchemaUsage && !principal.effectiveSchemaCreate &&
      principal.loginCanLogin && !principal.loginSuperuser && !principal.loginBypassRls && !principal.loginCreateRole &&
      !principal.loginCreateDb && !principal.loginReplication && principal.mayAssumeRole &&
      !principal.loginSchemaUsage && !principal.loginSchemaCreate && !principal.publicSchemaPublicGrant &&
      principal.authBootstrapDefinerSafe && principal.rateLimitCounterDefinerSafe &&
      principal.directMembershipCount === 1 && principal.loginMembershipClosureCount === 1 &&
      principal.loginMemberCount === 0 && !principal.loginHasOtherSetRoleMembers &&
      principal.loginExpectedMembershipCount === 1 && principal.loginMembershipOptionsSafe &&
      principal.effectiveMemberCount === 1 &&
      principal.loginAdminOptionCount === 0 && principal.effectiveAdminOptionCount === 0 &&
      principal.effectiveMembershipClosureCount === 0 && !principal.canAssumeOtherRuntime && !principal.canSetOtherRuntime &&
      !principal.usersInsert && !principal.usersAnyInsert && !principal.authSubjectSelect && !principal.authSubjectInsert &&
      !principal.loginAuthBootstrapExecute && !principal.loginUsersInsert && !principal.loginUsersAnyInsert &&
      !principal.loginAuthSubjectSelect && !principal.loginAuthSubjectInsert;
    const valid = kind === 'runtime'
      ? commonValid && !principal.rateLimitSelect && !principal.rateLimitInsert && !principal.rateLimitUpdate &&
        !principal.rateLimitDelete && !principal.actionInsert && !principal.actionReasonInsert &&
        principal.authBootstrapExecute && principal.authBootstrapDefinerSafe && !principal.queueSelectId &&
        !principal.queueSelectMediaId && !principal.queueSelectSourceKey && !principal.queueSelectActionId &&
        !principal.queueSelectAttemptCount && !principal.queueSelectRetryAfter && !principal.queueSelectCreatedAt &&
        !principal.queueSelectEscalatedAt && !principal.queueInsert && !principal.queueDelete &&
        !principal.queueUpdateAttemptCount && !principal.queueUpdateRetryAfter &&
        !principal.queueUpdateEscalatedAt
      : kind === 'limiter'
        ? commonValid && !principal.rateLimitSelect && !principal.rateLimitInsert && !principal.rateLimitUpdate &&
          !principal.rateLimitDelete && principal.rateLimitCounterExecute && !principal.authBootstrapExecute &&
          !principal.queueSelectId && !principal.queueSelectMediaId && !principal.queueSelectSourceKey &&
          !principal.queueSelectActionId && !principal.queueSelectAttemptCount && !principal.queueSelectRetryAfter &&
          !principal.queueSelectCreatedAt && !principal.queueSelectEscalatedAt && !principal.queueInsert &&
          !principal.queueDelete && !principal.queueUpdateAttemptCount && !principal.queueUpdateRetryAfter &&
          !principal.queueUpdateEscalatedAt && !principal.actionInsert
        : commonValid && !principal.authBootstrapExecute && principal.queueSelectId && principal.queueSelectMediaId &&
          principal.queueSelectSourceKey && principal.queueSelectActionId && principal.queueSelectAttemptCount &&
          principal.queueSelectRetryAfter && principal.queueSelectCreatedAt && principal.queueSelectEscalatedAt &&
          !principal.queueInsert && !principal.queueDelete && principal.queueUpdateAttemptCount &&
          principal.queueUpdateRetryAfter && principal.queueUpdateEscalatedAt && !principal.queueUpdateTable &&
          !principal.queueUpdateUnexpected && !principal.workerHasUnexpectedUpdate && !principal.actionUpdate;
    if (!valid) throw new Error(`Database principal verification failed for ${kind} pool`);
  };

  await Promise.all([
    verify(runtimePool, 'nova_fastify_runtime', 'runtime'),
    verify(limiterPool, 'nova_rate_limiter_runtime', 'limiter'),
    verify(workerPool, 'nova_media_revocation_worker', 'worker'),
  ]);
  let missingRuntimeContract: string[];
  try {
    const result = await runtimePool.query<{ missing: string[] }>(moderationRuntimeContractQuery);
    missingRuntimeContract = result.rows[0]?.missing ?? ['runtime contract probe returned no row'];
  } catch {
    throw new Error('Runtime database contract probe failed; startup remains fail-closed');
  }
  if (missingRuntimeContract.length > 0) {
    throw new Error(
      `Missing runtime database contract: ${missingRuntimeContract.join(', ')}. ` +
      'Install an approved canonical migration and least-privilege role grants before production rollout; test-only schema objects are not accepted.',
    );
  }
  try {
    const result = await runtimePool.query<{ safe: boolean }>(moderationDefinerQuery);
    if (result.rows[0]?.safe !== true) throw new Error('unsafe moderation helper metadata');
  } catch {
    throw new Error('Database principal verification failed for runtime pool');
  }
  try {
    const result = await runtimePool.query<{ safe: boolean }>(moderationActionPredicateQuery);
    if (result.rows[0]?.safe !== true) throw new Error('unsafe verified hide-action predicate metadata');
  } catch {
    throw new Error('Database principal verification failed for runtime pool');
  }
  try {
    const result = await runtimePool.query<{ safe: boolean }>(mediaRevocationWorkerPolicyQuery);
    if (result.rows[0]?.safe !== true) throw new Error('unsafe media-revocation worker policy scope');
  } catch {
    throw new Error('Database principal verification failed for worker pool');
  }
}
