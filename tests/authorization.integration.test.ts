import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWTPayload } from 'jose';
import pg from 'pg';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { closePool, pool } from '../src/db.js';
import { processPendingMediaKeyRevocations } from '../src/media-key-revocations.js';
import { ObjectCopyError } from '../src/storage/s3.js';

const enabled = process.env.RUN_INTEGRATION_TESTS === '1';
type Actor = { subject: string; token: string; id: string };
type Evidence = { check: string; result: 'PASS' | 'FAIL'; requestId: string; actorRole: string; timestamp: string };
type TestResponse = { statusCode: number; headers: Record<string, unknown>; json: () => any };

function requireDisposableUrl(url: string | undefined, name: string): string {
  if (!url) throw new Error(`${name} is required for RUN_INTEGRATION_TESTS=1`);
  const parsed = new URL(url);
  if (!['127.0.0.1', 'localhost', '::1'].includes(parsed.hostname)) {
    throw new Error(`${name} must point to a loopback-only PostgreSQL database`);
  }
  const database = decodeURIComponent(parsed.pathname.replace(/^\//, ''));
  if (!database.startsWith('nova_rls_e2e_moderation_')) {
    throw new Error(`${name} must name the disposable nova_rls_e2e_moderation_ database`);
  }
  return database;
}

describe.skipIf(!enabled)('authorization matrix (PostgreSQL integration)', () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  let controlPool: pg.Pool | null = null;
  let jwksServer: Server;
  let privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];
  let issuer = 'https://issuer.authz.test/';
  let prefix = `authz-test:${randomUUID()}`;
  const actors = new Map<string, Actor>();
  const evidence: Evidence[] = [];
  const createdStoryIds: string[] = [];
  const createdReportIds: string[] = [];
  const createdFeedbackIds: string[] = [];
  const createdSecurityReportIds: string[] = [];
  const createdMediaIds: string[] = [];
  const rotatedObjectKeys: Array<{ sourceKey: string; destinationKey: string }> = [];
  const compensationWarnings: Array<Record<string, unknown>> = [];
  const subjects = ['owner', 'reader', 'moderator', 'admin', 'support', 'security'].map((name) => `${prefix}:${name}`);

  async function tokenFor(subject: string, claims: JWTPayload = {}): Promise<string> {
    return new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: 'authz-matrix' })
      .setIssuer(issuer).setAudience('nova-api').setSubject(subject).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  }

  async function request(method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE', url: string, actor?: Actor, payload?: unknown, headers: Record<string, string> = {}): Promise<TestResponse> {
    const inject = app.inject.bind(app) as unknown as (options: {
      method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'; url: string; payload?: unknown; headers?: Record<string, string>;
    }) => Promise<TestResponse>;
    return inject({ method, url, ...(payload === undefined ? {} : { payload }), headers: {
      ...headers,
      ...(actor ? { authorization: `Bearer ${actor.token}` } : {}),
    } });
  }

  function record(check: string, response: TestResponse, expected: number, actorRole: string, condition = true): void {
    const requestId = String(response.headers['x-request-id'] ?? 'not-issued');
    let errorCode: string | null = null;
    try {
      const code = response.json()?.error?.code;
      if (typeof code === 'string') errorCode = code;
    } catch { /* keep evidence metadata-only */ }
    const passed = response.statusCode === expected && condition;
    evidence.push({ check, result: passed ? 'PASS' : 'FAIL', requestId, actorRole, timestamp: new Date().toISOString() });
    expect(passed, `${check}; requestId=${requestId}; http=${response.statusCode}; errorCode=${errorCode ?? 'none'}`).toBe(true);
  }

  async function createActor(role: string): Promise<Actor> {
    const subject = `${prefix}:${role}`;
    const token = await tokenFor(subject);
    const response = await request('GET', '/api/v1/me', { subject, token, id: '' });
    expect(response.statusCode).toBe(200);
    const id = response.json().data.id as string;
    const actor = { subject, token, id };
    actors.set(role, actor);
    return actor;
  }

  beforeAll(async () => {
    const databaseNames = [
      requireDisposableUrl(process.env.DATABASE_URL, 'DATABASE_URL'),
      requireDisposableUrl(process.env.RATE_LIMIT_DATABASE_URL, 'RATE_LIMIT_DATABASE_URL'),
      requireDisposableUrl(process.env.MEDIA_REVOCATION_DATABASE_URL, 'MEDIA_REVOCATION_DATABASE_URL'),
      requireDisposableUrl(process.env.RLS_CONTROL_DATABASE_URL, 'RLS_CONTROL_DATABASE_URL'),
    ];
    if (!databaseNames.every((name) => name === databaseNames[0])) throw new Error('All URLs must point to the same disposable database.');
    const addresses = [process.env.DATABASE_URL, process.env.RATE_LIMIT_DATABASE_URL,
      process.env.MEDIA_REVOCATION_DATABASE_URL, process.env.RLS_CONTROL_DATABASE_URL]
      .map((url) => new URL(url!).host);
    if (!addresses.every((address) => address === addresses[0])) throw new Error('All URLs must point to the same loopback PostgreSQL server.');
    controlPool = new pg.Pool({ connectionString: process.env.RLS_CONTROL_DATABASE_URL, max: 5, application_name: 'nova-authz-test-control' });
    const controlPrincipal = await controlPool.query<{ role: string; login: string }>(
      'SELECT current_user AS role, session_user AS login',
    );
    expect(controlPrincipal.rows[0]).toEqual({ role: 'postgres', login: 'postgres' });
    const { publicKey, privateKey: signer } = await generateKeyPair('RS256');
    privateKey = signer;
    const jwk = await exportJWK(publicKey);
    Object.assign(jwk, { kid: 'authz-matrix', alg: 'RS256', use: 'sig' });
    jwksServer = createServer((req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end(req.url === '/jwks' ? JSON.stringify({ keys: [jwk] }) : '{}');
    });
    await new Promise<void>((resolve, reject) => {
      jwksServer.once('error', reject);
      jwksServer.listen(0, '127.0.0.1', resolve);
    });
    const port = (jwksServer.address() as AddressInfo).port;
    const config = loadConfig({
      ...process.env,
      NODE_ENV: 'test', LOG_LEVEL: 'error',
      RATE_LIMIT_HMAC_KEY: randomBytes(32).toString('hex'),
      AUTH_JWKS_URL: `http://127.0.0.1:${port}/jwks`,
      AUTH_ISSUER: issuer, AUTH_AUDIENCE: 'nova-api',
      CORS_ORIGINS: 'https://app.nova.test', NOINDEX: 'true',
      S3_ENDPOINT: 'http://127.0.0.1:9000', S3_REGION: 'us-east-1', S3_BUCKET: 'nova-test-private',
      S3_ACCESS_KEY_ID: 'test-access-key', S3_SECRET_ACCESS_KEY: 'test-only-secret', S3_FORCE_PATH_STYLE: 'true',
    });
    app = await buildApp({ config, pg: pool });
    app.addHook('onRequest', async (request) => {
      const originalWarn = request.log.warn.bind(request.log);
      Object.defineProperty(request.log, 'warn', {
        configurable: true,
        value: (fields: unknown, message?: string) => {
          if (fields && typeof fields === 'object' && !Array.isArray(fields)
              && 'event' in fields && fields.event === 'media_revocation_copy_compensation_failed') {
            compensationWarnings.push(fields as Record<string, unknown>);
          }
          return (originalWarn as unknown as (fields: unknown, message?: string) => void)(fields, message);
        },
      });
    });
    const coverFixture = Buffer.from('fictional cover fixture bytes');
    app.mediaStorage.readObject = async () => ({ body: Readable.from([coverFixture]), contentLength: coverFixture.length });
    app.mediaStorage.copyObjectToKey = async (sourceKey, destinationKey) => { rotatedObjectKeys.push({ sourceKey, destinationKey }); };
    app.mediaStorage.deleteObject = async () => undefined;
    for (const role of ['owner', 'reader', 'moderator', 'admin', 'support', 'security']) await createActor(role);
    await controlPool!.query("UPDATE users SET role='moderator' WHERE auth_subject=$1", [actors.get('moderator')!.subject]);
    await controlPool!.query("UPDATE users SET role='admin' WHERE auth_subject=$1", [actors.get('admin')!.subject]);
    await controlPool!.query("UPDATE users SET role='support' WHERE auth_subject=$1", [actors.get('support')!.subject]);
    await controlPool!.query("UPDATE users SET role='security' WHERE auth_subject=$1", [actors.get('security')!.subject]);
  }, 30_000);

  afterAll(async () => {
    if (actors.size) {
      const ids = [...actors.values()].map((actor) => actor.id);
      const storyIds = [...createdStoryIds];
      const commentRows = await controlPool!.query<{ id: string }>('SELECT id FROM comments WHERE story_id=ANY($1::uuid[])', [storyIds]);
      const commentIds = commentRows.rows.map((row) => row.id);
      await controlPool!.query('DELETE FROM staff_access_audit WHERE staff_id=ANY($1::uuid[]) OR resource_id=ANY($2::uuid[])',
        [ids, [...createdReportIds, ...createdFeedbackIds, ...createdSecurityReportIds, ...createdStoryIds]]);
      await controlPool!.query(
        `DELETE FROM media_key_revocations WHERE media_id=ANY($1::uuid[])
           OR moderation_action_id IN (SELECT id FROM moderation_actions
             WHERE moderator_id=ANY($2::uuid[]) OR target_id=ANY($3::uuid[]))`,
        [createdMediaIds, ids, [...createdStoryIds, ...commentIds]],
      );
      await controlPool!.query('DELETE FROM moderation_actions WHERE moderator_id=ANY($1::uuid[]) OR target_id=ANY($2::uuid[])',
        [ids, [...createdStoryIds, ...commentIds]]);
      await controlPool!.query('DELETE FROM beta_feedback WHERE reporter_id=ANY($1::uuid[]) OR id=ANY($2::uuid[])', [ids, createdFeedbackIds]);
      await controlPool!.query('DELETE FROM security_reports WHERE reporter_id=ANY($1::uuid[]) OR id=ANY($2::uuid[])', [ids, createdSecurityReportIds]);
      await controlPool!.query('DELETE FROM reports WHERE reporter_id=ANY($1::uuid[]) OR id=ANY($2::uuid[]) OR target_id=ANY($3::uuid[])',
        [ids, createdReportIds, [...createdStoryIds, ...commentIds]]);
      await controlPool!.query('DELETE FROM comments WHERE id=ANY($1::uuid[])', [commentIds]);
      await controlPool!.query('DELETE FROM story_tags WHERE story_id=ANY($1::uuid[])', [storyIds]);
      await controlPool!.query('DELETE FROM bookmarks WHERE story_id=ANY($1::uuid[]) OR user_id=ANY($2::uuid[])', [storyIds, ids]);
      await controlPool!.query('DELETE FROM follows WHERE follower_id=ANY($1::uuid[]) OR followed_id=ANY($1::uuid[])', [ids]);
      await controlPool!.query('DELETE FROM stories WHERE id=ANY($1::uuid[]) OR author_id=ANY($2::uuid[])', [storyIds, ids]);
      await controlPool!.query('DELETE FROM media_assets WHERE id=ANY($1::uuid[]) OR owner_id=ANY($2::uuid[])', [createdMediaIds, ids]);
      await controlPool!.query('DELETE FROM users WHERE id=ANY($1::uuid[])', [ids]);
    }
    if (app) await app.close();
    if (jwksServer) await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
    if (enabled) {
      const evidencePath = process.env.AUTHZ_EVIDENCE_PATH ?? 'artifacts/security-matrix.json';
      await mkdir(dirname(evidencePath), { recursive: true });
      await writeFile(evidencePath, JSON.stringify({ generatedAt: new Date().toISOString(), evidence }, null, 2) + '\n');
    }
    await controlPool?.end();
    await closePool();
  }, 30_000);

  it('protects Draft ownership, Publish, role inputs, CORS, and pending uploads', async () => {
    const owner = actors.get('owner')!;
    const reader = actors.get('reader')!;
    const moderator = actors.get('moderator')!;
    const admin = actors.get('admin')!;

    const injectedAuthor = await request('POST', '/api/v1/stories', owner, {
      title: 'Invalid ownership payload', author_id: reader.id, role: 'moderator',
    });
    record('client_author_id_and_role_rejected', injectedAuthor, 400, 'owner');

    const forgedRole = await request('PATCH', '/api/v1/me', owner, { role: 'moderator' });
    record('client_role_change_rejected', forgedRole, 400, 'owner');

    const avatarMediaId = randomUUID();
    await controlPool!.query(
      `INSERT INTO public.media_assets (id,owner_id,purpose,object_key,mime_type,size_bytes,checksum,status,ready_at)
       VALUES ($1,$2,'avatar',$3,'image/png',128,$4,'ready',now())`,
      [avatarMediaId, owner.id, `ready/${owner.id}/${avatarMediaId}.png`, 'a'.repeat(64)],
    );
    createdMediaIds.push(avatarMediaId);
    const profilePatch = await request('PATCH', '/api/v1/me', owner, {
      displayName: 'Fictional Matrix Owner', bio: 'Disposable RLS profile test.', avatarMediaId,
    });
    record('owner_profile_and_ready_avatar_update_is_allowed', profilePatch, 200, 'owner',
      profilePatch.json().data?.displayName === 'Fictional Matrix Owner'
        && profilePatch.json().data?.bio === 'Disposable RLS profile test.'
        && profilePatch.json().data?.avatarMediaId === avatarMediaId
        && profilePatch.json().data?.role === 'reader');
    const profileBeforeInvalidAvatar = await request('GET', '/api/v1/me', owner);
    const invalidAvatar = await request('PATCH', '/api/v1/me', owner, { avatarMediaId: randomUUID() });
    record('invalid_avatar_reference_is_rejected_without_sqlstate', invalidAvatar, 400, 'owner',
      invalidAvatar.json().error?.code === 'MEDIA_NOT_READY'
        && !/42501|SQLSTATE|permission denied/i.test(JSON.stringify(invalidAvatar.json())));
    expect((await request('GET', '/api/v1/me', owner)).json().data).toEqual(profileBeforeInvalidAvatar.json().data);
    const clearAvatar = await request('PATCH', '/api/v1/me', owner, { avatarMediaId: null });
    record('owner_can_clear_avatar_reference', clearAvatar, 200, 'owner', clearAvatar.json().data?.avatarMediaId === null);

    const followFirst = await request('PUT', `/api/v1/me/following/${reader.id}`, owner);
    record('owner_can_follow_active_user', followFirst, 204, 'owner');
    const followAgain = await request('PUT', `/api/v1/me/following/${reader.id}`, owner);
    const followCount = await controlPool!.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM public.follows WHERE follower_id=$1 AND followed_id=$2', [owner.id, reader.id],
    );
    record('follow_insert_is_idempotent_and_self_readable', followAgain, 204, 'owner', followCount.rows[0]?.count === '1');
    const followingList = await request('GET', '/api/v1/me/following', owner);
    record('owner_reads_only_own_following_list', followingList, 200, 'owner',
      followingList.json().data.some((row: { id: string }) => row.id === reader.id));
    const unfollow = await request('DELETE', `/api/v1/me/following/${reader.id}`, owner);
    const unfollowAgain = await request('DELETE', `/api/v1/me/following/${reader.id}`, owner);
    const followCountAfterDelete = await controlPool!.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM public.follows WHERE follower_id=$1 AND followed_id=$2', [owner.id, reader.id],
    );
    record('own_follow_delete_is_idempotent', unfollowAgain, 204, 'owner',
      unfollow.statusCode === 204 && followCountAfterDelete.rows[0]?.count === '0');

    const forcedPublic = await request('POST', '/api/v1/stories', owner, {
      title: 'Forced public state attempt', body: 'Fictional test only.', status: 'published', visibility: 'public',
    });
    record('client_cannot_force_public_state', forcedPublic, 400, 'owner');

    const tags = await controlPool!.query<{ id: string; normalized_name: string }>(
      "SELECT id, normalized_name FROM public.tags WHERE normalized_name IN ('fantasy','science-fiction')",
    );
    const tagByName = new Map(tags.rows.map((tag) => [tag.normalized_name, tag.id]));
    expect(tagByName.has('fantasy')).toBe(true);
    expect(tagByName.has('science-fiction')).toBe(true);
    const storyCountBeforeCoverCreate = await controlPool!.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM public.stories WHERE author_id=$1', [owner.id],
    );
    const coverCreate = await request('POST', '/api/v1/stories', owner, {
      title: 'Unavailable cover assignment', coverMediaId: randomUUID(), tagIds: [tagByName.get('fantasy')],
    });
    const storyCountAfterCoverCreate = await controlPool!.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM public.stories WHERE author_id=$1', [owner.id],
    );
    record('story_cover_assignment_is_501_before_create_side_effects', coverCreate, 501, 'owner',
      coverCreate.json().error?.code === 'NOT_INTEGRATED'
        && coverCreate.json().error?.message === 'Story cover assignment is unavailable for the MVP. No changes were made.'
        && !/42501|SQLSTATE|permission denied/i.test(JSON.stringify(coverCreate.json()))
        && storyCountAfterCoverCreate.rows[0]?.count === storyCountBeforeCoverCreate.rows[0]?.count);

    const created = await request('POST', '/api/v1/stories', owner, {
      title: 'Auth matrix Draft', summary: 'Fictional test fixture', body: 'Non-sensitive integration-test text.',
      tagIds: [tagByName.get('fantasy')!],
    });
    record('owner_create_draft', created, 201, 'owner', created.json().data.authorId === owner.id);
    const storyId = created.json().data.id as string;
    createdStoryIds.push(storyId);
    const createdStoryTags = await controlPool!.query<{ normalized_name: string }>(
      `SELECT t.normalized_name FROM public.story_tags st JOIN public.tags t ON t.id=st.tag_id WHERE st.story_id=$1`, [storyId],
    );
    record('story_create_writes_only_curated_tags', created, 201, 'owner',
      createdStoryTags.rows.map((row) => row.normalized_name).join(',') === 'fantasy');

    const anonymousRead = await request('GET', `/api/v1/stories/${storyId}`);
    record('anonymous_cannot_read_draft', anonymousRead, 404, 'anonymous');
    const otherRead = await request('GET', `/api/v1/stories/${storyId}`, reader);
    record('other_account_cannot_read_draft', otherRead, 404, 'reader');
    const ownerRead = await request('GET', `/api/v1/stories/${storyId}`, owner);
    record('owner_can_read_draft', ownerRead, 200, 'owner', ownerRead.json().data.authorId === owner.id);
    const otherEdit = await request('PATCH', `/api/v1/stories/${storyId}`, reader, { version: 1, title: 'Attempted takeover' });
    record('other_account_cannot_edit_draft', otherEdit, 404, 'reader');
    const readTransitionState = () => controlPool!.query<{
      story: Record<string, unknown>; comments: unknown; actionCount: string; outboxCount: string;
    }>(
      `SELECT pg_catalog.to_jsonb(s) AS story,
         COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
           'id',c.id,'status',c.status::text,'body',c.body,'deletedAt',c.deleted_at,'updatedAt',c.updated_at) ORDER BY c.id)
           FROM public.comments c WHERE c.story_id=s.id),'[]'::jsonb) AS comments,
         (SELECT count(*)::text FROM public.moderation_actions a WHERE a.target_type='story' AND a.target_id=s.id) AS "actionCount",
         (SELECT count(*)::text FROM public.media_key_revocations q JOIN public.moderation_actions a ON a.id=q.moderation_action_id
           WHERE a.target_type='story' AND a.target_id=s.id) AS "outboxCount"
       FROM public.stories s WHERE s.id=$1`, [storyId],
    );
    const beforeTransitions = (await readTransitionState()).rows[0];
    expect(beforeTransitions).toMatchObject({
      story: { status: 'draft', visibility: 'private', version: 1, published_at: null, comments_open: true, deleted_at: null },
      comments: [], actionCount: '0', outboxCount: '0',
    });
    const otherPublish = await request('POST', `/api/v1/stories/${storyId}/publish`, reader, {});
    record('disabled_publish_returns_safe_501_without_owner_lookup', otherPublish, 501, 'reader',
      otherPublish.json().error?.code === 'NOT_INTEGRATED'
        && otherPublish.json().error?.message === 'Publish is unavailable for the MVP. No changes were made.');

    const cookieCrossOrigin = await request('POST', `/api/v1/stories/${storyId}/publish`, undefined, {}, {
      origin: 'https://attacker.invalid', cookie: 'nova_session=fake-test-cookie',
    });
    record('cross_origin_cookie_publish_rejected', cookieCrossOrigin, 401, 'anonymous', !cookieCrossOrigin.headers['access-control-allow-origin']);

    const ownerPublish = await request('POST', `/api/v1/stories/${storyId}/publish`, owner, {});
    record('owner_publish_is_unavailable_without_side_effects', ownerPublish, 501, 'owner',
      ownerPublish.json().error?.code === 'NOT_INTEGRATED'
        && ownerPublish.json().error?.message === 'Publish is unavailable for the MVP. No changes were made.');
    const anonymousPublishedRead = await request('GET', `/api/v1/stories/${storyId}`);
    record('anonymous_still_cannot_read_after_unavailable_publish', anonymousPublishedRead, 404, 'anonymous');
    const ownerUnpublish = await request('POST', `/api/v1/stories/${storyId}/unpublish`, owner, {});
    record('owner_unpublish_is_unavailable_without_side_effects', ownerUnpublish, 501, 'owner',
      ownerUnpublish.json().error?.code === 'NOT_INTEGRATED'
        && ownerUnpublish.json().error?.message === 'Unpublish is unavailable for the MVP. No changes were made.');
    const anonymousAfterUnpublish = await request('GET', `/api/v1/stories/${storyId}`);
    record('anonymous_still_cannot_read_after_unavailable_unpublish', anonymousAfterUnpublish, 404, 'anonymous');
    const ownerDelete = await request('DELETE', `/api/v1/stories/${storyId}`, owner);
    record('owner_delete_is_unavailable_without_side_effects', ownerDelete, 501, 'owner',
      ownerDelete.json().error?.code === 'NOT_INTEGRATED'
        && ownerDelete.json().error?.message === 'Delete is unavailable for the MVP. No changes were made.');
    const ownerAfterTransitions = await request('GET', `/api/v1/stories/${storyId}`, owner);
    record('owner_still_reads_draft_after_unavailable_transitions', ownerAfterTransitions, 200, 'owner',
      ownerAfterTransitions.json().data?.status === 'draft' && ownerAfterTransitions.json().data?.visibility === 'private'
        && ownerAfterTransitions.json().data?.version === 1);
    expect((await readTransitionState()).rows[0]).toEqual(beforeTransitions);

    const ownerPatch = await request('PATCH', `/api/v1/stories/${storyId}`, owner, {
      version: 1, title: 'Auth matrix Draft revised', summary: 'Updated in the disposable RLS test.',
      body: 'Updated body.', tagIds: [tagByName.get('science-fiction')!], coverMediaId: null,
    });
    record('owner_story_patch_updates_allowed_columns_and_tags', ownerPatch, 200, 'owner',
      ownerPatch.json().data?.version === 2 && ownerPatch.json().data?.title === 'Auth matrix Draft revised');
    const patchedStoryState = () => controlPool!.query<{ story: Record<string, unknown>; tagIds: string[] }>(
      `SELECT pg_catalog.to_jsonb(s) AS story,
         COALESCE((SELECT array_agg(st.tag_id::text ORDER BY st.tag_id::text) FROM public.story_tags st WHERE st.story_id=s.id),ARRAY[]::text[]) AS "tagIds"
       FROM public.stories s WHERE s.id=$1`, [storyId],
    );
    const patchedTagNames = await controlPool!.query<{ normalized_name: string }>(
      `SELECT t.normalized_name FROM public.story_tags st JOIN public.tags t ON t.id=st.tag_id WHERE st.story_id=$1`, [storyId],
    );
    expect(patchedTagNames.rows.map((row) => row.normalized_name)).toEqual(['science-fiction']);
    const beforeUnavailableCoverPatch = (await patchedStoryState()).rows[0];
    const coverPatch = await request('PATCH', `/api/v1/stories/${storyId}`, owner, { version: 2, coverMediaId: randomUUID() });
    record('story_cover_patch_is_501_before_story_lookup_or_mutation', coverPatch, 501, 'owner',
      coverPatch.json().error?.code === 'NOT_INTEGRATED'
        && coverPatch.json().error?.message === 'Story cover assignment is unavailable for the MVP. No changes were made.'
        && !/42501|SQLSTATE|permission denied/i.test(JSON.stringify(coverPatch.json())));
    expect((await patchedStoryState()).rows[0]).toEqual(beforeUnavailableCoverPatch);
    const beforeStalePatch = (await patchedStoryState()).rows[0];
    const stalePatch = await request('PATCH', `/api/v1/stories/${storyId}`, owner, { version: 1, title: 'Stale update attempt' });
    record('stale_owner_story_patch_is_rejected_without_changes', stalePatch, 409, 'owner',
      stalePatch.json().error?.code === 'VERSION_CONFLICT'
        && !/42501|SQLSTATE|permission denied/i.test(JSON.stringify(stalePatch.json())));
    expect((await patchedStoryState()).rows[0]).toEqual(beforeStalePatch);

    const pendingMediaId = randomUUID();
    const pendingObjectKey = `pending/${owner.id}/${pendingMediaId}.jpg`;
    await controlPool!.query(
      `INSERT INTO public.media_assets (id,owner_id,purpose,object_key,mime_type,size_bytes,status)
       VALUES ($1,$2,'avatar',$3,'image/jpeg',128,'pending')`, [pendingMediaId, owner.id, pendingObjectKey],
    );
    createdMediaIds.push(pendingMediaId);
    const pendingAnonymous = await request('GET', `/api/v1/media/${pendingMediaId}`);
    record('anonymous_cannot_read_pending_upload', pendingAnonymous, 404, 'anonymous');
    const pendingOwner = await request('GET', `/api/v1/media/${pendingMediaId}`, owner);
    record('owner_cannot_read_pending_upload', pendingOwner, 404, 'owner');
    const pendingOther = await request('GET', `/api/v1/media/${pendingMediaId}`, reader);
    record('other_account_cannot_read_pending_upload', pendingOther, 404, 'reader');
    const readUploadWriteState = () => controlPool!.query<{
      media: Record<string, unknown>; actionCount: string; outboxCount: string; ownerMediaCount: string;
    }>(
      `SELECT pg_catalog.to_jsonb(m) AS media,
         (SELECT count(*)::text FROM public.moderation_actions a WHERE a.target_id=m.id) AS "actionCount",
         (SELECT count(*)::text FROM public.media_key_revocations q WHERE q.media_id=m.id) AS "outboxCount",
         (SELECT count(*)::text FROM public.media_assets own WHERE own.owner_id=m.owner_id) AS "ownerMediaCount"
       FROM public.media_assets m WHERE m.id=$1`, [pendingMediaId],
    );
    const uploadBeforeUnavailableWrites = (await readUploadWriteState()).rows[0];
    expect(uploadBeforeUnavailableWrites).toMatchObject({
      media: { id: pendingMediaId, status: 'pending', object_key: pendingObjectKey, ready_at: null },
      actionCount: '0', outboxCount: '0',
    });
    const storageCallCounts = { createUploadUrl: 0, normalizeAndPromote: 0, deleteObject: 0 };
    const originalCreateUploadUrl = app.mediaStorage.createUploadUrl;
    const normalizeAndPromote = app.mediaStorage.normalizeAndPromote;
    const deleteObject = app.mediaStorage.deleteObject;
    app.mediaStorage.createUploadUrl = async () => { storageCallCounts.createUploadUrl += 1; throw new Error('unexpected storage call'); };
    app.mediaStorage.normalizeAndPromote = async () => { storageCallCounts.normalizeAndPromote += 1; throw new Error('unexpected storage call'); };
    app.mediaStorage.deleteObject = async () => { storageCallCounts.deleteObject += 1; };
    try {
      const objectKeyInjection = await request('POST', '/api/v1/media/upload-intents', owner, {
        purpose: 'avatar', mimeType: 'image/jpeg', sizeBytes: 128, objectKey: `${reader.id}/ready/victim.jpg`,
      });
      record('upload_intent_is_unavailable_without_storage_or_database_side_effects', objectKeyInjection, 501, 'owner',
        objectKeyInjection.json().error?.code === 'NOT_INTEGRATED'
          && objectKeyInjection.json().error?.message === 'Media upload is unavailable for the MVP. No changes were made.'
          && !/42501|SQLSTATE|permission denied/i.test(JSON.stringify(objectKeyInjection.json())));
      const uploadIntent = await request('POST', '/api/v1/media/upload-intents', owner, {
        purpose: 'avatar', mimeType: 'image/jpeg', sizeBytes: 128,
      });
      record('normal_upload_intent_is_unavailable_without_side_effects', uploadIntent, 501, 'owner',
        uploadIntent.json().error?.code === 'NOT_INTEGRATED');
      const ownerComplete = await request('POST', `/api/v1/media/${pendingMediaId}/complete`, owner, {});
      record('owner_completion_is_unavailable_without_side_effects', ownerComplete, 501, 'owner',
        ownerComplete.json().error?.code === 'NOT_INTEGRATED'
          && ownerComplete.json().error?.message === 'Media upload is unavailable for the MVP. No changes were made.'
          && !/42501|SQLSTATE|permission denied/i.test(JSON.stringify(ownerComplete.json())));
      const otherComplete = await request('POST', `/api/v1/media/${pendingMediaId}/complete`, reader, {});
      record('other_account_completion_has_no_media_existence_side_channel', otherComplete, 501, 'reader',
        otherComplete.json().error?.code === 'NOT_INTEGRATED');
      const uploadAfterUnavailableWrites = (await readUploadWriteState()).rows[0];
      expect(uploadAfterUnavailableWrites).toEqual(uploadBeforeUnavailableWrites);
      expect(storageCallCounts).toEqual({ createUploadUrl: 0, normalizeAndPromote: 0, deleteObject: 0 });
    } finally {
      app.mediaStorage.createUploadUrl = originalCreateUploadUrl;
      app.mediaStorage.normalizeAndPromote = normalizeAndPromote;
      app.mediaStorage.deleteObject = deleteObject;
    }

    const adminModeration = await request('GET', '/api/v1/moderation/reports', admin);
    record('general_admin_is_not_moderator', adminModeration, 403, 'admin');
    const claimEscalation = await request('GET', '/api/v1/moderation/reports', { ...reader, token: await tokenFor(reader.subject, { role: 'moderator' }) });
    record('client_token_role_claim_cannot_escalate', claimEscalation, 403, 'reader');
  });

  it('rejects access tokens without an expiry claim', async () => {
    const reader = actors.get('reader')!;
    const token = await new SignJWT().setProtectedHeader({ alg: 'RS256', kid: 'authz-matrix' })
      .setIssuer(issuer).setAudience('nova-api').setSubject(reader.subject).setIssuedAt().sign(privateKey);
    const response = await request('GET', '/api/v1/me', { ...reader, token });
    record('token_without_exp_rejected', response, 401, 'reader');
  });

  it('keeps hidden Story and revocation state fail-closed while unsupported report/suspension writes return 501', async () => {
    const owner = await createActor('suspended_owner');
    const storyOwnerSubject = 'nova-rls-e2e:cover-owner';
    const storyOwner: Actor = {
      subject: storyOwnerSubject, token: await tokenFor(storyOwnerSubject), id: 'e1000000-0000-4000-8000-000000000002',
    };
    const reader = actors.get('reader')!;
    const coverMediaId = 'e2000000-0000-4000-8000-000000000001';
    const storyId = 'e3000000-0000-4000-8000-000000000001';
    const initialCoverKey = `ready/${storyOwner.id}/${coverMediaId}.jpg`;
    const seededStory = await request('GET', `/api/v1/stories/${storyId}`, storyOwner);
    record('takedown_fixture_story_is_seeded_public', seededStory, 200, 'owner',
      seededStory.json().data?.status === 'published' && seededStory.json().data?.visibility === 'public');
    const commentWriteState = () => controlPool!.query<{
      story: Record<string, unknown>; comments: unknown; actionCount: string; outboxCount: string;
    }>(
      `SELECT pg_catalog.to_jsonb(s) AS story,
         COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(c) ORDER BY c.id)
           FROM public.comments c WHERE c.story_id=s.id),'[]'::jsonb) AS comments,
         (SELECT count(*)::text FROM public.moderation_actions a WHERE a.target_type='story' AND a.target_id=s.id) AS "actionCount",
         (SELECT count(*)::text FROM public.media_key_revocations q JOIN public.moderation_actions a ON a.id=q.moderation_action_id
           WHERE a.target_type='story' AND a.target_id=s.id) AS "outboxCount"
       FROM public.stories s WHERE s.id=$1`, [storyId],
    );
    const commentStateBefore = (await commentWriteState()).rows[0];
    expect(commentStateBefore).toMatchObject({
      story: { status: 'published', visibility: 'public', comments_open: true }, actionCount: '0', outboxCount: '0',
    });
    const sharedStoryInsert = await controlPool!.query<{ id: string }>(
      `INSERT INTO stories(author_id,title,slug,status,visibility,published_at,cover_media_id)
       VALUES($1,'Shared cover fixture',$2,'draft','private',NULL,$3) RETURNING id`,
      [storyOwner.id, `shared-cover-${randomUUID()}`, coverMediaId],
    );
    const sharedStoryId = sharedStoryInsert.rows[0]!.id;
    createdStoryIds.push(sharedStoryId);
    const commentCreate = await request('POST', `/api/v1/stories/${storyId}/comments`, reader, { body: 'Fictional test comment.' });
    record('public_reader_comment_creation_is_unavailable_without_side_effects', commentCreate, 501, 'reader',
      commentCreate.json().error?.code === 'NOT_INTEGRATED'
        && commentCreate.json().error?.message === 'Comment creation is unavailable for the MVP. No changes were made.'
        && !/42501|SQLSTATE|permission denied/i.test(JSON.stringify(commentCreate.json())));
    expect((await commentWriteState()).rows[0]).toEqual(commentStateBefore);
    const commentRead = await request('GET', `/api/v1/stories/${storyId}/comments`, reader);
    record('public_comment_reads_remain_available', commentRead, 200, 'reader',
      Array.isArray(commentRead.json().data) && commentRead.json().data.some((row: { body: string }) => row.body === 'Disposable comment for moderation guard'));
    const seedComment = await controlPool!.query<{ id: string }>(
      "SELECT id FROM public.comments WHERE story_id=$1 AND body='Disposable comment for moderation guard' AND status='visible'", [storyId],
    );
    expect(seedComment.rows[0]?.id).toBeTruthy();
    const commentDeleteState = () => controlPool!.query<{ comment: Record<string, unknown>; actionCount: string; outboxCount: string }>(
      `SELECT pg_catalog.to_jsonb(c) AS comment,
         (SELECT count(*)::text FROM public.moderation_actions a WHERE a.target_id=c.story_id) AS "actionCount",
         (SELECT count(*)::text FROM public.media_key_revocations q JOIN public.moderation_actions a ON a.id=q.moderation_action_id
           WHERE a.target_id=c.story_id) AS "outboxCount"
       FROM public.comments c WHERE c.id=$1`, [seedComment.rows[0]!.id],
    );
    const commentBeforeDelete = (await commentDeleteState()).rows[0];
    const moderatorDelete = await request('DELETE', `/api/v1/comments/${seedComment.rows[0]!.id}`, actors.get('moderator'));
    record('moderator_comment_delete_is_501_without_side_effects', moderatorDelete, 501, 'moderator',
      moderatorDelete.json().error?.code === 'NOT_INTEGRATED'
        && moderatorDelete.json().error?.message === 'Comment deletion is unavailable for the MVP. No changes were made.'
        && !/42501|SQLSTATE|permission denied/i.test(JSON.stringify(moderatorDelete.json())));
    const authorDelete = await request('DELETE', `/api/v1/comments/${seedComment.rows[0]!.id}`, storyOwner);
    record('author_comment_delete_is_also_501_without_side_effects', authorDelete, 501, 'owner',
      authorDelete.json().error?.code === 'NOT_INTEGRATED'
        && !/42501|SQLSTATE|permission denied/i.test(JSON.stringify(authorDelete.json())));
    const otherDelete = await request('DELETE', `/api/v1/comments/${seedComment.rows[0]!.id}`, reader);
    record('reader_comment_delete_has_no_existence_side_channel', otherDelete, 501, 'reader',
      otherDelete.json().error?.code === 'NOT_INTEGRATED');
    expect((await commentDeleteState()).rows[0]).toEqual(commentBeforeDelete);
    const commentsAfterUnavailableDelete = await request('GET', `/api/v1/stories/${storyId}/comments`, reader);
    record('comment_read_remains_available_after_delete_returns_501', commentsAfterUnavailableDelete, 200, 'reader',
      commentsAfterUnavailableDelete.json().data.some((row: { id: string }) => row.id === seedComment.rows[0]!.id));
    const reportResponse = await request('POST', '/api/v1/reports', actors.get('admin'), {
      targetType: 'story', targetId: storyId, reason: 'spam', details: 'Fictional takedown test report.',
    });
    record('takedown_report_created_for_pending_state_test', reportResponse, 201, 'admin');
    const reportId = reportResponse.json().data.caseId as string;
    createdReportIds.push(reportId);
    const creator = await controlPool!.query<{ username: string }>('SELECT username FROM users WHERE id=$1', [storyOwner.id]);
    const username = creator.rows[0]!.username;

    const bookmarkBefore = await request('PUT', `/api/v1/me/bookmarks/${storyId}`, reader);
    record('active_creator_story_can_be_bookmarked', bookmarkBefore, 204, 'reader');
    const bookmarkAgain = await request('PUT', `/api/v1/me/bookmarks/${storyId}`, reader);
    const bookmarkCount = await controlPool!.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM public.bookmarks WHERE user_id=$1 AND story_id=$2', [reader.id, storyId],
    );
    record('bookmark_insert_is_idempotent_and_private_to_reader', bookmarkAgain, 204, 'reader', bookmarkCount.rows[0]?.count === '1');
    const coverBefore = await request('GET', `/api/v1/media/${coverMediaId}`);
    record('active_creator_cover_streams_with_caching_disabled', coverBefore, 200, 'anonymous',
      coverBefore.headers['content-type'] === 'image/jpeg' && !coverBefore.headers.location &&
      String(coverBefore.headers['cache-control']).includes('no-store'));

    const copyObjectToKey = app.mediaStorage.copyObjectToKey.bind(app.mediaStorage);
    const deleteObject = app.mediaStorage.deleteObject.bind(app.mediaStorage);
    app.mediaStorage.copyObjectToKey = async () => { throw new ObjectCopyError(); };
    const failedHide = await request('POST', '/api/v1/moderation/actions', actors.get('moderator'), {
      targetType: 'story', targetId: storyId, action: 'hide_story', reason: 'Synthetic storage failure test.',
    });
    const storyAfterFailedHide = await controlPool!.query<{ status: string }>('SELECT status FROM stories WHERE id=$1', [storyId]);
    record('failed_cover_rotation_does_not_commit_takedown', failedHide, 503, 'moderator', storyAfterFailedHide.rows[0]?.status === 'published');
    app.mediaStorage.copyObjectToKey = copyObjectToKey;

    const moderationStateSnapshot = () => controlPool!.query<{
      story_status: string; story_visibility: string; story_version: number; media_key: string;
      report_status: string; removal_pending: boolean; report_open: boolean; action_count: string; outbox_count: string;
    }>(
      `SELECT s.status::text AS story_status,s.visibility::text AS story_visibility,s.version AS story_version,
         m.object_key AS media_key,r.status::text AS report_status,r.removal_pending,(r.closed_at IS NULL) AS report_open,
         (SELECT count(*)::text FROM public.moderation_actions a WHERE a.target_type='story' AND a.target_id=s.id) AS action_count,
         (SELECT count(*)::text FROM public.media_key_revocations q JOIN public.moderation_actions a ON a.id=q.moderation_action_id
           WHERE a.target_type='story' AND a.target_id=s.id) AS outbox_count
       FROM public.stories s JOIN public.media_assets m ON m.id=$2 JOIN public.reports r ON r.id=$3 WHERE s.id=$1`,
      [storyId, coverMediaId, reportId],
    );
    compensationWarnings.length = 0;
    const enqueueFailureBefore = (await moderationStateSnapshot()).rows[0];
    const enqueueFailureCopies: string[] = [];
    const enqueueFailureDeletes: string[] = [];
    let enqueueRollbackStateAtDelete: Awaited<ReturnType<typeof moderationStateSnapshot>>['rows'][number] | undefined;
    app.mediaStorage.copyObjectToKey = async (sourceKey, destinationKey) => {
      enqueueFailureCopies.push(destinationKey);
      rotatedObjectKeys.push({ sourceKey, destinationKey });
    };
    app.mediaStorage.deleteObject = async (destinationKey) => {
      enqueueFailureDeletes.push(destinationKey);
      enqueueRollbackStateAtDelete = (await moderationStateSnapshot()).rows[0];
    };
    await controlPool!.query('REVOKE EXECUTE ON FUNCTION public.nova_enqueue_media_key_revocation(uuid,uuid,text,text) FROM nova_fastify_runtime');
    let enqueueFailure: TestResponse;
    try {
      enqueueFailure = await request('POST', '/api/v1/moderation/actions', actors.get('moderator'), {
        targetType: 'story', targetId: storyId, action: 'hide_story', reason: 'Synthetic enqueue failure compensation test.',
      });
    } finally {
      await controlPool!.query('GRANT EXECUTE ON FUNCTION public.nova_enqueue_media_key_revocation(uuid,uuid,text,text) TO nova_fastify_runtime');
    }
    const enqueueFailureAfter = (await moderationStateSnapshot()).rows[0];
    const enqueueFailureBody = JSON.stringify(enqueueFailure!.json());
    record('enqueue_failure_rolls_back_before_successful_copy_compensation', enqueueFailure!, 503, 'moderator',
      enqueueFailureCopies.length === 1 && enqueueFailureDeletes.length === 1
        && enqueueFailureDeletes[0] === enqueueFailureCopies[0]
        && JSON.stringify(enqueueRollbackStateAtDelete) === JSON.stringify(enqueueFailureBefore)
        && JSON.stringify(enqueueFailureAfter) === JSON.stringify(enqueueFailureBefore)
        && enqueueFailure!.json().error?.code === 'MEDIA_REVOCATION_UNAVAILABLE'
        && enqueueFailure!.json().error?.message === "We couldn't confirm the status. Refresh before trying again."
        && enqueueFailure!.json().removal === undefined
        && !/42501|SQLSTATE|permission denied|127\.0\.0\.1|Synthetic/.test(enqueueFailureBody)
        && !enqueueFailureCopies.some((key) => enqueueFailureBody.includes(key)));

    const commitFailureBefore = (await moderationStateSnapshot()).rows[0];
    const commitFailureCopies: string[] = [];
    const commitFailureDeletes: string[] = [];
    let commitRollbackStateAtDelete: Awaited<ReturnType<typeof moderationStateSnapshot>>['rows'][number] | undefined;
    await controlPool!.query(`
      CREATE FUNCTION public.nova_test_fail_revocation_commit() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'test-only deferred commit failure' USING ERRCODE='23514'; END $$;
      CREATE CONSTRAINT TRIGGER nova_test_fail_revocation_commit
      AFTER INSERT ON public.media_key_revocations DEFERRABLE INITIALLY DEFERRED
      FOR EACH ROW EXECUTE FUNCTION public.nova_test_fail_revocation_commit()`);
    compensationWarnings.length = 0;
    app.mediaStorage.copyObjectToKey = async (sourceKey, destinationKey) => {
      commitFailureCopies.push(destinationKey);
      rotatedObjectKeys.push({ sourceKey, destinationKey });
    };
    app.mediaStorage.deleteObject = async (destinationKey) => {
      commitFailureDeletes.push(destinationKey);
      commitRollbackStateAtDelete = (await moderationStateSnapshot()).rows[0];
      throw new Error('Synthetic provider endpoint detail must remain internal.');
    };
    let commitFailure: TestResponse | undefined;
    try {
      commitFailure = await request('POST', '/api/v1/moderation/actions', actors.get('moderator'), {
        targetType: 'story', targetId: storyId, action: 'hide_story', reason: 'Synthetic commit failure compensation test.',
      });
    } finally {
      await controlPool!.query('DROP TRIGGER IF EXISTS nova_test_fail_revocation_commit ON public.media_key_revocations; DROP FUNCTION IF EXISTS public.nova_test_fail_revocation_commit()');
      app.mediaStorage.copyObjectToKey = copyObjectToKey;
      app.mediaStorage.deleteObject = deleteObject;
    }
    const commitFailureAfter = (await moderationStateSnapshot()).rows[0];
    const commitFailureBody = JSON.stringify(commitFailure?.json());
    const cleanupWarning = compensationWarnings.find((entry) => entry.mediaId === coverMediaId
      && entry.event === 'media_revocation_copy_compensation_failed');
    record('commit_failure_cleanup_failure_is_log_only_and_state_remains_open', commitFailure!, 503, 'moderator',
      commitFailureCopies.length === 1 && commitFailureDeletes.length === 1
        && commitFailureDeletes[0] === commitFailureCopies[0]
        && JSON.stringify(commitRollbackStateAtDelete) === JSON.stringify(commitFailureBefore)
        && JSON.stringify(commitFailureAfter) === JSON.stringify(commitFailureBefore)
        && commitFailure!.json().error?.code === 'TRANSACTION_OUTCOME_UNCONFIRMED'
        && commitFailure!.json().error?.message === "We couldn't confirm the status. Refresh before trying again."
        && commitFailure!.json().removal === undefined
        && !/23514|SQLSTATE|test-only|provider|127\.0\.0\.1/.test(commitFailureBody)
        && !commitFailureCopies.some((key) => commitFailureBody.includes(key))
        && cleanupWarning?.errorType === 'Error'
        && cleanupWarning?.reconciliationRequired === true
        && cleanupWarning?.durableReconciliationRecorded === false
        && cleanupWarning?.alertSent === false
        && cleanupWarning?.destinationKeyPresent === true
        && !commitFailureCopies.some((key) => JSON.stringify(cleanupWarning).includes(key)));

    const successfulCleanupBefore = (await moderationStateSnapshot()).rows[0];
    const successfulCleanupCopies: string[] = [];
    const successfulCleanupDeletes: string[] = [];
    let successfulCleanupStateAtDelete: Awaited<ReturnType<typeof moderationStateSnapshot>>['rows'][number] | undefined;
    await controlPool!.query(`
      CREATE FUNCTION public.nova_test_fail_revocation_commit() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'test-only deferred commit failure' USING ERRCODE='23514'; END $$;
      CREATE CONSTRAINT TRIGGER nova_test_fail_revocation_commit
      AFTER INSERT ON public.media_key_revocations DEFERRABLE INITIALLY DEFERRED
      FOR EACH ROW EXECUTE FUNCTION public.nova_test_fail_revocation_commit()`);
    compensationWarnings.length = 0;
    app.mediaStorage.copyObjectToKey = async (sourceKey, destinationKey) => {
      successfulCleanupCopies.push(destinationKey);
      rotatedObjectKeys.push({ sourceKey, destinationKey });
    };
    app.mediaStorage.deleteObject = async (destinationKey) => {
      successfulCleanupDeletes.push(destinationKey);
      successfulCleanupStateAtDelete = (await moderationStateSnapshot()).rows[0];
    };
    let successfulCleanupResponse: TestResponse | undefined;
    try {
      successfulCleanupResponse = await request('POST', '/api/v1/moderation/actions', actors.get('moderator'), {
        targetType: 'story', targetId: storyId, action: 'hide_story', reason: 'Synthetic successful compensation test.',
      });
    } finally {
      await controlPool!.query('DROP TRIGGER IF EXISTS nova_test_fail_revocation_commit ON public.media_key_revocations; DROP FUNCTION IF EXISTS public.nova_test_fail_revocation_commit()');
      app.mediaStorage.copyObjectToKey = copyObjectToKey;
      app.mediaStorage.deleteObject = deleteObject;
    }
    const successfulCleanupAfter = (await moderationStateSnapshot()).rows[0];
    const successfulCleanupBody = JSON.stringify(successfulCleanupResponse?.json());
    record('definite_commit_failure_successfully_deletes_copy_without_removal_claim', successfulCleanupResponse!, 503, 'moderator',
      successfulCleanupCopies.length === 1 && successfulCleanupDeletes.length === 1
        && successfulCleanupDeletes[0] === successfulCleanupCopies[0]
        && JSON.stringify(successfulCleanupStateAtDelete) === JSON.stringify(successfulCleanupBefore)
        && JSON.stringify(successfulCleanupAfter) === JSON.stringify(successfulCleanupBefore)
        && successfulCleanupResponse!.json().error?.code === 'TRANSACTION_OUTCOME_UNCONFIRMED'
        && successfulCleanupResponse!.json().error?.message === "We couldn't confirm the status. Refresh before trying again."
        && successfulCleanupResponse!.json().removal === undefined
        && !/23514|SQLSTATE|test-only|provider|127\.0\.0\.1/.test(successfulCleanupBody)
        && !successfulCleanupCopies.some((key) => successfulCleanupBody.includes(key))
        && compensationWarnings.length === 0);

    const unknownCommitBefore = (await moderationStateSnapshot()).rows[0];
    const unknownCommitCopies: string[] = [];
    const unknownCommitDeletes: string[] = [];
    const unknownOriginalCopy = app.mediaStorage.copyObjectToKey;
    const unknownOriginalDelete = app.mediaStorage.deleteObject;
    await controlPool!.query(`
      CREATE FUNCTION public.nova_test_unknown_commit_sqlstate() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN RAISE EXCEPTION 'test-only ambiguous server outcome' USING ERRCODE='58030'; END $$;
      CREATE CONSTRAINT TRIGGER nova_test_unknown_commit_sqlstate
      AFTER INSERT ON public.media_key_revocations DEFERRABLE INITIALLY DEFERRED
      FOR EACH ROW EXECUTE FUNCTION public.nova_test_unknown_commit_sqlstate()`);
    app.mediaStorage.copyObjectToKey = async (sourceKey, destinationKey) => {
      unknownCommitCopies.push(destinationKey);
      rotatedObjectKeys.push({ sourceKey, destinationKey });
    };
    app.mediaStorage.deleteObject = async (destinationKey) => { unknownCommitDeletes.push(destinationKey); };
    let unknownCommitResponse: TestResponse | undefined;
    try {
      unknownCommitResponse = await request('POST', '/api/v1/moderation/actions', actors.get('moderator'), {
        targetType: 'story', targetId: storyId, action: 'hide_story', reason: 'Synthetic unknown SQLSTATE test.',
      });
    } finally {
      await controlPool!.query('DROP TRIGGER IF EXISTS nova_test_unknown_commit_sqlstate ON public.media_key_revocations; DROP FUNCTION IF EXISTS public.nova_test_unknown_commit_sqlstate()');
      app.mediaStorage.copyObjectToKey = unknownOriginalCopy;
      app.mediaStorage.deleteObject = unknownOriginalDelete;
    }
    const unknownCommitAfter = (await moderationStateSnapshot()).rows[0];
    const unknownCommitBody = JSON.stringify(unknownCommitResponse?.json());
    record('unknown_commit_server_sqlstate_preserves_copy_and_requires_refresh', unknownCommitResponse!, 503, 'moderator',
      unknownCommitCopies.length === 1 && unknownCommitDeletes.length === 0
        && JSON.stringify(unknownCommitAfter) === JSON.stringify(unknownCommitBefore)
        && unknownCommitResponse!.json().error?.code === 'TRANSACTION_OUTCOME_UNCONFIRMED'
        && unknownCommitResponse!.json().error?.message === "We couldn't confirm the status. Refresh before trying again."
        && unknownCommitResponse!.json().removal === undefined
        && !/58030|SQLSTATE|test-only|provider|127\.0\.0\.1/.test(unknownCommitBody)
        && !unknownCommitCopies.some((key) => unknownCommitBody.includes(key)));
    console.log('SAFE_COMMIT_SQLSTATE_CLASSIFICATION', JSON.stringify({
      knownConstraintAbortCompensates: successfulCleanupCopies.length === 1
        && successfulCleanupDeletes.length === 1 && JSON.stringify(successfulCleanupAfter) === JSON.stringify(successfulCleanupBefore),
      unknownServerSqlstatePreservesCopy: unknownCommitCopies.length === 1 && unknownCommitDeletes.length === 0,
      unknownServerSqlstateLeavesDatabaseUnchanged: JSON.stringify(unknownCommitAfter) === JSON.stringify(unknownCommitBefore),
      refreshRequired: unknownCommitResponse?.json().error?.code === 'TRANSACTION_OUTCOME_UNCONFIRMED',
    }));

    app.mediaStorage.deleteObject = async () => { throw new Error('Synthetic storage delete failure.'); };
    const hideAction = await request('POST', '/api/v1/moderation/actions', actors.get('moderator'), {
      targetType: 'story', targetId: storyId, action: 'hide_story', reason: 'Synthetic takedown test.',
    });
    record('moderator_takes_down_cover_fixture_story_with_visible_pending_state', hideAction, 202, 'moderator',
      hideAction.json().removal?.status === 'pending'
        && hideAction.json().removal?.label === 'Removal pending — cleanup could not be confirmed');
    const initialRevocation = await controlPool!.query<{ attempt_count: number; escalated_at: Date | null }>(
      'SELECT attempt_count, escalated_at FROM media_key_revocations WHERE media_id=$1', [coverMediaId],
    );
    record('new_revocation_stays_pending_unverified_before_worker_attempt', hideAction, 202, 'moderator',
      initialRevocation.rows[0]?.attempt_count === 0 && initialRevocation.rows[0]?.escalated_at === null);
    const keyAfterTakedown = await controlPool!.query<{ object_key: string }>('SELECT object_key FROM media_assets WHERE id=$1', [coverMediaId]);
    record('takedown_rotates_origin_cover_key_before_action_completes', hideAction, 202, 'moderator',
      keyAfterTakedown.rows[0]?.object_key !== initialCoverKey && rotatedObjectKeys.some((entry) => entry.sourceKey === initialCoverKey));
    const sameCoverUrlAfterTakedown = await request('GET', `/api/v1/media/${coverMediaId}`);
    record('api_cover_is_fail_closed_while_private_takedown_revocation_is_pending', sameCoverUrlAfterTakedown, 404, 'anonymous');
    const ownerReadWhilePending = await request('GET', `/api/v1/media/${coverMediaId}`, storyOwner);
    record('owner_cannot_bypass_pending_cover_revocation', ownerReadWhilePending, 404, 'owner');
    await controlPool!.query(
      "UPDATE public.stories SET status='published',visibility='public',published_at=now(),updated_at=now() WHERE id=$1",
      [sharedStoryId],
    );
    const sharedStoryReportResponse = await request('POST', '/api/v1/reports', actors.get('admin'), {
      targetType: 'story', targetId: sharedStoryId, reason: 'other', details: 'Fictional second-target policy probe.',
    });
    record('second_story_report_created_for_scoped_policy_probe', sharedStoryReportResponse, 201, 'admin');
    const sharedStoryReportId = sharedStoryReportResponse.json().data.caseId as string;
    createdReportIds.push(sharedStoryReportId);
    const adminReporter = actors.get('admin')!;
    const reportPageOne = await request('GET', '/api/v1/me/reports?limit=1', adminReporter);
    const reportPageOneData = reportPageOne.json().data as Array<Record<string, unknown>>;
    const reportPageOneCursor = reportPageOne.json().page?.nextCursor;
    record('reporter_collection_first_page_is_safe_and_paginated', reportPageOne, 200, 'admin',
      reportPageOneData.length === 1 && reportPageOne.json().page?.hasMore === true
        && typeof reportPageOneCursor === 'string'
        && [reportId, sharedStoryReportId].includes(String(reportPageOneData[0]?.caseId))
        && !('targetId' in (reportPageOneData[0] ?? {})) && !('reason' in (reportPageOneData[0] ?? {}))
        && !('details' in (reportPageOneData[0] ?? {}))
        && typeof reportPageOneData[0]?.removalPending === 'boolean'
        && ['pending', 'not_pending'].includes(String((reportPageOneData[0]?.removal as Record<string, unknown> | undefined)?.status)));
    const reportPageTwo = await request(
      'GET', `/api/v1/me/reports?limit=1&cursor=${encodeURIComponent(String(reportPageOneCursor ?? ''))}`, adminReporter,
    );
    const reportPageTwoData = reportPageTwo.json().data as Array<Record<string, unknown>>;
    record('reporter_collection_second_page_completes_own_cases', reportPageTwo, 200, 'admin',
      reportPageTwoData.length === 1 && reportPageTwo.json().page?.hasMore === false
        && reportPageTwo.json().page?.nextCursor === null
        && [reportId, sharedStoryReportId].includes(String(reportPageTwoData[0]?.caseId))
        && String(reportPageOneData[0]?.caseId) !== String(reportPageTwoData[0]?.caseId)
        && !('targetId' in (reportPageTwoData[0] ?? {})) && !('details' in (reportPageTwoData[0] ?? {})));
    const otherReporterCollection = await request('GET', '/api/v1/me/reports', actors.get('reader'));
    record('other_reporter_cannot_list_another_reporters_cases', otherReporterCollection, 200, 'reader',
      otherReporterCollection.json().data.length === 0
        && otherReporterCollection.json().page?.hasMore === false
        && otherReporterCollection.json().page?.nextCursor === null);
    const nonHideActionId = randomUUID();
    await controlPool!.query(
      `INSERT INTO public.moderation_actions(id,moderator_id,target_type,target_id,action,reason)
       VALUES($1,$2,'story',$3,'restore_story','Disposable non-hide action policy probe.')`,
      [nonHideActionId, actors.get('moderator')!.id, storyId],
    );
    const enqueuerVisibleReports = async (storyContext: string, actionContext: string): Promise<string[]> => {
      const client = await controlPool!.connect();
      try {
        await client.query('BEGIN');
        await client.query('SET LOCAL ROLE nova_revocation_enqueuer_owner');
        await client.query(
          "SELECT set_config('nova.fixture_enqueue_story_id',$1,true),set_config('nova.fixture_enqueue_action_id',$2,true)",
          [storyContext, actionContext],
        );
        const result = await client.query<{ id: string }>(
          'SELECT id::text AS id FROM public.reports WHERE id=ANY($1::uuid[]) ORDER BY id',
          [[reportId, sharedStoryReportId]],
        );
        await client.query('ROLLBACK');
        return result.rows.map((row) => row.id);
      } finally {
        client.release();
      }
    };
    const enqueuerUpdateCount = async (storyContext: string, actionContext: string, reportTargetId: string): Promise<number> => {
      const client = await controlPool!.connect();
      try {
        await client.query('BEGIN');
        await client.query('SET LOCAL ROLE nova_revocation_enqueuer_owner');
        await client.query(
          "SELECT set_config('nova.fixture_enqueue_story_id',$1,true),set_config('nova.fixture_enqueue_action_id',$2,true)",
          [storyContext, actionContext],
        );
        const result = await client.query(
          'UPDATE public.reports SET removal_pending=true WHERE id=$1 RETURNING id', [reportTargetId],
        );
        await client.query('ROLLBACK');
        return result.rowCount ?? 0;
      } finally {
        client.release();
      }
    };
    const hideActionId = String(hideAction.json().data?.id ?? '');
    const validBoundVisible = await enqueuerVisibleReports(storyId, hideActionId);
    const absentContextVisible = await enqueuerVisibleReports('', '');
    const malformedContextVisible = await enqueuerVisibleReports('not-a-uuid', 'also-not-a-uuid');
    const forgedStoryVisible = await enqueuerVisibleReports(sharedStoryId, hideActionId);
    const invalidActionVisible = await enqueuerVisibleReports(storyId, randomUUID());
    const nonHideActionVisible = await enqueuerVisibleReports(storyId, nonHideActionId);
    const validBoundUpdateCount = await enqueuerUpdateCount(storyId, hideActionId, reportId);
    const absentContextUpdateCount = await enqueuerUpdateCount('', '', reportId);
    const malformedContextUpdateCount = await enqueuerUpdateCount('not-a-uuid', 'also-not-a-uuid', reportId);
    const forgedStoryUpdateCount = await enqueuerUpdateCount(sharedStoryId, hideActionId, sharedStoryReportId);
    const invalidActionUpdateCount = await enqueuerUpdateCount(storyId, randomUUID(), reportId);
    const nonHideActionUpdateCount = await enqueuerUpdateCount(storyId, nonHideActionId, reportId);
    const runtimeReportPrivilege = await controlPool!.query<{
      select_granted: boolean; forced_rls: boolean; scoped_policy: boolean;
    }>(
      `SELECT pg_catalog.has_table_privilege('nova_fastify_runtime','public.reports','SELECT') AS select_granted,
         (SELECT relrowsecurity AND relforcerowsecurity FROM pg_catalog.pg_class WHERE oid='public.reports'::regclass) AS forced_rls,
         EXISTS (SELECT 1 FROM pg_catalog.pg_policies WHERE schemaname='public' AND tablename='reports'
           AND policyname='reports_read_scoped' AND roles @> ARRAY['nova_fastify_runtime']::name[]) AS scoped_policy`,
    );
    const runtimeVisibleReports = async (actor: Actor): Promise<number> => {
      const client = await controlPool!.connect();
      try {
        await client.query('BEGIN');
        await client.query('SET LOCAL ROLE nova_fastify_runtime');
        await client.query(
          "SELECT set_config('app.user_id',$1,true),set_config('app.auth_subject',$2,true),set_config('app.user_role',$3,true)",
          [actor.id, actor.subject, actor.subject.endsWith(':moderator') ? 'moderator' : actor.subject.endsWith(':admin') ? 'admin' : 'reader'],
        );
        const result = await client.query<{ count: string }>(
          'SELECT count(*)::text AS count FROM public.reports WHERE id=ANY($1::uuid[])',
          [[reportId, sharedStoryReportId]],
        );
        await client.query('ROLLBACK');
        return Number(result.rows[0]?.count ?? 0);
      } finally {
        client.release();
      }
    };
    const runtimeReaderCount = await runtimeVisibleReports(actors.get('reader')!);
    const runtimeReporterCount = await runtimeVisibleReports(actors.get('admin')!);
    const runtimeModeratorCount = await runtimeVisibleReports(actors.get('moderator')!);
    const policyProbesPassed = validBoundVisible.length === 1 && validBoundVisible[0] === reportId
      && absentContextVisible.length === 0 && malformedContextVisible.length === 0
      && forgedStoryVisible.length === 0 && invalidActionVisible.length === 0 && nonHideActionVisible.length === 0
      && validBoundUpdateCount === 1 && absentContextUpdateCount === 0 && malformedContextUpdateCount === 0
      && forgedStoryUpdateCount === 0 && invalidActionUpdateCount === 0 && nonHideActionUpdateCount === 0
      && runtimeReportPrivilege.rows[0]?.select_granted === true
      && runtimeReportPrivilege.rows[0]?.forced_rls === true && runtimeReportPrivilege.rows[0]?.scoped_policy === true
      && runtimeReaderCount === 0 && runtimeReporterCount === 2 && runtimeModeratorCount === 2;
    console.log('SAFE_ENQUEUER_ACTION_STORY_BINDING', JSON.stringify({
      validBoundReadCount: validBoundVisible.length,
      deniedReadCounts: [absentContextVisible.length, malformedContextVisible.length, forgedStoryVisible.length,
        invalidActionVisible.length, nonHideActionVisible.length],
      validBoundUpdateCount,
      deniedUpdateCounts: [absentContextUpdateCount, malformedContextUpdateCount, forgedStoryUpdateCount,
        invalidActionUpdateCount, nonHideActionUpdateCount],
      runtimeReaderCount, runtimeReporterCount, runtimeModeratorCount,
      forcedRls: runtimeReportPrivilege.rows[0]?.forced_rls === true,
    }));
    evidence.push({ check: 'reports_enqueuer_and_runtime_rls_policy_scope', result: policyProbesPassed ? 'PASS' : 'FAIL',
      requestId: 'database-policy-probe', actorRole: 'nova_revocation_enqueuer_owner/nova_fastify_runtime', timestamp: new Date().toISOString() });
    expect(policyProbesPassed, 'report SELECT/UPDATE policy scope and action-target binding').toBe(true);
    const reporterCasePending = await request('GET', `/api/v1/me/reports/${reportId}`, actors.get('admin'));
    const pendingReportDbState = await controlPool!.query<{
      status: string; removal_pending: boolean; report_open: boolean; target_matches: boolean; queued_revocations: string;
    }>(
      `SELECT r.status::text,r.removal_pending,(r.closed_at IS NULL) AS report_open,
         (r.target_type::text='story' AND r.target_id=$2) AS target_matches,
         (SELECT count(*)::text FROM public.media_key_revocations q JOIN public.moderation_actions a ON a.id=q.moderation_action_id
           WHERE a.target_type='story' AND a.target_id=$2) AS queued_revocations
       FROM public.reports r WHERE r.id=$1`, [reportId, storyId],
    );
    const enqueueLinkState = await controlPool!.query<{
      action_exists: boolean; action_target_matches_story: boolean; queue_exists_for_action: boolean;
      linked_revocations: string; expected_media_and_source_key: boolean;
    }>(
      `SELECT EXISTS (SELECT 1 FROM public.moderation_actions a WHERE a.id=$1) AS action_exists,
         EXISTS (SELECT 1 FROM public.moderation_actions a
           WHERE a.id=$1 AND a.target_type::text='story' AND a.target_id=$2 AND a.action='hide_story')
           AS action_target_matches_story,
         EXISTS (SELECT 1 FROM public.media_key_revocations q WHERE q.moderation_action_id=$1) AS queue_exists_for_action,
         (SELECT count(*)::text FROM public.media_key_revocations q WHERE q.moderation_action_id=$1) AS linked_revocations,
         EXISTS (SELECT 1 FROM public.media_key_revocations q JOIN public.media_assets m ON m.id=q.media_id
           WHERE q.moderation_action_id=$1 AND q.media_id=$3 AND q.source_key=$4 AND m.object_key<>$4)
           AS expected_media_and_source_key`,
      [hideAction.json().data?.id, storyId, coverMediaId, initialCoverKey],
    );
    console.log('SAFE_REPORT_PENDING_METADATA', JSON.stringify({
      db: pendingReportDbState.rows[0] ?? null,
      enqueue: enqueueLinkState.rows[0] ?? null,
      api: { status: reporterCasePending.json().data?.status, statusLabel: reporterCasePending.json().data?.statusLabel,
        removalStatus: reporterCasePending.json().data?.removal?.status,
        removalPending: reporterCasePending.json().data?.removalPending },
    }));
    record('reporter_sees_separate_open_report_and_pending_removal_states', reporterCasePending, 200, 'admin',
      reporterCasePending.json().data?.status === 'reviewing'
        && reporterCasePending.json().data?.statusLabel === 'Under review'
        && reporterCasePending.json().data?.removal?.status === 'pending'
        && reporterCasePending.json().data?.removal?.label === 'Removal pending — cleanup could not be confirmed'
        && reporterCasePending.json().data?.removalPending === true
        && pendingReportDbState.rows[0]?.status === 'reviewing'
        && pendingReportDbState.rows[0]?.removal_pending === true
        && pendingReportDbState.rows[0]?.report_open === true
        && Number(pendingReportDbState.rows[0]?.queued_revocations) === 1
        && pendingReportDbState.rows[0]?.target_matches === true);
    const moderatorQueuePending = await request('GET', '/api/v1/moderation/reports?status=reviewing', actors.get('moderator'));
    record('moderator_queue_exposes_removal_pending_case', moderatorQueuePending, 200, 'moderator',
      moderatorQueuePending.json().data.some((row: { id: string; removalPending: boolean }) => row.id === reportId && row.removalPending));
    const prematureReportClose = await request('PATCH', `/api/v1/moderation/reports/${reportId}`, actors.get('moderator'), { status: 'closed' });
    const reportAfterUnsupportedClose = await controlPool!.query<{ status: string; removal_pending: boolean }>(
      'SELECT status::text, removal_pending FROM reports WHERE id=$1', [reportId],
    );
    record('report_status_patch_is_not_integrated_and_leaves_case_open', prematureReportClose, 501, 'moderator',
      prematureReportClose.json().error?.code === 'NOT_INTEGRATED'
        && reportAfterUnsupportedClose.rows[0]?.status === 'reviewing'
        && reportAfterUnsupportedClose.rows[0]?.removal_pending === true);

    const sharedStoryRead = await request('GET', `/api/v1/stories/${sharedStoryId}`);
    record('still_live_story_sharing_cover_remains_readable', sharedStoryRead, 200, 'anonymous');
    const sharedCoverRead = await request('GET', `/api/v1/media/${coverMediaId}`);
    record('shared_cover_api_access_is_preserved_for_other_live_story', sharedCoverRead, 200, 'anonymous');

    app.mediaStorage.deleteObject = deleteObject;
    await controlPool!.query('UPDATE media_key_revocations SET retry_after=now() WHERE media_id=$1', [coverMediaId]);
    await processPendingMediaKeyRevocations(app);
    const pendingAfterSuccessfulDelete = await controlPool!.query<{ attempt_count: number; escalated_at: Date | null }>(
      'SELECT attempt_count, escalated_at FROM media_key_revocations WHERE media_id=$1', [coverMediaId],
    );
    const reporterCaseAfterDelete = await request('GET', `/api/v1/me/reports/${reportId}`, actors.get('admin'));
    record('storage_key_delete_alone_does_not_claim_verified_purge_or_close_case', reporterCaseAfterDelete, 200, 'admin',
      pendingAfterSuccessfulDelete.rowCount === 1 && pendingAfterSuccessfulDelete.rows[0]?.attempt_count === 1
        && pendingAfterSuccessfulDelete.rows[0]?.escalated_at === null
        && reporterCaseAfterDelete.json().data?.status === 'reviewing'
        && reporterCaseAfterDelete.json().data?.statusLabel === 'Under review'
        && reporterCaseAfterDelete.json().data?.removal?.status === 'pending'
        && reporterCaseAfterDelete.json().data?.removal?.label === 'Removal pending — cleanup could not be confirmed'
        && reporterCaseAfterDelete.json().data?.removalPending === true);

    const userReportResponse = await request('POST', '/api/v1/reports', actors.get('admin'), {
      targetType: 'user', targetId: owner.id, reason: 'other', details: 'Fictional suspension test report.',
    });
    record('user_report_created_for_unintegrated_action_test', userReportResponse, 201, 'admin');
    const userReportId = userReportResponse.json().data.caseId as string;
    createdReportIds.push(userReportId);

    const suspendAction = await request('POST', '/api/v1/moderation/actions', actors.get('moderator'), {
      targetType: 'user', targetId: owner.id, action: 'suspend_user', reason: 'Synthetic unsupported action test.',
    });
    const userStateAfterUnsupportedAction = await controlPool!.query<{ status: string }>('SELECT status FROM users WHERE id=$1', [owner.id]);
    const userActionRevocations = await controlPool!.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM media_key_revocations r
       JOIN moderation_actions a ON a.id=r.moderation_action_id
       WHERE a.target_type='user' AND a.target_id=$1`, [owner.id],
    );
    record('suspend_user_is_501_and_has_no_side_effects', suspendAction, 501, 'moderator',
      suspendAction.json().error?.code === 'NOT_INTEGRATED'
        && userStateAfterUnsupportedAction.rows[0]?.status === 'active'
        && userActionRevocations.rows[0]?.count === '0');
    const userCaseAfterUnsupportedAction = await request('GET', `/api/v1/me/reports/${userReportId}`, actors.get('admin'));
    record('unsupported_suspension_leaves_report_open_and_unmodified', userCaseAfterUnsupportedAction, 200, 'admin',
      userCaseAfterUnsupportedAction.json().data?.statusLabel === 'Received'
        && userCaseAfterUnsupportedAction.json().data?.removal?.status === 'not_pending'
        && userCaseAfterUnsupportedAction.json().data?.removal?.label === undefined
        && userCaseAfterUnsupportedAction.json().data?.removalPending === false);
    const directRead = await request('GET', `/api/v1/stories/${storyId}`);
    record('hidden_creator_story_returns_neutral_not_found', directRead, 404, 'anonymous');
    const authorSearch = await request('GET', `/api/v1/stories?author=${encodeURIComponent(username)}`);
    record('hidden_creator_story_excluded_from_author_search', authorSearch, 200, 'anonymous',
      !authorSearch.json().data.some((row: { id: string }) => row.id === storyId));
    const bookmarkList = await request('GET', '/api/v1/me/bookmarks', reader);
    record('hidden_creator_story_removed_from_bookmarks', bookmarkList, 200, 'reader',
      !bookmarkList.json().data.some((row: { id: string }) => row.id === storyId));
    const newBookmark = await request('PUT', `/api/v1/me/bookmarks/${storyId}`, reader);
    record('hidden_creator_story_cannot_be_bookmarked', newBookmark, 404, 'reader');
    const deleteHiddenBookmark = await request('DELETE', `/api/v1/me/bookmarks/${storyId}`, reader);
    const deleteHiddenBookmarkAgain = await request('DELETE', `/api/v1/me/bookmarks/${storyId}`, reader);
    const hiddenBookmarkCount = await controlPool!.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM public.bookmarks WHERE user_id=$1 AND story_id=$2', [reader.id, storyId],
    );
    record('own_bookmark_delete_remains_idempotent_after_story_hide', deleteHiddenBookmarkAgain, 204, 'reader',
      deleteHiddenBookmark.statusCode === 204 && hiddenBookmarkCount.rows[0]?.count === '0');
    const comments = await request('GET', `/api/v1/stories/${storyId}/comments`);
    record('hidden_creator_story_comments_are_hidden', comments, 200, 'anonymous', comments.json().data.length === 0);
    const newComment = await request('POST', `/api/v1/stories/${storyId}/comments`, reader, { body: 'Fictional test comment.' });
    record('comment_creation_remains_explicitly_unavailable_after_hide', newComment, 501, 'reader',
      newComment.json().error?.code === 'NOT_INTEGRATED'
        && !/42501|SQLSTATE|permission denied/i.test(JSON.stringify(newComment.json())));
    const sameCoverUrlAfterHide = await request('GET', `/api/v1/media/${coverMediaId}`);
    const stillLiveSharedStory = await request('GET', `/api/v1/stories/${sharedStoryId}`);
    record('shared_cover_remains_available_only_through_other_live_story_while_removal_is_pending', sameCoverUrlAfterHide, 200, 'anonymous',
      pendingAfterSuccessfulDelete.rowCount === 1 && stillLiveSharedStory.statusCode === 200);
  });

  it('limits content-report details to the reporter and dedicated moderator', async () => {
    const owner = actors.get('owner')!;
    const reporter = actors.get('reader')!;
    const moderator = actors.get('moderator')!;
    const storyId = 'e3000000-0000-4000-8000-000000000002';
    const publishedFixture = await request('GET', `/api/v1/stories/${storyId}`);
    record('report_fixture_is_seeded_public', publishedFixture, 200, 'anonymous',
      publishedFixture.json().data?.status === 'published' && publishedFixture.json().data?.visibility === 'public');

    const submitted = await request('POST', '/api/v1/reports', reporter, {
      targetType: 'story', targetId: storyId, reason: 'spam', details: 'Fictional non-sensitive test report detail.',
    });
    record('reporter_creates_case', submitted, 201, 'reader', submitted.json().data?.statusLabel === 'Received' && Boolean(submitted.json().data?.statusUrl));
    const caseId = submitted.json().data?.caseId as string;
    createdReportIds.push(caseId);
    const ownStatus = await request('GET', `/api/v1/me/reports/${caseId}`, reporter);
    record('reporter_sees_status_only', ownStatus, 200, 'reporter', ownStatus.json().data?.statusLabel === 'Received' && ownStatus.json().data?.details === undefined);
    const otherStatus = await request('GET', `/api/v1/me/reports/${caseId}`, owner);
    record('other_account_cannot_read_report', otherStatus, 404, 'owner');
    const moderatorQueue = await request('GET', '/api/v1/moderation/reports?status=received', moderator);
    record('dedicated_moderator_can_read_report_details', moderatorQueue, 200, 'moderator',
      Array.isArray(moderatorQueue.json().data) && moderatorQueue.json().data.some((row: { id: string }) => row.id === caseId));
    const readerQueue = await request('GET', '/api/v1/moderation/reports?status=received', reporter);
    record('reporter_cannot_read_moderation_queue', readerQueue, 403, 'reader');

    const changed = await request('PATCH', `/api/v1/moderation/reports/${caseId}`, moderator, { status: 'reviewing' });
    record('report_status_update_is_not_integrated', changed, 501, 'moderator', changed.json().error?.code === 'NOT_INTEGRATED');
    const updatedStatus = await request('GET', `/api/v1/me/reports/${caseId}`, reporter);
    record('reporter_sees_original_open_status_after_unsupported_patch', updatedStatus, 200, 'reporter',
      updatedStatus.json().data?.statusLabel === 'Received');
  });

  it('keeps feedback and security reports private to their assigned staff roles and audits staff access', async () => {
    const reporter = actors.get('reader')!;
    const owner = actors.get('owner')!;
    const support = actors.get('support')!;
    const security = actors.get('security')!;

    const feedback = await request('POST', '/api/v1/feedback', reporter, {
      category: 'bug', summary: 'Fictional test issue', expectedBehavior: 'A test screen loads.', actualBehavior: 'The test screen does not load.',
    });
    record('feedback_case_created_with_received_status', feedback, 201, 'reader', feedback.json().data?.statusLabel === 'Received' && Boolean(feedback.json().data?.caseId));
    const feedbackId = feedback.json().data?.caseId as string;
    createdFeedbackIds.push(feedbackId);
    const supportDetail = await request('GET', `/api/v1/internal/feedback/${feedbackId}`, support);
    record('feedback_has_no_implicitly_attached_screenshot', supportDetail, 200, 'support', supportDetail.json().data?.hasScreenshot === false);
    record('support_reads_feedback_detail', supportDetail, 200, 'support', supportDetail.json().data?.summary === 'Fictional test issue');
    const feedbackPatch = await request('PATCH', `/api/v1/internal/feedback/${feedbackId}`, support, { status: 'triaged', recurrenceKey: 'draft.preview.test' });
    record('support_status_change_is_authorized', feedbackPatch, 200, 'support');
    const feedbackStatus = await request('GET', `/api/v1/me/feedback/${feedbackId}`, reporter);
    record('feedback_status_link_is_reporter_protected', feedbackStatus, 200, 'reporter', feedbackStatus.json().data?.statusLabel === 'Under review');
    const otherFeedback = await request('GET', `/api/v1/me/feedback/${feedbackId}`, owner);
    record('other_user_cannot_read_feedback_status', otherFeedback, 404, 'owner');
    const securityCannotReadFeedback = await request('GET', `/api/v1/internal/feedback/${feedbackId}`, security);
    record('security_role_cannot_read_support_feedback', securityCannotReadFeedback, 403, 'security');

    const screenshotMediaId = randomUUID();
    createdMediaIds.push(screenshotMediaId);
    await controlPool!.query(
      `INSERT INTO media_assets(id,owner_id,purpose,object_key,mime_type,size_bytes,status,ready_at)
       VALUES($1,$2,'feedback_screenshot',$3,'image/jpeg',128,'ready',now())`,
      [screenshotMediaId, reporter.id, `ready/${reporter.id}/${screenshotMediaId}.jpg`],
    );
    const feedbackCountBeforeScreenshot = await controlPool!.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM public.beta_feedback WHERE reporter_id=$1', [reporter.id],
    );
    const screenshotFeedback = await request('POST', '/api/v1/feedback', reporter, {
      category: 'usability', summary: 'Fictional selected screenshot', screenshotMediaId,
    });
    const feedbackCountAfterScreenshot = await controlPool!.query<{ count: string }>(
      'SELECT count(*)::text AS count FROM public.beta_feedback WHERE reporter_id=$1', [reporter.id],
    );
    record('feedback_screenshot_attachment_is_501_before_media_or_case_side_effects', screenshotFeedback, 501, 'reporter',
      screenshotFeedback.json().error?.code === 'NOT_INTEGRATED'
        && screenshotFeedback.json().error?.message === 'Feedback screenshot attachments are unavailable for the MVP. No changes were made.'
        && !/42501|SQLSTATE|permission denied/i.test(JSON.stringify(screenshotFeedback.json()))
        && feedbackCountAfterScreenshot.rows[0]?.count === feedbackCountBeforeScreenshot.rows[0]?.count);
    await controlPool!.query('UPDATE public.beta_feedback SET screenshot_media_id=$1 WHERE id=$2', [screenshotMediaId, feedbackId]);
    const historicalScreenshotDetail = await request('GET', `/api/v1/internal/feedback/${feedbackId}`, support);
    record('support_can_read_existing_private_screenshot_metadata', historicalScreenshotDetail, 200, 'support',
      historicalScreenshotDetail.json().data?.hasScreenshot === true);
    const publicScreenshot = await request('GET', `/api/v1/media/${screenshotMediaId}`, reporter);
    record('feedback_screenshot_is_not_publicly_readable', publicScreenshot, 404, 'reporter');
    const supportScreenshot = await request('GET', `/api/v1/internal/feedback/${feedbackId}/screenshot`, support);
    record('support_screenshot_access_is_short_lived_and_audited', supportScreenshot, 302, 'support', Boolean(supportScreenshot.headers.location));
    const securityScreenshot = await request('GET', `/api/v1/internal/feedback/${feedbackId}/screenshot`, security);
    record('security_role_cannot_read_support_screenshot', securityScreenshot, 403, 'security');

    const securityReport = await request('POST', '/api/v1/security-reports', owner, {
      category: 'privacy', summary: 'Fictional privacy test case', details: 'Synthetic report details with no secret or personal data.',
    });
    record('security_case_created_with_received_status', securityReport, 201, 'owner', securityReport.json().data?.statusLabel === 'Received');
    const securityId = securityReport.json().data?.caseId as string;
    createdSecurityReportIds.push(securityId);
    const securityDetail = await request('GET', `/api/v1/internal/security-reports/${securityId}`, security);
    record('security_role_reads_security_detail', securityDetail, 200, 'security');
    const securityPatch = await request('PATCH', `/api/v1/internal/security-reports/${securityId}`, security, { status: 'reviewing' });
    record('security_status_change_is_authorized', securityPatch, 200, 'security');
    const supportCannotReadSecurity = await request('GET', `/api/v1/internal/security-reports/${securityId}`, support);
    record('support_role_cannot_read_security_report', supportCannotReadSecurity, 403, 'support');
    const otherSecurityStatus = await request('GET', `/api/v1/me/security-reports/${securityId}`, reporter);
    record('other_user_cannot_read_security_status', otherSecurityStatus, 404, 'reader');
    const readerMetrics = await request('GET', '/api/v1/internal/feedback/metrics', reporter);
    record('public_reader_cannot_read_private_aggregate_metrics', readerMetrics, 403, 'reader');

    const audits = await controlPool!.query<{ count: number }>(
      `SELECT count(*)::int AS count FROM staff_access_audit WHERE
         (staff_id=$1 AND resource_id=$3 AND event_type IN ('feedback.read','feedback.status_changed')) OR
         (staff_id=$2 AND resource_id=$4 AND event_type IN ('security_report.read','security_report.status_changed'))`,
      [support.id, security.id, feedbackId, securityId],
    );
    record('staff_read_and_status_changes_are_audited', securityPatch, 200, 'security', Number(audits.rows[0]?.count ?? 0) >= 4);
  });
});
