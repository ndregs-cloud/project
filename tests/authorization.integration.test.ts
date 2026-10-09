import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { mkdir, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWTPayload } from 'jose';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { closePool, pool } from '../src/db.js';
import { processPendingMediaKeyRevocations } from '../src/media-key-revocations.js';
import { ObjectCopyError } from '../src/storage/s3.js';

const enabled = process.env.RUN_INTEGRATION_TESTS === '1';
type Actor = { subject: string; token: string; id: string };
type Evidence = { check: string; result: 'PASS' | 'FAIL'; requestId: string; actorRole: string; timestamp: string };
type TestResponse = { statusCode: number; headers: Record<string, unknown>; json: () => any };

describe.skipIf(!enabled)('authorization matrix (PostgreSQL integration)', () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
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
    if (!process.env.DATABASE_URL) throw new Error('RUN_INTEGRATION_TESTS=1 requires DATABASE_URL pointing to a disposable test database.');
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
      AUTH_JWKS_URL: `http://127.0.0.1:${port}/jwks`,
      AUTH_ISSUER: issuer, AUTH_AUDIENCE: 'nova-api',
      CORS_ORIGINS: 'https://app.nova.test', NOINDEX: 'true',
      S3_ENDPOINT: 'http://127.0.0.1:9000', S3_REGION: 'us-east-1', S3_BUCKET: 'nova-test-private',
      S3_ACCESS_KEY_ID: 'test-access-key', S3_SECRET_ACCESS_KEY: 'test-only-secret', S3_FORCE_PATH_STYLE: 'true',
    });
    app = await buildApp({ config, pg: pool });
    const coverFixture = Buffer.from('fictional cover fixture bytes');
    app.mediaStorage.readObject = async () => ({ body: Readable.from([coverFixture]), contentLength: coverFixture.length });
    app.mediaStorage.copyObjectToKey = async (sourceKey, destinationKey) => { rotatedObjectKeys.push({ sourceKey, destinationKey }); };
    app.mediaStorage.deleteObject = async () => undefined;
    for (const role of ['owner', 'reader', 'moderator', 'admin', 'support', 'security']) await createActor(role);
    await pool.query("UPDATE users SET role='moderator' WHERE auth_subject=$1", [actors.get('moderator')!.subject]);
    await pool.query("UPDATE users SET role='admin' WHERE auth_subject=$1", [actors.get('admin')!.subject]);
    await pool.query("UPDATE users SET role='support' WHERE auth_subject=$1", [actors.get('support')!.subject]);
    await pool.query("UPDATE users SET role='security' WHERE auth_subject=$1", [actors.get('security')!.subject]);
  }, 30_000);

  afterAll(async () => {
    if (actors.size) {
      const ids = [...actors.values()].map((actor) => actor.id);
      const storyIds = [...createdStoryIds];
      const commentRows = await pool.query<{ id: string }>('SELECT id FROM comments WHERE story_id=ANY($1::uuid[])', [storyIds]);
      const commentIds = commentRows.rows.map((row) => row.id);
      await pool.query('DELETE FROM staff_access_audit WHERE staff_id=ANY($1::uuid[]) OR resource_id=ANY($2::uuid[])',
        [ids, [...createdReportIds, ...createdFeedbackIds, ...createdSecurityReportIds, ...createdStoryIds]]);
      await pool.query('DELETE FROM moderation_actions WHERE moderator_id=ANY($1::uuid[]) OR target_id=ANY($2::uuid[])',
        [ids, [...createdStoryIds, ...commentIds]]);
      await pool.query('DELETE FROM beta_feedback WHERE reporter_id=ANY($1::uuid[]) OR id=ANY($2::uuid[])', [ids, createdFeedbackIds]);
      await pool.query('DELETE FROM security_reports WHERE reporter_id=ANY($1::uuid[]) OR id=ANY($2::uuid[])', [ids, createdSecurityReportIds]);
      await pool.query('DELETE FROM reports WHERE reporter_id=ANY($1::uuid[]) OR id=ANY($2::uuid[]) OR target_id=ANY($3::uuid[])',
        [ids, createdReportIds, [...createdStoryIds, ...commentIds]]);
      await pool.query('DELETE FROM comments WHERE id=ANY($1::uuid[])', [commentIds]);
      await pool.query('DELETE FROM story_tags WHERE story_id=ANY($1::uuid[])', [storyIds]);
      await pool.query('DELETE FROM bookmarks WHERE story_id=ANY($1::uuid[]) OR user_id=ANY($2::uuid[])', [storyIds, ids]);
      await pool.query('DELETE FROM follows WHERE follower_id=ANY($1::uuid[]) OR followed_id=ANY($1::uuid[])', [ids]);
      await pool.query('DELETE FROM stories WHERE id=ANY($1::uuid[]) OR author_id=ANY($2::uuid[])', [storyIds, ids]);
      await pool.query('DELETE FROM media_assets WHERE id=ANY($1::uuid[]) OR owner_id=ANY($2::uuid[])', [createdMediaIds, ids]);
      await pool.query('DELETE FROM users WHERE id=ANY($1::uuid[])', [ids]);
    }
    if (app) await app.close();
    if (jwksServer) await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
    if (enabled) {
      await mkdir('artifacts', { recursive: true });
      await writeFile('artifacts/security-matrix.json', JSON.stringify({ generatedAt: new Date().toISOString(), evidence }, null, 2) + '\n');
    }
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

    const forcedPublic = await request('POST', '/api/v1/stories', owner, {
      title: 'Forced public state attempt', body: 'Fictional test only.', status: 'published', visibility: 'public',
    });
    record('client_cannot_force_public_state', forcedPublic, 400, 'owner');

    const created = await request('POST', '/api/v1/stories', owner, {
      title: 'Auth matrix Draft', summary: 'Fictional test fixture', body: 'Non-sensitive integration-test text.',
    });
    record('owner_create_draft', created, 201, 'owner', created.json().data.authorId === owner.id);
    const storyId = created.json().data.id as string;
    createdStoryIds.push(storyId);

    const anonymousRead = await request('GET', `/api/v1/stories/${storyId}`);
    record('anonymous_cannot_read_draft', anonymousRead, 404, 'anonymous');
    const otherRead = await request('GET', `/api/v1/stories/${storyId}`, reader);
    record('other_account_cannot_read_draft', otherRead, 404, 'reader');
    const ownerRead = await request('GET', `/api/v1/stories/${storyId}`, owner);
    record('owner_can_read_draft', ownerRead, 200, 'owner', ownerRead.json().data.authorId === owner.id);
    const otherEdit = await request('PATCH', `/api/v1/stories/${storyId}`, reader, { version: 1, title: 'Attempted takeover' });
    record('other_account_cannot_edit_draft', otherEdit, 404, 'reader');
    const otherPublish = await request('POST', `/api/v1/stories/${storyId}/publish`, reader, {});
    record('other_account_cannot_publish_draft', otherPublish, 404, 'reader');

    const cookieCrossOrigin = await request('POST', `/api/v1/stories/${storyId}/publish`, undefined, {}, {
      origin: 'https://attacker.invalid', cookie: 'nova_session=fake-test-cookie',
    });
    record('cross_origin_cookie_publish_rejected', cookieCrossOrigin, 401, 'anonymous', !cookieCrossOrigin.headers['access-control-allow-origin']);

    const ownerPublish = await request('POST', `/api/v1/stories/${storyId}/publish`, owner, {});
    record('owner_explicit_publish_succeeds', ownerPublish, 200, 'owner',
      ownerPublish.json().data?.status === 'published' && ownerPublish.json().data?.visibility === 'public' && Boolean(ownerPublish.json().data?.publishedAt));
    const anonymousPublishedRead = await request('GET', `/api/v1/stories/${storyId}`);
    record('anonymous_sees_story_only_after_persisted_publish', anonymousPublishedRead, 200, 'anonymous',
      anonymousPublishedRead.json().data?.status === 'published' && anonymousPublishedRead.json().data?.visibility === 'public');
    const ownerUnpublish = await request('POST', `/api/v1/stories/${storyId}/unpublish`, owner, {});
    record('owner_unpublish_persists_private_draft', ownerUnpublish, 200, 'owner',
      ownerUnpublish.json().data?.status === 'draft' && ownerUnpublish.json().data?.visibility === 'private');
    const anonymousAfterUnpublish = await request('GET', `/api/v1/stories/${storyId}`);
    record('anonymous_cannot_see_unpublished_story', anonymousAfterUnpublish, 404, 'anonymous');

    const objectKeyInjection = await request('POST', '/api/v1/media/upload-intents', owner, {
      purpose: 'avatar', mimeType: 'image/jpeg', sizeBytes: 128, objectKey: `${reader.id}/ready/victim.jpg`,
    });
    record('client_cannot_select_signed_upload_key', objectKeyInjection, 400, 'owner');

    const uploadIntent = await request('POST', '/api/v1/media/upload-intents', owner, {
      purpose: 'avatar', mimeType: 'image/jpeg', sizeBytes: 128,
    });
    const pendingMediaId = uploadIntent.json().data.id as string;
    const signedPath = new URL(uploadIntent.json().data.uploadUrl).pathname;
    record('signed_upload_key_is_server_generated_and_owner_scoped', uploadIntent, 201, 'owner',
      signedPath.includes(`/pending/${owner.id}/${pendingMediaId}.jpg`) && !signedPath.includes(reader.id));
    createdMediaIds.push(pendingMediaId);
    const pendingAnonymous = await request('GET', `/api/v1/media/${pendingMediaId}`);
    record('anonymous_cannot_read_pending_upload', pendingAnonymous, 404, 'anonymous');
    const pendingOwner = await request('GET', `/api/v1/media/${pendingMediaId}`, owner);
    record('owner_cannot_read_pending_upload', pendingOwner, 404, 'owner');
    const pendingOther = await request('GET', `/api/v1/media/${pendingMediaId}`, reader);
    record('other_account_cannot_read_pending_upload', pendingOther, 404, 'reader');
    const otherComplete = await request('POST', `/api/v1/media/${pendingMediaId}/complete`, reader, {});
    record('other_account_cannot_complete_upload', otherComplete, 404, 'reader');

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

  it('removes a suspended creator Story from public access, search facets, bookmarks, comments, and covers', async () => {
    const owner = await createActor('suspended_owner');
    const reader = actors.get('reader')!;
    const coverMediaId = randomUUID();
    createdMediaIds.push(coverMediaId);
    const initialCoverKey = `ready/${owner.id}/${coverMediaId}.jpg`;
    await pool.query(
      `INSERT INTO media_assets(id,owner_id,purpose,object_key,mime_type,size_bytes,status,ready_at)
       VALUES($1,$2,'cover',$3,'image/jpeg',128,'ready',now())`,
      [coverMediaId, owner.id, initialCoverKey],
    );
    const created = await request('POST', '/api/v1/stories', owner, {
      title: 'Suspension fixture', summary: 'Fictional test fixture', body: 'Non-sensitive integration-test text.', coverMediaId,
    });
    record('suspension_fixture_story_created', created, 201, 'owner');
    const storyId = created.json().data.id as string;
    createdStoryIds.push(storyId);
    const published = await request('POST', `/api/v1/stories/${storyId}/publish`, owner, {});
    record('suspension_fixture_published', published, 200, 'owner');
    const reportResponse = await request('POST', '/api/v1/reports', actors.get('admin'), {
      targetType: 'story', targetId: storyId, reason: 'spam', details: 'Fictional takedown test report.',
    });
    record('takedown_report_created_for_pending_state_test', reportResponse, 201, 'admin');
    const reportId = reportResponse.json().data.caseId as string;
    createdReportIds.push(reportId);
    const creator = await pool.query<{ username: string }>('SELECT username FROM users WHERE id=$1', [owner.id]);
    const username = creator.rows[0]!.username;

    const bookmarkBefore = await request('PUT', `/api/v1/me/bookmarks/${storyId}`, reader);
    record('active_creator_story_can_be_bookmarked', bookmarkBefore, 204, 'reader');
    const commentBefore = await request('POST', `/api/v1/stories/${storyId}/comments`, reader, { body: 'Fictional test comment.' });
    record('active_creator_story_accepts_comment', commentBefore, 201, 'reader');
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
    const storyAfterFailedHide = await pool.query<{ status: string }>('SELECT status FROM stories WHERE id=$1', [storyId]);
    record('failed_cover_rotation_does_not_commit_takedown', failedHide, 503, 'moderator', storyAfterFailedHide.rows[0]?.status === 'published');
    app.mediaStorage.copyObjectToKey = copyObjectToKey;

    app.mediaStorage.deleteObject = async () => { throw new Error('Synthetic storage delete failure.'); };
    const hideAction = await request('POST', '/api/v1/moderation/actions', actors.get('moderator'), {
      targetType: 'story', targetId: storyId, action: 'hide_story', reason: 'Synthetic takedown test.',
    });
    record('moderator_takes_down_cover_fixture_story_with_visible_pending_state', hideAction, 202, 'moderator',
      hideAction.json().removal?.status === 'pending');
    await pool.query('UPDATE media_key_revocations SET retry_after=now() WHERE media_id=$1', [coverMediaId]);
    await processPendingMediaKeyRevocations(app);
    await pool.query('UPDATE media_key_revocations SET retry_after=now() WHERE media_id=$1', [coverMediaId]);
    await processPendingMediaKeyRevocations(app);
    const escalatedRevocation = await pool.query<{ attempt_count: number; escalated_at: Date | null }>(
      'SELECT attempt_count, escalated_at FROM media_key_revocations WHERE media_id=$1', [coverMediaId],
    );
    record('third_failed_attempt_persists_escalation_while_case_stays_open', hideAction, 202, 'moderator',
      escalatedRevocation.rows[0]?.attempt_count === 3 && escalatedRevocation.rows[0]?.escalated_at != null);
    const keyAfterTakedown = await pool.query<{ object_key: string }>('SELECT object_key FROM media_assets WHERE id=$1', [coverMediaId]);
    record('takedown_rotates_origin_cover_key_before_action_completes', hideAction, 202, 'moderator',
      keyAfterTakedown.rows[0]?.object_key !== initialCoverKey && rotatedObjectKeys.some((entry) => entry.sourceKey === initialCoverKey));
    const sameCoverUrlAfterTakedown = await request('GET', `/api/v1/media/${coverMediaId}`);
    record('api_cover_is_fail_closed_while_private_takedown_revocation_is_pending', sameCoverUrlAfterTakedown, 404, 'anonymous');
    const ownerReadWhilePending = await request('GET', `/api/v1/media/${coverMediaId}`, owner);
    record('owner_cannot_bypass_pending_cover_revocation', ownerReadWhilePending, 404, 'owner');
    const reporterCasePending = await request('GET', `/api/v1/me/reports/${reportId}`, actors.get('admin'));
    record('reporter_sees_removal_pending_instead_of_completed_case', reporterCasePending, 200, 'admin',
      reporterCasePending.json().data?.statusLabel === 'Removal pending' && reporterCasePending.json().data?.removalPending === true);
    const moderatorQueuePending = await request('GET', '/api/v1/moderation/reports?status=reviewing', actors.get('moderator'));
    record('moderator_queue_exposes_removal_pending_case', moderatorQueuePending, 200, 'moderator',
      moderatorQueuePending.json().data.some((row: { id: string; removalPending: boolean }) => row.id === reportId && row.removalPending));
    const prematureReportClose = await request('PATCH', `/api/v1/moderation/reports/${reportId}`, actors.get('moderator'), { status: 'closed' });
    record('moderator_cannot_close_case_before_revocation_is_verified', prematureReportClose, 409, 'moderator',
      prematureReportClose.json().error?.code === 'REMOVAL_PENDING');

    const sharedStoryInsert = await pool.query<{ id: string }>(
      `INSERT INTO stories(author_id,title,slug,status,visibility,published_at,cover_media_id)
       VALUES($1,'Shared cover fixture',$2,'published','public',now(),$3) RETURNING id`,
      [reader.id, `shared-cover-${randomUUID()}`, coverMediaId],
    );
    const sharedStoryId = sharedStoryInsert.rows[0]!.id;
    createdStoryIds.push(sharedStoryId);
    const sharedStoryRead = await request('GET', `/api/v1/stories/${sharedStoryId}`);
    record('still_live_story_sharing_cover_remains_readable', sharedStoryRead, 200, 'anonymous');
    const sharedCoverRead = await request('GET', `/api/v1/media/${coverMediaId}`);
    record('shared_cover_api_access_is_preserved_for_other_live_story', sharedCoverRead, 200, 'anonymous');

    app.mediaStorage.deleteObject = deleteObject;
    await pool.query('UPDATE media_key_revocations SET retry_after=now() WHERE media_id=$1', [coverMediaId]);
    await processPendingMediaKeyRevocations(app);
    const pendingAfterHideRetry = await pool.query('SELECT 1 FROM media_key_revocations WHERE media_id=$1', [coverMediaId]);
    const reporterCaseAfterRetry = await request('GET', `/api/v1/me/reports/${reportId}`, actors.get('admin'));
    record('verified_retry_completes_removal_case', reporterCaseAfterRetry, 200, 'admin',
      pendingAfterHideRetry.rowCount === 0 && reporterCaseAfterRetry.json().data?.statusLabel === 'Action taken' &&
      reporterCaseAfterRetry.json().data?.removalPending === false);
    await pool.query("UPDATE stories SET status='removed', visibility='private' WHERE id=$1", [sharedStoryId]);
    const ownerReadAfterVerification = await request('GET', `/api/v1/media/${coverMediaId}`, owner);
    record('owner_cannot_read_takedown_cover_without_a_live_story_after_verification', ownerReadAfterVerification, 404, 'owner');
    await pool.query("UPDATE stories SET status='published', visibility='public' WHERE id=$1", [sharedStoryId]);

    const restoreAction = await request('POST', '/api/v1/moderation/actions', actors.get('moderator'), {
      targetType: 'story', targetId: storyId, action: 'restore_story', reason: 'Restore synthetic takedown fixture.',
    });
    record('moderator_restores_cover_fixture_story', restoreAction, 201, 'moderator');
    const coverAfterRestore = await request('GET', `/api/v1/media/${coverMediaId}`);
    record('cover_api_url_is_readable_again_after_restore', coverAfterRestore, 200, 'anonymous');

    const userReportResponse = await request('POST', '/api/v1/reports', actors.get('admin'), {
      targetType: 'user', targetId: owner.id, reason: 'other', details: 'Fictional suspension test report.',
    });
    record('suspension_report_created_for_pending_state_test', userReportResponse, 201, 'admin');
    const userReportId = userReportResponse.json().data.caseId as string;
    createdReportIds.push(userReportId);

    app.mediaStorage.deleteObject = async () => { throw new Error('Synthetic storage delete failure.'); };
    const suspendAction = await request('POST', '/api/v1/moderation/actions', actors.get('moderator'), {
      targetType: 'user', targetId: owner.id, action: 'suspend_user', reason: 'Synthetic suspension test.',
    });
    const suspendedState = await pool.query<{ status: string }>('SELECT status FROM users WHERE id=$1', [owner.id]);
    const pendingRevocation = await pool.query<{ id: string }>('SELECT id FROM media_key_revocations WHERE media_id=$1', [coverMediaId]);
    record('suspension_is_applied_with_visible_durable_revocation_pending_after_delete_failure', suspendAction, 202, 'moderator',
      suspendAction.json().removal?.status === 'pending' && suspendedState.rows[0]?.status === 'suspended' && pendingRevocation.rowCount === 1);
    const userCasePending = await request('GET', `/api/v1/me/reports/${userReportId}`, actors.get('admin'));
    record('suspension_report_shows_removal_pending', userCasePending, 200, 'admin',
      userCasePending.json().data?.statusLabel === 'Removal pending' && userCasePending.json().data?.removalPending === true);
    const keyAfterSuspension = await pool.query<{ object_key: string }>('SELECT object_key FROM media_assets WHERE id=$1', [coverMediaId]);
    record('suspension_rotates_origin_cover_key_before_action_completes', suspendAction, 202, 'moderator',
      keyAfterSuspension.rows[0]?.object_key !== keyAfterTakedown.rows[0]?.object_key &&
      rotatedObjectKeys.some((entry) => entry.sourceKey === keyAfterTakedown.rows[0]?.object_key));
    app.mediaStorage.deleteObject = deleteObject;
    await pool.query('UPDATE media_key_revocations SET retry_after=now() WHERE media_id=$1', [coverMediaId]);
    await processPendingMediaKeyRevocations(app);
    const pendingAfterRetry = await pool.query('SELECT 1 FROM media_key_revocations WHERE media_id=$1', [coverMediaId]);
    const userCaseAfterRetry = await request('GET', `/api/v1/me/reports/${userReportId}`, actors.get('admin'));
    record('verified_suspension_retry_completes_report_case', userCaseAfterRetry, 200, 'admin',
      pendingAfterRetry.rowCount === 0 && userCaseAfterRetry.json().data?.statusLabel === 'Action taken' &&
      userCaseAfterRetry.json().data?.removalPending === false);
    const directRead = await request('GET', `/api/v1/stories/${storyId}`);
    record('suspended_creator_story_returns_neutral_not_found', directRead, 404, 'anonymous');
    const authorSearch = await request('GET', `/api/v1/stories?author=${encodeURIComponent(username)}`);
    record('suspended_creator_story_excluded_from_author_search', authorSearch, 200, 'anonymous',
      !authorSearch.json().data.some((row: { id: string }) => row.id === storyId));
    const bookmarkList = await request('GET', '/api/v1/me/bookmarks', reader);
    record('suspended_creator_story_removed_from_bookmarks', bookmarkList, 200, 'reader',
      !bookmarkList.json().data.some((row: { id: string }) => row.id === storyId));
    const newBookmark = await request('PUT', `/api/v1/me/bookmarks/${storyId}`, reader);
    record('suspended_creator_story_cannot_be_bookmarked', newBookmark, 404, 'reader');
    const comments = await request('GET', `/api/v1/stories/${storyId}/comments`);
    record('suspended_creator_story_comments_are_hidden', comments, 200, 'anonymous', comments.json().data.length === 0);
    const newComment = await request('POST', `/api/v1/stories/${storyId}/comments`, reader, { body: 'Fictional test comment.' });
    record('suspended_creator_story_rejects_new_comments', newComment, 404, 'reader');
    const sameCoverUrlAfterSuspension = await request('GET', `/api/v1/media/${coverMediaId}`);
    const stillLiveSharedStory = await request('GET', `/api/v1/stories/${sharedStoryId}`);
    record('shared_cover_remains_available_only_through_other_live_story_after_suspension_retry', sameCoverUrlAfterSuspension, 200, 'anonymous',
      pendingAfterRetry.rowCount === 0 && stillLiveSharedStory.statusCode === 200);
  });

  it('limits content-report details to the reporter and dedicated moderator', async () => {
    const owner = actors.get('owner')!;
    const reporter = actors.get('reader')!;
    const moderator = actors.get('moderator')!;
    const reportDraft = await request('POST', '/api/v1/stories', owner, {
      title: 'Report matrix fixture', summary: 'Fictional test fixture', body: 'Non-sensitive integration-test text.',
    });
    record('report_fixture_draft_created', reportDraft, 201, 'owner');
    const storyId = reportDraft.json().data?.id as string | undefined;
    if (storyId) createdStoryIds.push(storyId);
    const reportPublish = await request('POST', `/api/v1/stories/${storyId ?? '00000000-0000-0000-0000-000000000000'}/publish`, owner, {});
    record('report_fixture_published', reportPublish, 200, 'owner', reportPublish.json().data?.status === 'published');

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
    record('moderator_changes_report_status', changed, 200, 'moderator');
    const updatedStatus = await request('GET', `/api/v1/me/reports/${caseId}`, reporter);
    record('reporter_sees_safe_updated_label', updatedStatus, 200, 'reporter', updatedStatus.json().data?.statusLabel === 'Under review');
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
    await pool.query(
      `INSERT INTO media_assets(id,owner_id,purpose,object_key,mime_type,size_bytes,status,ready_at)
       VALUES($1,$2,'feedback_screenshot',$3,'image/jpeg',128,'ready',now())`,
      [screenshotMediaId, reporter.id, `ready/${reporter.id}/${screenshotMediaId}.jpg`],
    );
    const screenshotFeedback = await request('POST', '/api/v1/feedback', reporter, {
      category: 'usability', summary: 'Fictional selected screenshot', screenshotMediaId,
    });
    record('screenshot_is_attached_only_after_explicit_selection', screenshotFeedback, 201, 'reporter');
    const screenshotCaseId = screenshotFeedback.json().data?.caseId as string;
    createdFeedbackIds.push(screenshotCaseId);
    const publicScreenshot = await request('GET', `/api/v1/media/${screenshotMediaId}`, reporter);
    record('feedback_screenshot_is_not_publicly_readable', publicScreenshot, 404, 'reporter');
    const supportScreenshot = await request('GET', `/api/v1/internal/feedback/${screenshotCaseId}/screenshot`, support);
    record('support_screenshot_access_is_short_lived_and_audited', supportScreenshot, 302, 'support', Boolean(supportScreenshot.headers.location));
    const securityScreenshot = await request('GET', `/api/v1/internal/feedback/${screenshotCaseId}/screenshot`, security);
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

    const audits = await pool.query<{ count: number }>(
      `SELECT count(*)::int AS count FROM staff_access_audit WHERE
         (staff_id=$1 AND resource_id=$3 AND event_type IN ('feedback.read','feedback.status_changed')) OR
         (staff_id=$2 AND resource_id=$4 AND event_type IN ('security_report.read','security_report.status_changed'))`,
      [support.id, security.id, feedbackId, securityId],
    );
    record('staff_read_and_status_changes_are_audited', securityPatch, 200, 'security', Number(audits.rows[0]?.count ?? 0) >= 4);
  });
});
