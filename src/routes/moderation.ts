import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { inTransaction } from '../db.js';
import { AppError } from '../errors.js';
import { hasPendingMediaKeyRevocations, processPendingMediaKeyRevocations } from '../media-key-revocations.js';
import { ObjectCopyError, versionedObjectKey } from '../storage/s3.js';
import { parseInput, parsePageSize, requireModerator, uuidSchema } from '../validation.js';
import { auditStaffAccessMany } from './internal-audit.js';

const reportParams = z.object({ id: uuidSchema });
const reportStatusSchema = z.object({ status: z.enum(['reviewing', 'actioned', 'no_violation', 'closed']) }).strict();
const actionSchema = z.object({
  targetType: z.enum(['user', 'story', 'comment']),
  targetId: uuidSchema,
  action: z.enum(['hide_story', 'restore_story', 'remove_comment', 'suspend_user', 'unsuspend_user']),
  reason: z.string().trim().min(5).max(1000),
}).strict();
const queueQuery = z.object({ limit: z.unknown().optional(), status: z.enum(['received', 'reviewing']).default('received') });

export async function registerModerationRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/v1/moderation/reports', { config: { authRequired: true } }, async (request) => {
    requireModerator(request);
    const query = parseInput(queueQuery, request.query);
    const limit = parsePageSize(query.limit);
    const result = await app.pg.query<{ id: string }>(
      `SELECT id, target_type AS "targetType", target_id AS "targetId", reason, details, status,
         removal_pending AS "removalPending", created_at AS "createdAt"
       FROM reports WHERE status=$1 ORDER BY created_at ASC, id ASC LIMIT $2`, [query.status, limit],
    );
    await auditStaffAccessMany(app, request.user!.id, 'content_report.read', result.rows.map((row) => row.id));
    return { data: result.rows };
  });

  app.patch('/api/v1/moderation/reports/:id', { config: { authRequired: true, rateLimitMax: 60 } }, async (request) => {
    const moderator = requireModerator(request);
    const { id } = parseInput(reportParams, request.params);
    const { status } = parseInput(reportStatusSchema, request.body);
    const result = await inTransaction(async (client) => {
      const current = await client.query<{ status: string; target_type: string; target_id: string; removal_pending: boolean }>(
        'SELECT status, target_type, target_id, removal_pending FROM reports WHERE id=$1 FOR UPDATE', [id],
      );
      const report = current.rows[0];
      if (!report) throw new AppError(404, 'NOT_FOUND', 'Laporan tidak ditemukan.');
      if (report.removal_pending && status !== 'reviewing') {
        throw new AppError(409, 'REMOVAL_PENDING', 'The report remains open until cover-key revocation is verified.');
      }
      if (status === 'actioned' || status === 'closed') {
        const pending = await client.query(
          `SELECT 1 FROM media_key_revocations revocations
           JOIN moderation_actions actions ON actions.id=revocations.moderation_action_id
           WHERE actions.target_type=$1::report_target_type AND actions.target_id=$2 LIMIT 1`,
          [report.target_type, report.target_id],
        );
        if (pending.rowCount) throw new AppError(409, 'REMOVAL_PENDING', 'The report remains open until cover-key revocation is verified.');
      }
      if (report.status === status) return { id, status, removalPending: report.removal_pending };
      if (!isReportTransitionAllowed(report.status, status)) throw new AppError(409, 'INVALID_STATE', 'Status laporan tidak dapat berpindah ke status tersebut.');
      const updated = await client.query(
        `UPDATE reports SET status=$2::report_status, updated_at=now(),
           first_response_at=COALESCE(first_response_at, CASE WHEN $2::report_status <> 'received'::report_status THEN now() END),
           closed_at=CASE WHEN $2::report_status='closed'::report_status THEN now() ELSE NULL END,
           reopen_count=reopen_count + CASE WHEN status='closed' AND $2::report_status='reviewing'::report_status THEN 1 ELSE 0 END
         WHERE id=$1 RETURNING id, status, updated_at AS "updatedAt", reopen_count AS "reopenCount"`, [id, status],
      );
      await client.query(
        `INSERT INTO moderation_actions (moderator_id, target_type, target_id, action, reason, metadata)
         VALUES ($1, $2::report_target_type, $3, $4, $5, $6::jsonb)`,
        [moderator.id, report.target_type, report.target_id, `report_status:${status}`, `Perubahan status laporan ${id}`,
          JSON.stringify({ reportId: id, previousStatus: report.status, status })],
      );
      await client.query(
        `INSERT INTO staff_access_audit (staff_id,event_type,resource_id,metadata)
         VALUES ($1,'content_report.status_changed',$2,$3::jsonb)`,
        [moderator.id,id,JSON.stringify({from:report.status,to:status})],
      );
      return { ...updated.rows[0], removalPending: false };
    });
    return { data: result };
  });

  app.post('/api/v1/moderation/actions', { config: { authRequired: true, rateLimitMax: 30 } }, async (request, reply) => {
    const moderator = requireModerator(request);
    const input = parseInput(actionSchema, request.body);
    if (!isActionCompatible(input.targetType, input.action)) throw new AppError(400, 'INVALID_ACTION', 'Tindakan tidak cocok dengan jenis target.');
    const committed = await inTransaction(async (client) => {
      let metadata: Record<string, unknown> = {};
      let covers: Array<{ id: string; object_key: string }> = [];
      const revocationIds: string[] = [];
      if (input.action === 'hide_story') {
        const current = await client.query<{ status: string; visibility: string; published_at: Date | null; comments_open: boolean; cover_media_id: string | null }>(
          'SELECT status, visibility, published_at, comments_open, cover_media_id FROM stories WHERE id=$1 AND deleted_at IS NULL FOR UPDATE', [input.targetId],
        );
        const row = current.rows[0];
        if (!row) throw new AppError(404, 'NOT_FOUND', 'Cerita tidak ditemukan.');
        if (row.status === 'removed') throw new AppError(409, 'INVALID_STATE', 'Cerita sudah disembunyikan atau dihapus.');
        metadata = { priorStatus: row.status, priorVisibility: row.visibility, priorPublishedAt: row.published_at, priorCommentsOpen: row.comments_open };
        if (row.cover_media_id) {
          const media = await client.query<{ id: string; object_key: string }>(
            "SELECT id, object_key FROM media_assets WHERE id=$1 AND purpose='cover' AND status='ready' FOR UPDATE", [row.cover_media_id],
          );
          covers = media.rows;
        }
        await client.query("UPDATE stories SET status='removed', visibility='private', comments_open=false, updated_at=now(), version=version+1 WHERE id=$1", [input.targetId]);
      } else if (input.action === 'restore_story') {
        const lastHide = await client.query<{ metadata: Record<string, unknown> }>(
          "SELECT metadata FROM moderation_actions WHERE target_type='story' AND target_id=$1 AND action='hide_story' ORDER BY created_at DESC LIMIT 1", [input.targetId],
        );
        const prior = lastHide.rows[0]?.metadata;
        if (!prior) throw new AppError(409, 'INVALID_STATE', 'Tidak ada tindakan penyembunyian yang dapat dipulihkan.');
        const restored = await client.query(
          `UPDATE stories SET status=$2::story_status, visibility=$3::story_visibility, comments_open=$4,
             updated_at=now(), version=version+1 WHERE id=$1 AND status='removed' AND deleted_at IS NULL RETURNING id`,
          [input.targetId, prior.priorStatus, prior.priorVisibility, prior.priorCommentsOpen],
        );
        if (!restored.rowCount) throw new AppError(409, 'INVALID_STATE', 'Cerita tidak dapat dipulihkan.');
        metadata = { restoredStatus: prior.priorStatus };
      } else if (input.action === 'remove_comment') {
        const updated = await client.query("UPDATE comments SET status='removed', deleted_at=now(), updated_at=now() WHERE id=$1 AND deleted_at IS NULL RETURNING id", [input.targetId]);
        if (!updated.rowCount) throw new AppError(404, 'NOT_FOUND', 'Komentar tidak ditemukan.');
      } else if (input.action === 'suspend_user') {
        const target = await client.query<{ id: string }>('SELECT id FROM users WHERE id=$1 AND status <> \'deleted\' FOR UPDATE', [input.targetId]);
        if (!target.rowCount) throw new AppError(404, 'NOT_FOUND', 'Pengguna tidak ditemukan.');
        await client.query('SELECT id FROM stories WHERE author_id=$1 ORDER BY id FOR UPDATE', [input.targetId]);
        const media = await client.query<{ id: string; object_key: string }>(
          `SELECT m.id, m.object_key FROM media_assets m
           WHERE m.owner_id=$1 AND m.purpose='cover' AND m.status='ready'
             AND EXISTS (SELECT 1 FROM stories s WHERE s.author_id=$1 AND s.cover_media_id=m.id
               AND s.status='published' AND s.visibility='public' AND s.deleted_at IS NULL)
           ORDER BY m.id FOR UPDATE OF m`, [input.targetId],
        );
        covers = media.rows;
        await client.query("UPDATE users SET status='suspended', updated_at=now() WHERE id=$1", [input.targetId]);
      } else {
        const updated = await client.query("UPDATE users SET status='active', updated_at=now() WHERE id=$1 AND status <> 'deleted' RETURNING id", [input.targetId]);
        if (!updated.rowCount) throw new AppError(404, 'NOT_FOUND', 'Pengguna tidak ditemukan.');
      }

      await rotateCoverKeys(app, client, covers, revocationIds);
      if (input.action === 'hide_story' || input.action === 'suspend_user') {
        metadata = { ...metadata, removalStatus: revocationIds.length ? 'pending' : 'not_required' };
      }
      const action = await client.query(
        `INSERT INTO moderation_actions (moderator_id, target_type, target_id, action, reason, metadata)
         VALUES ($1, $2::report_target_type, $3, $4, $5, $6::jsonb)
         RETURNING id, target_type AS "targetType", target_id AS "targetId", action, reason, created_at AS "createdAt"`,
        [moderator.id, input.targetType, input.targetId, input.action, input.reason, JSON.stringify(metadata)],
      );
      const actionId = action.rows[0]!.id as string;
      if (revocationIds.length) {
        await client.query(
          'UPDATE media_key_revocations SET moderation_action_id=$2 WHERE id=ANY($1::uuid[])', [revocationIds, actionId],
        );
        await client.query(
          `UPDATE reports
           SET status='reviewing', removal_pending=true, updated_at=now(),
               first_response_at=COALESCE(first_response_at,now()), closed_at=NULL,
               reopen_count=reopen_count + CASE WHEN status='closed' THEN 1 ELSE 0 END
           WHERE target_type=$1::report_target_type AND target_id=$2`, [input.targetType, input.targetId],
        );
      }
      return { action: action.rows[0], actionId, revocationIds };
    });
    await processPendingMediaKeyRevocations(app, committed.revocationIds);
    let removalPending = committed.revocationIds.length > 0;
    if (removalPending) {
      try {
        removalPending = await hasPendingMediaKeyRevocations(app, committed.revocationIds);
      } catch (error) {
        app.log.error({ actionId: committed.actionId, errorType: error instanceof Error ? error.name : 'UnknownError' },
          'Moderation committed but removal status could not be checked; treating it as pending.');
      }
    }
    if (removalPending) reply.code(202).header('Retry-After', '5');
    else reply.code(201);
    return {
      data: committed.action,
      removal: { status: removalPending ? 'pending' : committed.revocationIds.length ? 'verified' : 'not_required' },
    };
  });
}

async function rotateCoverKeys(
  app: FastifyInstance,
  client: import('pg').PoolClient,
  covers: Array<{ id: string; object_key: string }>,
  revocationIds: string[],
): Promise<void> {
  let cursor = 0;
  let failed = false;
  let failure: unknown;
  const worker = async (): Promise<void> => {
    while (!failed) {
      const index = cursor++;
      const cover = covers[index];
      if (!cover) return;
      const destinationKey = versionedObjectKey(cover.object_key);
      try {
        const queued = await client.query<{ id: string }>(
          'INSERT INTO media_key_revocations (media_id, source_key) VALUES ($1,$2) RETURNING id',
          [cover.id, cover.object_key],
        );
        await app.mediaStorage.copyObjectToKey(cover.object_key, destinationKey);
        const updated = await client.query(
          'UPDATE media_assets SET object_key=$2, updated_at=now() WHERE id=$1 AND object_key=$3 RETURNING id',
          [cover.id, destinationKey, cover.object_key],
        );
        if (!updated.rowCount) throw new AppError(503, 'MEDIA_REVOCATION_UNAVAILABLE', 'Cover access could not be safely revoked.');
        revocationIds.push(queued.rows[0]!.id);
      } catch (error) {
        failed = true;
        failure = error instanceof AppError ? error : new AppError(503, 'MEDIA_REVOCATION_UNAVAILABLE', 'Cover access could not be prepared safely; the moderation action was not committed.');
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(8, covers.length) }, () => worker()));
  if (failed) throw failure;
}

function isActionCompatible(type: string, action: string): boolean {
  if (action.endsWith('_story')) return type === 'story';
  if (action.endsWith('_comment')) return type === 'comment';
  return type === 'user';
}

function isReportTransitionAllowed(from: string, to: string): boolean {
  if (from === 'received') return to === 'reviewing';
  if (from === 'reviewing') return to === 'actioned' || to === 'no_violation';
  if (from === 'actioned' || from === 'no_violation') return to === 'closed';
  if (from === 'closed') return to === 'reviewing';
  return false;
}
