import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { registerRequestRollbackCompensation } from '../auth.js';
import { inRequestTransaction, requestDatabase } from '../db.js';
import { AppError } from '../errors.js';
import { versionedObjectKey } from '../storage/s3.js';
import { parseInput, parsePageSize, requireModerator, uuidSchema } from '../validation.js';
import { auditStaffAccessMany } from './internal-audit.js';

const NOT_INTEGRATED_MESSAGE = 'Tindakan ini belum tersedia. Tidak ada perubahan yang dibuat dan kasus tetap terbuka.';
const actionSchema = z.object({
  targetType: z.enum(['user', 'story', 'comment']),
  targetId: uuidSchema,
  action: z.enum(['hide_story', 'restore_story', 'remove_comment', 'suspend_user', 'unsuspend_user']),
  reason: z.string().trim().min(5).max(1000),
  expectedHideActionId: uuidSchema.optional(),
}).strict();
const queueQuery = z.object({ limit: z.unknown().optional(), status: z.enum(['received', 'reviewing']).default('received') });

export async function registerModerationRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/v1/moderation/reports', { config: { authRequired: true } }, async (request) => {
    requireModerator(request);
    const query = parseInput(queueQuery, request.query);
    const limit = parsePageSize(query.limit);
    const result = await requestDatabase(request).query<{ id: string }>(
      `SELECT id, target_type AS "targetType", target_id AS "targetId", reason, details, status,
         removal_pending AS "removalPending", created_at AS "createdAt"
       FROM reports WHERE status=$1 ORDER BY created_at ASC, id ASC LIMIT $2`, [query.status, limit],
    );
    await auditStaffAccessMany(requestDatabase(request), request.user!.id, 'content_report.read', result.rows.map((row) => row.id));
    return { data: result.rows };
  });

  app.patch('/api/v1/moderation/reports/:id', { config: { authRequired: true, rateLimitMax: 60 } }, async (request) => {
    requireModerator(request);
    throw new AppError(501, 'NOT_INTEGRATED', NOT_INTEGRATED_MESSAGE);
  });

  app.post('/api/v1/moderation/actions', { config: { authRequired: true, rateLimitMax: 30 } }, async (request, reply) => {
    requireModerator(request);
    const input = parseInput(actionSchema, request.body);
    if (input.action !== 'hide_story' && input.action !== 'restore_story') {
      throw new AppError(501, 'NOT_INTEGRATED', NOT_INTEGRATED_MESSAGE);
    }
    if (input.action === 'restore_story' && !input.expectedHideActionId) {
      throw new AppError(400, 'INVALID_INPUT', 'The hide action reviewed for restore is required.');
    }
    if (input.action !== 'restore_story' && input.expectedHideActionId) {
      throw new AppError(400, 'INVALID_INPUT', 'A hide-action version is only valid for restore.');
    }
    if (!isActionCompatible(input.targetType, input.action)) throw new AppError(400, 'INVALID_ACTION', 'Tindakan tidak cocok dengan jenis target.');
    const committed = await inRequestTransaction(request, async (client) => {
      let covers: Array<{ id: string; object_key: string }> = [];
      const revocationIds: string[] = [];
      let action: { id: string; targetType: string; targetId: string; action: string; reason: string; createdAt: Date; commentsOpen?: boolean } | undefined;
      let actionId: string | undefined;
      let removalStatus: string | undefined;
      if (input.action === 'hide_story') {
        const current = await client.query<{ status: string; visibility: string; published_at: Date | null; comments_open: boolean; cover_media_id: string | null }>(
          'SELECT status, visibility, published_at, comments_open, cover_media_id FROM stories WHERE id=$1 AND deleted_at IS NULL FOR UPDATE', [input.targetId],
        );
        const row = current.rows[0];
        if (!row) throw new AppError(404, 'NOT_FOUND', 'Cerita tidak ditemukan.');
        if (row.status === 'removed') {
          const existing = await findExistingRemovalAction(client, input);
          if (existing) return {
            action: existing.action,
            actionId: existing.action.id,
            revocationIds,
            removalPending: existing.removalStatus === 'pending',
            removalStatus: existing.removalStatus,
          };
          throw new AppError(409, 'INVALID_STATE', 'Cerita sudah disembunyikan atau dihapus.');
        }
        if (row.cover_media_id) {
          const media = await client.query<{ id: string; object_key: string }>(
            "SELECT id, object_key FROM media_assets WHERE id=$1 AND purpose='cover' AND status='ready' FOR UPDATE", [row.cover_media_id],
          );
          covers = media.rows;
        }
        const moderated = await client.query<{ id: string }>(
          'SELECT public.nova_moderate_hide_story($1,$2) AS id', [input.targetId, input.reason],
        );
        actionId = moderated.rows[0]?.id;
        if (!actionId) throw new AppError(503, 'MODERATION_UNAVAILABLE', 'Prosedur moderasi tidak menghasilkan tindakan.');
        const created = await client.query<{
          id: string; targetType: string; targetId: string; action: string; reason: string; createdAt: Date; removalStatus: string | null;
        }>(
          `SELECT id, target_type AS "targetType", target_id AS "targetId", action, reason,
             created_at AS "createdAt", metadata->>'removalStatus' AS "removalStatus"
           FROM moderation_actions WHERE id=$1`, [actionId],
        );
        const rowAction = created.rows[0];
        if (!rowAction) throw new AppError(503, 'MODERATION_UNAVAILABLE', 'Tindakan moderasi tidak dapat dimuat.');
        const { removalStatus: actionRemovalStatus, ...actionData } = rowAction;
        action = actionData;
        removalStatus = actionRemovalStatus ?? undefined;
        removalStatus ??= covers.length ? 'pending' : 'no_media_required';
        if (covers.length) await rotateCoverKeys(app, request, client, covers, revocationIds, actionId);
      } else {
        let restored: { rows: Array<{ id: string }> };
        try {
          restored = await client.query<{ id: string }>(
            'SELECT public.nova_moderate_restore_story($1,$2,$3) AS id',
            [input.targetId, input.expectedHideActionId!, input.reason],
          );
        } catch (error) {
          if (typeof error === 'object' && error !== null && 'code' in error && error.code === '40001') {
            throw new AppError(409, 'STALE_STORY_STATE', 'Story status changed. Reload the latest status before trying again.');
          }
          throw error;
        }
        actionId = restored.rows[0]?.id;
        if (!actionId) throw new AppError(409, 'INVALID_STATE', 'Cerita tidak dapat dipulihkan.');
        const created = await client.query<{ id: string; targetType: string; targetId: string; action: string; reason: string; createdAt: Date }>(
          `SELECT id, target_type AS "targetType", target_id AS "targetId", action, reason, created_at AS "createdAt"
           FROM moderation_actions WHERE id=$1`, [actionId],
        );
        const restoredAction = created.rows[0];
        if (!restoredAction) throw new AppError(503, 'MODERATION_UNAVAILABLE', 'Tindakan moderasi tidak dapat dimuat.');
        const restoredStory = await client.query<{ commentsOpen: boolean }>(
          "SELECT comments_open AS \"commentsOpen\" FROM stories WHERE id=$1 AND status<>'removed' AND deleted_at IS NULL",
          [input.targetId],
        );
        const commentsOpen = restoredStory.rows[0]?.commentsOpen;
        if (typeof commentsOpen !== 'boolean') throw new AppError(409, 'STALE_STORY_STATE', 'Story status changed. Reload the latest status before trying again.');
        action = { ...restoredAction, commentsOpen };
      }

      if (!action || !actionId) throw new AppError(503, 'MODERATION_UNAVAILABLE', 'Tindakan moderasi tidak dapat dimuat.');
      return {
        action,
        actionId,
        revocationIds,
        removalPending: revocationIds.length > 0 || removalStatus === 'pending',
        removalStatus: removalStatus ?? (input.action === 'hide_story' ? 'no_media_required' : undefined),
      };
    });
    if (committed.removalPending) reply.code(202);
    else if (committed.removalStatus === 'verified') reply.code(200);
    else reply.code(201);
    return { data: committed.action, removal: {
      status: committed.removalStatus ?? (committed.removalPending ? 'pending' : 'not_required'),
      ...(committed.removalPending ? { label: 'Removal pending — cleanup could not be confirmed' } : {}),
    } };
  });
}

async function findExistingRemovalAction(
  client: import('pg').PoolClient,
  input: z.infer<typeof actionSchema>,
): Promise<{
  action: { id: string; targetType: string; targetId: string; action: string; reason: string; createdAt: Date };
  removalStatus: string;
} | undefined> {
  if (input.action !== 'hide_story') return undefined;
  const result = await client.query(
    `SELECT id, target_type AS "targetType", target_id AS "targetId", action, reason,
       created_at AS "createdAt", metadata->>'removalStatus' AS "removalStatus"
     FROM moderation_actions
     WHERE target_type=$1::report_target_type AND target_id=$2 AND action=$3
       AND metadata->>'removalStatus' IN ('pending','verified','no_media_required','not_required')
     ORDER BY created_at DESC, id DESC LIMIT 1`,
    [input.targetType, input.targetId, input.action],
  );
  const row = result.rows[0] as {
    id: string; targetType: string; targetId: string; action: string; reason: string; createdAt: Date; removalStatus: string;
  } | undefined;
  if (!row) return undefined;
  const currentStory = await client.query<{ status: string; deletedAt: Date | null }>(
    'SELECT status::text AS status, deleted_at AS "deletedAt" FROM stories WHERE id=$1', [row.targetId],
  );
  if (!currentStory.rows[0] || currentStory.rows[0].deletedAt) {
    throw new AppError(404, 'NOT_FOUND', 'Cerita tidak ditemukan.');
  }
  if (currentStory.rows[0].status !== 'removed') return undefined;
  return {
    action: { id: row.id, targetType: row.targetType, targetId: row.targetId, action: row.action, reason: row.reason, createdAt: row.createdAt },
    removalStatus: row.removalStatus,
  };
}

async function rotateCoverKeys(
  app: FastifyInstance,
  request: import('fastify').FastifyRequest,
  client: import('pg').PoolClient,
  covers: Array<{ id: string; object_key: string }>,
  revocationIds: string[],
  actionId: string,
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
      let revocationId: string | undefined;
      try {
        registerRequestRollbackCompensation(request, async () => {
          try {
            await app.mediaStorage.deleteObject(destinationKey);
          } catch (error) {
            request.log.warn({
              event: 'media_revocation_copy_compensation_failed',
              actionId,
              mediaId: cover.id,
              destinationKeyPresent: true,
              errorType: error instanceof Error ? error.name : 'UnknownError',
              reconciliationRequired: true,
              durableReconciliationRecorded: false,
              alertSent: false,
            }, 'Rollback copy cleanup failed; destination may be orphaned and requires manual reconciliation. No durable queue or alert was created.');
          }
        }, {
          confirmCommitted: async () => {
            if (!revocationId) return false;
            const visible = await app.mediaRevocationPg.query<{
              id: string; media_id: string; moderation_action_id: string | null;
            }>(
              'SELECT id,media_id,moderation_action_id FROM public.media_key_revocations WHERE id=$1',
              [revocationId],
            );
            const row = visible.rows[0];
            return row?.id === revocationId && row.media_id === cover.id && row.moderation_action_id === actionId;
          },
          onOutcomeUnknown: () => request.log.warn({
            event: 'media_revocation_commit_outcome_unconfirmed',
            actionId,
            mediaId: cover.id,
            destinationPreserved: true,
            reconciliationRequired: true,
            durableReconciliationRecorded: false,
            alertSent: false,
          }, 'Commit outcome could not be established; the copied destination was preserved. Refresh authoritative state before retrying.'),
        });
        await app.mediaStorage.copyObjectToKey(cover.object_key, destinationKey);
        const queued = await client.query<{ id: string }>(
          'SELECT public.nova_enqueue_media_key_revocation($1,$2,$3,$4) AS id',
          [cover.id, actionId, cover.object_key, destinationKey],
        );
        revocationId = queued.rows[0]?.id;
        if (!revocationId) throw new AppError(503, 'MEDIA_REVOCATION_UNAVAILABLE', "We couldn't confirm the status. Refresh before trying again.");
        revocationIds.push(revocationId);
      } catch (error) {
        failed = true;
        failure = error instanceof AppError ? error : new AppError(
          503,
          'MEDIA_REVOCATION_UNAVAILABLE',
          "We couldn't confirm the status. Refresh before trying again.",
          undefined,
          true,
        );
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
