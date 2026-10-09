import type { FastifyInstance } from 'fastify';
import type { PoolClient } from 'pg';

type PendingRevocation = {
  id: string;
  source_key: string;
  moderation_action_id: string | null;
  attempt_count: number;
};

export async function processPendingMediaKeyRevocations(app: FastifyInstance, ids?: string[]): Promise<void> {
  let client: PoolClient | undefined;
  const retryAlerts: Array<{ context: Record<string, string | number>; escalated: boolean }> = [];
  const resolvedAlerts: Array<{ revocationId: string; attemptCount: number }> = [];
  try {
    client = await app.pg.connect();
    await client.query('BEGIN');
    const pending = ids?.length
      ? await client.query<PendingRevocation>(
        `SELECT id, source_key, moderation_action_id, attempt_count FROM media_key_revocations
         WHERE id = ANY($1::uuid[]) AND retry_after <= now()
         ORDER BY created_at, id FOR UPDATE SKIP LOCKED`, [ids],
      )
      : await client.query<PendingRevocation>(
        `SELECT id, source_key, moderation_action_id, attempt_count FROM media_key_revocations
         WHERE retry_after <= now()
         ORDER BY created_at, id LIMIT 25 FOR UPDATE SKIP LOCKED`,
      );

    for (const row of pending.rows) {
      try {
        // Storage must confirm the old key is no longer readable before the durable case is completed.
        await app.mediaStorage.deleteObject(row.source_key);
      } catch (error) {
        const attemptCount = row.attempt_count + 1;
        const retryAfterSeconds = Math.min(300, 5 * 2 ** Math.min(attemptCount - 1, 6));
        await client.query(
          `UPDATE media_key_revocations
           SET attempt_count=$2,
               retry_after=now()+($3 * interval '1 second'),
               escalated_at=CASE WHEN $2 >= 3 THEN COALESCE(escalated_at, now()) ELSE escalated_at END
           WHERE id=$1`, [row.id, attemptCount, retryAfterSeconds],
        );
        const logContext = {
          revocationId: row.id,
          attemptCount,
          retryAfterSeconds,
          errorType: error instanceof Error ? error.name : 'UnknownError',
        };
        retryAlerts.push({ context: logContext, escalated: attemptCount >= 3 });
        continue;
      }

      await client.query('DELETE FROM media_key_revocations WHERE id=$1', [row.id]);
      if (row.attempt_count >= 3) resolvedAlerts.push({ revocationId: row.id, attemptCount: row.attempt_count });
      if (!row.moderation_action_id) continue;

      const actionPending = await client.query(
        'SELECT 1 FROM media_key_revocations WHERE moderation_action_id=$1 LIMIT 1', [row.moderation_action_id],
      );
      if (actionPending.rowCount) continue;

      await client.query(
        `UPDATE moderation_actions
         SET metadata=metadata || jsonb_build_object('removalStatus','verified','removalVerifiedAt',now())
         WHERE id=$1`, [row.moderation_action_id],
      );
      await client.query(
        `UPDATE reports r
         SET status='actioned', removal_pending=false, updated_at=now(), closed_at=NULL
         WHERE r.removal_pending=true
           AND EXISTS (
             SELECT 1 FROM moderation_actions a
             WHERE a.id=$1 AND a.target_type=r.target_type AND a.target_id=r.target_id
           )
           AND NOT EXISTS (
             SELECT 1 FROM media_key_revocations pending
             JOIN moderation_actions pending_action ON pending_action.id=pending.moderation_action_id
             WHERE pending_action.target_type=r.target_type AND pending_action.target_id=r.target_id
           )`, [row.moderation_action_id],
      );
    }
    await client.query('COMMIT');
    for (const retry of retryAlerts) {
      if (retry.escalated) {
        app.log.error(retry.context, 'ALERT: cover-key revocation remains unverified after three attempts; escalate until verified.');
      } else {
        app.log.warn(retry.context, 'Cover-key revocation is not verified; durable retry scheduled.');
      }
    }
    for (const resolved of resolvedAlerts) {
      app.log.info(resolved, 'Cover-key revocation verified; escalation may be resolved.');
    }
  } catch (error) {
    await client?.query('ROLLBACK').catch(() => undefined);
    app.log.error({ errorType: error instanceof Error ? error.name : 'UnknownError' }, 'Cover revocation outbox processing failed.');
  } finally {
    client?.release();
  }
}

export async function hasPendingMediaKeyRevocations(app: FastifyInstance, ids: string[]): Promise<boolean> {
  if (ids.length === 0) return false;
  const result = await app.pg.query('SELECT 1 FROM media_key_revocations WHERE id=ANY($1::uuid[]) LIMIT 1', [ids]);
  return Boolean(result.rowCount);
}
