import type { FastifyInstance } from 'fastify';
import type { PoolClient } from 'pg';

type PendingRevocation = {
  id: string;
  source_key: string;
  moderation_action_id: string | null;
  attempt_count: number;
};

const retryDelaySeconds = [30, 120, 600, 1_800, 7_200] as const;

export async function processPendingMediaKeyRevocations(app: FastifyInstance, ids?: string[]): Promise<void> {
  let client: PoolClient | undefined;
  const retryAlerts: Array<{ context: Record<string, string | number>; escalated: boolean; purgeSucceeded: boolean }> = [];
  try {
    client = await app.mediaRevocationPg.connect();
    await client.query('BEGIN');
    const eligible = `retry_after <= statement_timestamp()
      AND attempt_count < 5 AND escalated_at IS NULL`;
    const pending = ids?.length
      ? await client.query<PendingRevocation>(
        `SELECT id, source_key, moderation_action_id, attempt_count FROM media_key_revocations
         WHERE id = ANY($1::uuid[]) AND ${eligible}
         ORDER BY created_at, id FOR UPDATE SKIP LOCKED`, [ids],
      )
      : await client.query<PendingRevocation>(
        `SELECT id, source_key, moderation_action_id, attempt_count FROM media_key_revocations
         WHERE ${eligible}
         ORDER BY created_at, id LIMIT 25 FOR UPDATE SKIP LOCKED`,
      );

    for (const row of pending.rows) {
      let purgeSucceeded = false;
      let errorType: string | undefined;
      try {
        // This confirms the old key is no longer readable, but is not authoritative
        // evidence that all object versions/cache variants were purged.
        await app.mediaStorage.deleteObject(row.source_key);
        purgeSucceeded = true;
      } catch (error) {
        errorType = error instanceof Error ? error.name : 'UnknownError';
      }

      const attemptCount = row.attempt_count + 1;
      const delaySeconds = retryDelaySeconds[attemptCount - 1]!;
      const updated = await client.query(
        `UPDATE media_key_revocations
         SET attempt_count=$2,
             retry_after=statement_timestamp()+($3 * interval '1 second'),
             escalated_at=CASE WHEN $2=5 THEN statement_timestamp() ELSE escalated_at END
         WHERE id=$1`, [row.id, attemptCount, delaySeconds],
      );
      if (updated.rowCount !== 1) continue;

      retryAlerts.push({
        context: {
          revocationId: row.id,
          moderationActionId: row.moderation_action_id ?? 'unlinked',
          attemptCount,
          retryAfterSeconds: delaySeconds,
          ...(errorType ? { errorType } : {}),
        },
        escalated: attemptCount >= 5,
        purgeSucceeded,
      });
    }
    await client.query('COMMIT');

    for (const retry of retryAlerts) {
      if (retry.escalated) {
        app.log.error(retry.context, 'ALERT: media removal remains pending at escalation threshold; authoritative finalizer is still required.');
      } else if (retry.purgeSucceeded) {
        app.log.warn(retry.context, 'Storage key is not readable, but the outbox remains pending until the authoritative finalizer confirms full purge.');
      } else {
        app.log.warn(retry.context, 'Media removal is not verified; the same outbox operation was rescheduled.');
      }
    }
  } catch (error) {
    await client?.query('ROLLBACK').catch(() => undefined);
    app.log.error({ errorType: error instanceof Error ? error.name : 'UnknownError' }, 'Cover revocation outbox processing failed.');
  } finally {
    client?.release();
  }
}
