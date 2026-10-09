import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { inTransaction } from '../db.js';
import { AppError } from '../errors.js';
import { decodeCursor, encodeCursor } from '../cursor.js';
import { auditStaffAccess, auditStaffAccessMany } from './internal-audit.js';
import { parseInput, parsePageSize, requireSupport, requireUser, uuidSchema } from '../validation.js';

const idParams = z.object({ id: uuidSchema });
const statusLabels: Record<string, string> = { received: 'Received', triaged: 'Under review', in_progress: 'In progress', closed: 'Closed' };
const recurrenceKeySchema = z.string().trim().toLowerCase().regex(/^[a-z0-9][a-z0-9._:-]{1,119}$/).nullable().optional();
const feedbackSchema = z.object({
  category: z.enum(['bug', 'usability', 'performance_reliability', 'content_safety', 'feature_request']),
  summary: z.string().trim().min(3).max(200),
  affectedFlow: z.string().trim().max(160).optional(),
  expectedBehavior: z.string().trim().max(2000).optional(),
  actualBehavior: z.string().trim().max(2000).optional(),
  reproductionSteps: z.string().trim().max(4000).optional(),
  impactFrequency: z.string().trim().max(500).optional(),
  workaround: z.string().trim().max(500).optional(),
  deviceInfo: z.string().trim().max(200).optional(),
  browserInfo: z.string().trim().max(200).optional(),
  occurredAt: z.string().datetime({ offset: true }).optional(),
  screenshotMediaId: uuidSchema.optional(),
}).strict().refine((value) => value.category !== 'bug' || (Boolean(value.expectedBehavior) && Boolean(value.actualBehavior)), {
  path: ['expectedBehavior'], message: 'Bug feedback needs expected and actual behavior.',
});
const listQuery = z.object({ status: z.enum(['received', 'triaged', 'in_progress', 'closed']).optional(), cursor: z.string().max(512).optional(), limit: z.unknown().optional() });
const updateSchema = z.object({
  status: z.enum(['triaged', 'in_progress', 'closed']),
  resolution: z.string().trim().max(1000).nullable().optional(),
  recurrenceKey: recurrenceKeySchema,
}).strict();
const metricsQuery = z.object({ days: z.coerce.number().int().min(1).max(90).default(30) });

export async function registerFeedbackRoutes(app: FastifyInstance): Promise<void> {
  app.post('/api/v1/feedback', { config: { authRequired: true, rateLimitMax: 5, rateLimitWindowMs: 86_400_000 } }, async (request, reply) => {
    const user = requireUser(request);
    const input = parseInput(feedbackSchema, request.body);
    if (input.screenshotMediaId) {
      const media = await app.pg.query(
        `SELECT id FROM media_assets m WHERE m.id=$1 AND m.owner_id=$2 AND m.purpose='feedback_screenshot' AND m.status='ready'
         AND NOT EXISTS (SELECT 1 FROM beta_feedback f WHERE f.screenshot_media_id=m.id)`,
        [input.screenshotMediaId, user.id],
      );
      if (!media.rowCount) throw new AppError(400, 'SCREENSHOT_NOT_READY', 'Select a verified screenshot you uploaded yourself.');
    }
    const result = await app.pg.query<{ id: string; createdAt: Date | string }>(
      `INSERT INTO beta_feedback (
         reporter_id, category, summary, affected_flow, expected_behavior, actual_behavior, reproduction_steps,
         impact_frequency, workaround, device_info, browser_info, occurred_at, screenshot_media_id, expires_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now() + ($14::int * interval '1 day'))
       RETURNING id, created_at AS "createdAt"`,
      [user.id, input.category, input.summary, input.affectedFlow ?? null, input.expectedBehavior ?? null,
        input.actualBehavior ?? null, input.reproductionSteps ?? null, input.impactFrequency ?? null,
        input.workaround ?? null, input.deviceInfo ?? null, input.browserInfo ?? null, input.occurredAt ?? null,
        input.screenshotMediaId ?? null, app.config.FEEDBACK_RETENTION_DAYS],
    );
    const feedback = result.rows[0];
    if (!feedback) throw new AppError(503, 'FEEDBACK_UNAVAILABLE', 'Feedback could not be saved.');
    reply.code(201);
    return { data: { caseId: feedback.id, status: 'received', statusLabel: statusLabels.received,
      statusUrl: `/api/v1/me/feedback/${feedback.id}`, createdAt: feedback.createdAt } };
  });

  app.get('/api/v1/me/feedback/:id', { config: { authRequired: true } }, async (request) => {
    const user = requireUser(request);
    const { id } = parseInput(idParams, request.params);
    const result = await app.pg.query<{ id: string; status: string; createdAt: Date | string; updatedAt: Date | string }>(
      `SELECT id, status, created_at AS "createdAt", updated_at AS "updatedAt"
       FROM beta_feedback WHERE id=$1 AND reporter_id=$2 AND expires_at>now()`, [id, user.id],
    );
    const row = result.rows[0];
    if (!row) throw new AppError(404, 'NOT_FOUND', 'Feedback case not found.');
    return { data: { caseId: row.id, status: row.status, statusLabel: statusLabels[row.status] ?? 'Received',
      statusUrl: `/api/v1/me/feedback/${row.id}`, createdAt: row.createdAt, updatedAt: row.updatedAt } };
  });

  app.get('/api/v1/internal/feedback', { config: { authRequired: true } }, async (request) => {
    const staff = requireSupport(request);
    const query = parseInput(listQuery, request.query);
    const limit = parsePageSize(query.limit);
    const cursor = decodeCursor(query.cursor);
    const params: unknown[] = [];
    const conditions = ['expires_at>now()'];
    if (query.status) { params.push(query.status); conditions.push(`status=$${params.length}`); }
    if (cursor) {
      params.push(cursor.createdAt, cursor.id);
      conditions.push(`(created_at,id)<($${params.length - 1}::timestamptz,$${params.length}::uuid)`);
    }
    params.push(limit + 1);
    const rows = await app.pg.query<{ id: string; category: string; status: string; createdAt: Date | string; hasScreenshot: boolean }>(
      `SELECT id, category, status, created_at AS "createdAt", (screenshot_media_id IS NOT NULL) AS "hasScreenshot"
       FROM beta_feedback WHERE ${conditions.join(' AND ')} ORDER BY created_at DESC,id DESC LIMIT $${params.length}`, params,
    );
    const hasMore = rows.rows.length > limit;
    const data = rows.rows.slice(0, limit);
    await auditStaffAccessMany(app, staff.id, 'feedback.read', data.map((row) => row.id));
    const last = data.at(-1);
    return { data: data.map((row) => ({ ...row, statusLabel: statusLabels[row.status] ?? 'Received',
      statusUrl: `/api/v1/internal/feedback/${row.id}` })),
      page: { hasMore, nextCursor: hasMore && last ? encodeCursor({ createdAt: new Date(last.createdAt).toISOString(), id: last.id }) : null } };
  });

  app.get('/api/v1/internal/feedback/metrics', { config: { authRequired: true } }, async (request) => {
    const staff = requireSupport(request);
    const { days } = parseInput(metricsQuery, request.query);
    await auditStaffAccess(app, staff.id, 'feedback.metrics_read', null, { days });
    const categories = await app.pg.query(
      `SELECT category, count(*)::int AS volume,
         round(avg(extract(epoch FROM (first_response_at-created_at)))::numeric,1) AS "avgFirstResponseSeconds",
         sum(reopen_count)::int AS "reopenedCases"
       FROM beta_feedback WHERE created_at>=now()-($1::int*interval '1 day')
       GROUP BY category ORDER BY volume DESC`, [days],
    );
    const recurring = await app.pg.query(
      `SELECT recurrence_key AS "recurrenceKey", count(*)::int AS volume
       FROM beta_feedback WHERE recurrence_key IS NOT NULL AND created_at>=now()-($1::int*interval '1 day')
       GROUP BY recurrence_key ORDER BY volume DESC LIMIT 10`, [days],
    );
    return { data: { windowDays: days, byCategory: categories.rows, recurringCases: recurring.rows } };
  });

  app.get('/api/v1/internal/feedback/:id', { config: { authRequired: true } }, async (request) => {
    const staff = requireSupport(request);
    const { id } = parseInput(idParams, request.params);
    const result = await app.pg.query(
      `SELECT id, category, summary, affected_flow AS "affectedFlow", expected_behavior AS "expectedBehavior",
         actual_behavior AS "actualBehavior", reproduction_steps AS "reproductionSteps", impact_frequency AS "impactFrequency",
         workaround, device_info AS "deviceInfo", browser_info AS "browserInfo", occurred_at AS "occurredAt",
         (screenshot_media_id IS NOT NULL) AS "hasScreenshot", status, recurrence_key AS "recurrenceKey", created_at AS "createdAt"
       FROM beta_feedback WHERE id=$1 AND expires_at>now()`, [id],
    );
    const row = result.rows[0];
    if (!row) throw new AppError(404, 'NOT_FOUND', 'Feedback case not found.');
    await auditStaffAccess(app, staff.id, 'feedback.read', id);
    return { data: row };
  });

  app.get('/api/v1/internal/feedback/:id/screenshot', { config: { authRequired: true, rateLimitMax: 10 } }, async (request, reply) => {
    const staff = requireSupport(request);
    const { id } = parseInput(idParams, request.params);
    const result = await app.pg.query<{ mediaId: string; objectKey: string }>(
      `SELECT m.id AS "mediaId", m.object_key AS "objectKey" FROM beta_feedback f
       JOIN media_assets m ON m.id=f.screenshot_media_id
       WHERE f.id=$1 AND f.expires_at>now() AND m.status='ready' AND m.purpose='feedback_screenshot'`, [id],
    );
    const row = result.rows[0];
    if (!row) throw new AppError(404, 'NOT_FOUND', 'Screenshot not found.');
    await auditStaffAccess(app, staff.id, 'feedback.screenshot_read', id, { mediaId: row.mediaId });
    const url = await app.mediaStorage.createFeedbackScreenshotReadUrl(row.objectKey, 60);
    return reply.redirect(url, 302);
  });

  app.patch('/api/v1/internal/feedback/:id', { config: { authRequired: true, rateLimitMax: 30 } }, async (request) => {
    const staff = requireSupport(request);
    const { id } = parseInput(idParams, request.params);
    const input = parseInput(updateSchema, request.body);
    return { data: await inTransaction(async (client) => {
      const current = await client.query<{ status: string }>('SELECT status FROM beta_feedback WHERE id=$1 AND expires_at>now() FOR UPDATE', [id]);
      const prior = current.rows[0]?.status;
      if (!prior) throw new AppError(404, 'NOT_FOUND', 'Feedback case not found.');
      if (!allowedTransition(prior, input.status)) throw new AppError(409, 'INVALID_STATE', 'Feedback status cannot move to that state.');
      const updated = await client.query(
        `UPDATE beta_feedback SET status=$2::feedback_status, resolution=CASE WHEN $3::boolean THEN $4::varchar ELSE resolution END,
           recurrence_key=CASE WHEN $5::boolean THEN $6::varchar ELSE recurrence_key END, reviewed_by=$7, updated_at=now(),
           first_response_at=COALESCE(first_response_at, CASE WHEN $2::feedback_status<>'received'::feedback_status THEN now() END),
           reopen_count=reopen_count+CASE WHEN status='closed' AND $2::feedback_status='triaged'::feedback_status THEN 1 ELSE 0 END
         WHERE id=$1 RETURNING id,status,updated_at AS "updatedAt",reopen_count AS "reopenCount"`,
        [id, input.status, input.resolution !== undefined, input.resolution ?? null,
          input.recurrenceKey !== undefined, input.recurrenceKey ?? null, staff.id],
      );
      await client.query(
        `INSERT INTO staff_access_audit (staff_id,event_type,resource_id,metadata)
         VALUES ($1,'feedback.status_changed',$2,$3::jsonb)`,
        [staff.id, id, JSON.stringify({ from: prior, to: input.status })],
      );
      return updated.rows[0];
    }) };
  });
}

function allowedTransition(from: string, to: string): boolean {
  if (from === to) return true;
  if (from === 'received') return to === 'triaged' || to === 'closed';
  if (from === 'triaged') return to === 'in_progress' || to === 'closed';
  if (from === 'in_progress') return to === 'closed';
  if (from === 'closed') return to === 'triaged';
  return false;
}
