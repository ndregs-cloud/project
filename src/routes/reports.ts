import type { FastifyInstance } from 'fastify';
import { requestDatabase } from '../db.js';
import { z } from 'zod';
import { decodeCursor, encodeCursor } from '../cursor.js';
import { AppError } from '../errors.js';
import { parseInput, parsePageSize, requireUser, uuidSchema } from '../validation.js';

const reportSchema = z.object({
  targetType: z.enum(['user', 'story', 'comment']),
  targetId: uuidSchema,
  reason: z.enum(['spam', 'harassment', 'copyright', 'sexual_or_harmful', 'other']),
  details: z.string().trim().max(2000).optional(),
}).strict();
const querySchema = z.object({ cursor: z.string().max(512).optional(), limit: z.unknown().optional() });
const idParams = z.object({ id: uuidSchema });
const reportStatusLabels: Record<string, string> = {
  received: 'Received', reviewing: 'Under review', actioned: 'Action taken',
  no_violation: 'No violation found', closed: 'Closed',
};

export async function registerReportRoutes(app: FastifyInstance): Promise<void> {
  app.post('/api/v1/reports', { config: { authRequired: true, rateLimitMax: 5, rateLimitWindowMs: 60_000 } }, async (request, reply) => {
    const user = requireUser(request);
    const input = parseInput(reportSchema, request.body);
    if (input.targetType === 'user' && input.targetId === user.id) throw new AppError(400, 'INVALID_REPORT', 'You cannot report yourself.');
    const target = input.targetType === 'user'
      ? await requestDatabase(request).query("SELECT id FROM users WHERE id=$1 AND status='active'", [input.targetId])
      : input.targetType === 'story'
        ? await requestDatabase(request).query("SELECT id FROM stories WHERE id=$1 AND status='published' AND deleted_at IS NULL", [input.targetId])
        : await requestDatabase(request).query(
          `SELECT c.id FROM comments c JOIN stories s ON s.id=c.story_id
           WHERE c.id=$1 AND c.status='visible' AND c.deleted_at IS NULL AND s.status='published' AND s.deleted_at IS NULL`,
          [input.targetId],
        );
    if (!target.rowCount) throw new AppError(404, 'NOT_FOUND', 'Content not found.');
    const result = await requestDatabase(request).query<{ id: string; status: string; removalPending: boolean; createdAt: Date | string }>(
      `INSERT INTO reports (reporter_id, target_type, target_id, reason, details)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, status, removal_pending AS "removalPending", created_at AS "createdAt"`,
      [user.id, input.targetType, input.targetId, input.reason, input.details ?? null],
    );
    const report = result.rows[0];
    if (!report) throw new AppError(503, 'REPORT_UNAVAILABLE', 'The report could not be saved.');
    reply.code(201);
    return { data: {
      caseId: report.id,
      status: report.status,
      statusLabel: reportStatusLabels[report.status] ?? 'Received',
      removal: report.removalPending
        ? { status: 'pending', label: 'Removal pending — cleanup could not be confirmed' }
        : { status: 'not_pending' },
      removalPending: report.removalPending,
      statusUrl: `/api/v1/me/reports/${report.id}`,
      createdAt: report.createdAt,
    } };
  });

  app.get('/api/v1/me/reports/:id', { config: { authRequired: true } }, async (request) => {
    const user = requireUser(request);
    const { id } = parseInput(idParams, request.params);
    const result = await requestDatabase(request).query<{ id: string; status: string; removalPending: boolean; createdAt: Date | string; updatedAt: Date | string }>(
      `SELECT id, status, removal_pending AS "removalPending", created_at AS "createdAt", updated_at AS "updatedAt"
       FROM reports WHERE id=$1 AND reporter_id=$2`, [id, user.id],
    );
    const report = result.rows[0];
    if (!report) throw new AppError(404, 'NOT_FOUND', 'Report not found.');
    return { data: {
      caseId: report.id, status: report.status,
      statusLabel: reportStatusLabels[report.status] ?? 'Received',
      removal: report.removalPending
        ? { status: 'pending', label: 'Removal pending — cleanup could not be confirmed' }
        : { status: 'not_pending' },
      removalPending: report.removalPending,
      statusUrl: `/api/v1/me/reports/${report.id}`, createdAt: report.createdAt, updatedAt: report.updatedAt,
    } };
  });

  app.get('/api/v1/me/reports', { config: { authRequired: true } }, async (request) => {
    const user = requireUser(request);
    const query = parseInput(querySchema, request.query);
    const limit = parsePageSize(query.limit);
    const cursor = decodeCursor(query.cursor);
    const params: unknown[] = [user.id];
    let cursorSql = '';
    if (cursor) {
      params.push(cursor.createdAt, cursor.id);
      cursorSql = `AND (created_at, id) < ($2::timestamptz, $3::uuid)`;
    }
    params.push(limit + 1);
    const result = await requestDatabase(request).query<{ id: string; status: string; targetType: string; removalPending: boolean; createdAt: Date | string; updatedAt: Date | string }>(
      `SELECT id, target_type AS "targetType", status, removal_pending AS "removalPending", created_at AS "createdAt", updated_at AS "updatedAt"
       FROM reports WHERE reporter_id=$1 ${cursorSql} ORDER BY created_at DESC, id DESC LIMIT $${params.length}`, params,
    );
    const hasMore = result.rows.length > limit;
    const rows = result.rows.slice(0, limit);
    const data = rows.map((report) => ({
      caseId: report.id, targetType: report.targetType, status: report.status,
      statusLabel: reportStatusLabels[report.status] ?? 'Received',
      removal: report.removalPending
        ? { status: 'pending', label: 'Removal pending — cleanup could not be confirmed' }
        : { status: 'not_pending' },
      removalPending: report.removalPending,
      statusUrl: `/api/v1/me/reports/${report.id}`, createdAt: report.createdAt, updatedAt: report.updatedAt,
    }));
    const last = rows.at(-1);
    return { data, page: { hasMore, nextCursor: hasMore && last ? encodeCursor({ createdAt: new Date(last.createdAt).toISOString(), id: last.id }) : null } };
  });
}
