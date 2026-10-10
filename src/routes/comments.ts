import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { decodeCursor, encodeCursor } from '../cursor.js';
import { AppError } from '../errors.js';
import { inRequestTransaction, requestDatabase } from '../db.js';
import { parseInput, parsePageSize, requireUser, uuidSchema } from '../validation.js';

const storyParams = z.object({ id: uuidSchema });
const querySchema = z.object({ cursor: z.string().max(512).optional(), limit: z.unknown().optional() });
const commentSchema = z.object({ body: z.string().trim().min(1).max(2000), parentId: uuidSchema.nullable().optional() }).strict();

export async function registerCommentRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/v1/stories/:id/comments', { config: { authOptional: true } }, async (request) => {
    const { id } = parseInput(storyParams, request.params);
    const query = parseInput(querySchema, request.query);
    const limit = parsePageSize(query.limit);
    const cursor = decodeCursor(query.cursor);
    const params: unknown[] = [id];
    let cursorSql = '';
    if (cursor) {
      params.push(cursor.createdAt, cursor.id);
      cursorSql = `AND (c.created_at, c.id) > ($2::timestamptz, $3::uuid)`;
    }
    params.push(limit + 1);
    const result = await requestDatabase(request).query(
      `SELECT c.id, c.story_id AS "storyId", c.parent_id AS "parentId", c.body,
              c.created_at AS "createdAt", c.updated_at AS "updatedAt", u.id AS "authorId",
              u.username AS "authorUsername", u.display_name AS "authorDisplayName"
       FROM comments c JOIN users u ON u.id=c.author_id JOIN stories s ON s.id=c.story_id
       JOIN users creator ON creator.id=s.author_id
       WHERE c.story_id=$1 AND s.status='published' AND s.visibility='public' AND s.deleted_at IS NULL AND s.comments_open=true
         AND creator.status='active'
         AND c.status='visible' AND c.deleted_at IS NULL AND u.status='active' ${cursorSql}
       ORDER BY c.created_at ASC, c.id ASC LIMIT $${params.length}`, params,
    );
    const hasMore = result.rows.length > limit;
    const data = result.rows.slice(0, limit);
    const last = data.at(-1) as { createdAt?: Date | string; id?: string } | undefined;
    return { data, page: { hasMore, nextCursor: hasMore && last?.createdAt && last.id ? encodeCursor({ createdAt: new Date(last.createdAt).toISOString(), id: last.id }) : null } };
  });

  app.post('/api/v1/stories/:id/comments', { config: { authRequired: true, rateLimitMax: 20 } }, async () => {
    throw new AppError(501, 'NOT_INTEGRATED', 'Comment creation is unavailable for the MVP. No changes were made.');
  });

  app.delete('/api/v1/comments/:id', { config: { authRequired: true } }, async () => {
    throw new AppError(501, 'NOT_INTEGRATED', 'Comment deletion is unavailable for the MVP. No changes were made.');
  });
}
