import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { decodeCursor, encodeCursor } from '../cursor.js';
import { AppError } from '../errors.js';
import { inTransaction } from '../db.js';
import { parseInput, parsePageSize, requireUser, uuidSchema } from '../validation.js';

const storyParams = z.object({ id: uuidSchema });
const commentParams = z.object({ id: uuidSchema });
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
    const result = await app.pg.query(
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

  app.post('/api/v1/stories/:id/comments', { config: { authRequired: true, rateLimitMax: 20 } }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = parseInput(storyParams, request.params);
    const input = parseInput(commentSchema, request.body);
    const result = await inTransaction(async (client) => {
      const story = await client.query(
        `SELECT s.id FROM stories s JOIN users creator ON creator.id=s.author_id
         WHERE s.id=$1 AND s.status='published' AND s.visibility='public' AND s.deleted_at IS NULL
           AND s.comments_open=true AND creator.status='active' FOR UPDATE OF s`, [id],
      );
      if (!story.rowCount) throw new AppError(404, 'NOT_FOUND', 'Cerita tidak ditemukan atau komentar ditutup.');
      if (input.parentId) {
        const parent = await client.query('SELECT id FROM comments WHERE id=$1 AND story_id=$2 AND parent_id IS NULL AND status=\'visible\' AND deleted_at IS NULL', [input.parentId, id]);
        if (!parent.rowCount) throw new AppError(400, 'INVALID_PARENT', 'Balasan harus merujuk komentar tingkat atas pada cerita yang sama.');
      }
      return client.query(
        `INSERT INTO comments (story_id, author_id, parent_id, body) VALUES ($1, $2, $3, $4)
         RETURNING id, story_id AS "storyId", author_id AS "authorId", parent_id AS "parentId", body,
                   created_at AS "createdAt", updated_at AS "updatedAt"`, [id, user.id, input.parentId ?? null, input.body],
      );
    });
    reply.code(201);
    return { data: result.rows[0] };
  });

  app.delete('/api/v1/comments/:id', { config: { authRequired: true } }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = parseInput(commentParams, request.params);
    const result = await app.pg.query(
      `UPDATE comments SET status='removed', deleted_at=now(), updated_at=now()
       WHERE id=$1 AND deleted_at IS NULL AND (author_id=$2 OR $3::boolean)
       RETURNING id`, [id, user.id, user.role === 'moderator'],
    );
    if (!result.rowCount) throw new AppError(404, 'NOT_FOUND', 'Komentar tidak ditemukan.');
    reply.code(204);
    return;
  });
}
