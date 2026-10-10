import type { FastifyInstance } from 'fastify';
import { requestDatabase } from '../db.js';
import { decodeCursor, encodeCursor } from '../cursor.js';
import { AppError } from '../errors.js';
import { parseInput, parsePageSize, requireUser, uuidSchema } from '../validation.js';
import { z } from 'zod';

const idParams = z.object({ userId: uuidSchema });
const storyParams = z.object({ storyId: uuidSchema });
const pageQuery = z.object({ cursor: z.string().max(512).optional(), limit: z.unknown().optional() });

export async function registerSocialRoutes(app: FastifyInstance): Promise<void> {
  app.put('/api/v1/me/following/:userId', { config: { authRequired: true, rateLimitMax: 60 } }, async (request, reply) => {
    const user = requireUser(request);
    const { userId } = parseInput(idParams, request.params);
    if (userId === user.id) throw new AppError(400, 'INVALID_FOLLOW', 'Anda tidak dapat mengikuti diri sendiri.');
    const target = await requestDatabase(request).query("SELECT id FROM users WHERE id=$1 AND status='active'", [userId]);
    if (!target.rowCount) throw new AppError(404, 'NOT_FOUND', 'Pengguna tidak ditemukan.');
    await requestDatabase(request).query('INSERT INTO follows (follower_id, followed_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [user.id, userId]);
    reply.code(204);
    return;
  });

  app.delete('/api/v1/me/following/:userId', { config: { authRequired: true } }, async (request, reply) => {
    const user = requireUser(request);
    const { userId } = parseInput(idParams, request.params);
    await requestDatabase(request).query('DELETE FROM follows WHERE follower_id=$1 AND followed_id=$2', [user.id, userId]);
    reply.code(204);
    return;
  });

  app.get('/api/v1/me/following', { config: { authRequired: true } }, async (request) => {
    const user = requireUser(request);
    const query = parseInput(pageQuery, request.query);
    const limit = parsePageSize(query.limit);
    const cursor = decodeCursor(query.cursor);
    const params: unknown[] = [user.id];
    const cursorSql = cursor ? (params.push(cursor.createdAt, cursor.id), `AND (f.created_at, f.followed_id) < ($2::timestamptz, $3::uuid)`) : '';
    params.push(limit + 1);
    const result = await requestDatabase(request).query(
      `SELECT u.id, u.username, u.display_name AS "displayName", u.bio, f.created_at AS "followedAt"
       FROM follows f JOIN users u ON u.id=f.followed_id
       WHERE f.follower_id=$1 AND u.status='active' ${cursorSql}
       ORDER BY f.created_at DESC, f.followed_id DESC LIMIT $${params.length}`, params,
    );
    const hasMore = result.rows.length > limit;
    const data = result.rows.slice(0, limit);
    const last = data.at(-1) as { followedAt?: Date | string; id?: string } | undefined;
    return { data, page: { hasMore, nextCursor: hasMore && last?.followedAt && last.id ? encodeCursor({ createdAt: new Date(last.followedAt).toISOString(), id: last.id }) : null } };
  });

  app.put('/api/v1/me/bookmarks/:storyId', { config: { authRequired: true, rateLimitMax: 60 } }, async (request, reply) => {
    const user = requireUser(request);
    const { storyId } = parseInput(storyParams, request.params);
    const story = await requestDatabase(request).query(
      `SELECT s.id FROM stories s JOIN users creator ON creator.id=s.author_id
       WHERE s.id=$1 AND s.status='published' AND s.visibility='public'
         AND s.deleted_at IS NULL AND creator.status='active'`, [storyId],
    );
    if (!story.rowCount) throw new AppError(404, 'NOT_FOUND', 'Cerita tidak ditemukan.');
    await requestDatabase(request).query('INSERT INTO bookmarks (user_id, story_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [user.id, storyId]);
    reply.code(204);
    return;
  });

  app.delete('/api/v1/me/bookmarks/:storyId', { config: { authRequired: true } }, async (request, reply) => {
    const user = requireUser(request);
    const { storyId } = parseInput(storyParams, request.params);
    await requestDatabase(request).query('DELETE FROM bookmarks WHERE user_id=$1 AND story_id=$2', [user.id, storyId]);
    reply.code(204);
    return;
  });

  app.get('/api/v1/me/bookmarks', { config: { authRequired: true } }, async (request) => {
    const user = requireUser(request);
    const query = parseInput(pageQuery, request.query);
    const limit = parsePageSize(query.limit);
    const cursor = decodeCursor(query.cursor);
    const params: unknown[] = [user.id];
    const cursorSql = cursor ? (params.push(cursor.createdAt, cursor.id), `AND (b.created_at, b.story_id) < ($2::timestamptz, $3::uuid)`) : '';
    params.push(limit + 1);
    const result = await requestDatabase(request).query(
      `SELECT s.id, s.title, s.slug, s.summary, s.published_at AS "publishedAt", b.created_at AS "bookmarkedAt",
              u.id AS "authorId", u.username AS "authorUsername", u.display_name AS "authorDisplayName"
       FROM bookmarks b JOIN stories s ON s.id=b.story_id JOIN users u ON u.id=s.author_id
       WHERE b.user_id=$1 AND s.status='published' AND s.visibility='public'
         AND s.deleted_at IS NULL AND u.status='active' ${cursorSql}
       ORDER BY b.created_at DESC, b.story_id DESC LIMIT $${params.length}`, params,
    );
    const hasMore = result.rows.length > limit;
    const data = result.rows.slice(0, limit);
    const last = data.at(-1) as { bookmarkedAt?: Date | string; id?: string } | undefined;
    return { data, page: { hasMore, nextCursor: hasMore && last?.bookmarkedAt && last.id ? encodeCursor({ createdAt: new Date(last.bookmarkedAt).toISOString(), id: last.id }) : null } };
  });
}
