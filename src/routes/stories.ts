import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { inRequestTransaction, requestDatabase } from '../db.js';
import { AppError } from '../errors.js';
import { decodeCursor, encodeCursor } from '../cursor.js';
import { parseInput, parsePageSize, requireUser, uuidSchema } from '../validation.js';

const createStorySchema = z.object({
  title: z.string().trim().max(160).optional().default(''),
  summary: z.string().trim().max(500).optional().default(''),
  body: z.string().max(100000).optional().default(''),
  tagIds: z.array(uuidSchema).max(8).optional().default([]),
  coverMediaId: uuidSchema.nullable().optional().default(null),
}).strict();
const patchStorySchema = z.object({
  version: z.number().int().min(1),
  title: z.string().trim().max(160).optional(),
  summary: z.string().trim().max(500).optional(),
  body: z.string().max(100000).optional(),
  tagIds: z.array(uuidSchema).max(8).optional(),
  coverMediaId: uuidSchema.nullable().optional(),
}).strict().refine((value) => Object.keys(value).some((key) => key !== 'version'), 'Setidaknya satu field harus diubah.');
const idSchema = z.object({ id: uuidSchema });
const feedQuerySchema = z.object({
  cursor: z.string().max(512).optional(),
  limit: z.unknown().optional(),
  tag: z.string().trim().min(2).max(40).optional(),
  author: z.string().trim().min(3).max(32).optional(),
});
const myStoriesQuerySchema = z.object({ status: z.enum(['draft', 'published']).default('draft'), cursor: z.string().max(512).optional(), limit: z.unknown().optional() });

const publicColumns = `s.id, s.author_id AS "authorId", s.title, s.slug, s.summary, s.body,
  s.version, s.published_at AS "publishedAt", s.created_at AS "createdAt", s.updated_at AS "updatedAt",
  s.cover_media_id AS "coverMediaId", u.username AS "authorUsername", u.display_name AS "authorDisplayName",
  COALESCE((SELECT json_agg(json_build_object('id', t.id, 'name', t.name, 'normalizedName', t.normalized_name) ORDER BY t.normalized_name)
    FROM story_tags st JOIN tags t ON t.id = st.tag_id WHERE st.story_id = s.id), '[]'::json) AS tags`;

export async function registerStoryRoutes(app: FastifyInstance): Promise<void> {
  app.post('/api/v1/stories', { config: { authRequired: true, rateLimitMax: 20 } }, async (request, reply) => {
    const user = requireUser(request);
    const input = parseInput(createStorySchema, request.body);
    if (input.coverMediaId) throw new AppError(501, 'NOT_INTEGRATED', 'Story cover assignment is unavailable for the MVP. No changes were made.');
    const id = randomUUID();
    const slugBase = slugify(input.title) || 'draft';
    const slug = `${slugBase.slice(0, 150)}-${id.slice(0, 8)}`;
    const story = await inRequestTransaction(request, async (client) => {
      await validateTags(client, input.tagIds);
      await validateCover(client, input.coverMediaId, user.id);
      const inserted = await client.query(
        `INSERT INTO stories (id, author_id, title, slug, summary, body, cover_media_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, author_id AS "authorId", title, slug, summary, body, status, visibility, version,
                   published_at AS "publishedAt", cover_media_id AS "coverMediaId", created_at AS "createdAt", updated_at AS "updatedAt"`,
        [id, user.id, input.title, slug, input.summary, input.body, input.coverMediaId],
      );
      await replaceTags(client, id, input.tagIds);
      return inserted.rows[0];
    });
    reply.code(201);
    return { data: story };
  });

  app.get('/api/v1/stories/:id', { config: { authOptional: true } }, async (request, reply) => {
    const { id } = parseInput(idSchema, request.params);
    const result = await requestDatabase(request).query(
      `SELECT ${publicColumns}, s.status, s.visibility, s.comments_open AS "commentsOpen"
       FROM stories s JOIN users u ON u.id = s.author_id
       WHERE s.id = $1 AND s.deleted_at IS NULL AND u.status = 'active'
         AND (s.status = 'published' OR (s.status = 'draft' AND $2::uuid IS NOT NULL AND s.author_id = $2))`,
      [id, request.user?.id ?? null],
    );
    if (!result.rowCount) throw new AppError(404, 'NOT_FOUND', 'Cerita tidak ditemukan.');
    const story = result.rows[0] as Record<string, unknown>;
    if (story.status === 'draft' && story.authorId !== request.user?.id) throw new AppError(404, 'NOT_FOUND', 'Cerita tidak ditemukan.');
    reply.header('ETag', `"${story.version}"`);
    return { data: story };
  });

  app.patch('/api/v1/stories/:id', { config: { authRequired: true, rateLimitMax: 40 } }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = parseInput(idSchema, request.params);
    const input = parseInput(patchStorySchema, request.body);
    if (input.coverMediaId) throw new AppError(501, 'NOT_INTEGRATED', 'Story cover assignment is unavailable for the MVP. No changes were made.');
    const story = await inRequestTransaction(request, async (client) => {
      const current = await client.query<{ author_id: string; version: number; status: string }>(
        'SELECT author_id, version, status FROM stories WHERE id = $1 AND deleted_at IS NULL FOR UPDATE', [id],
      );
      const row = current.rows[0];
      if (!row || row.author_id !== user.id) throw new AppError(404, 'NOT_FOUND', 'Cerita tidak ditemukan.');
      if (row.status === 'removed') throw new AppError(409, 'INVALID_STATE', 'Cerita yang dihapus tidak dapat diubah.');
      if (row.version !== input.version) throw new AppError(409, 'VERSION_CONFLICT', 'Cerita telah berubah. Muat ulang sebelum menyimpan.', { version: String(row.version) });
      await validateTags(client, input.tagIds ?? []);
      if (input.coverMediaId !== undefined) await validateCover(client, input.coverMediaId, user.id);
      const update = await client.query(
        `UPDATE stories SET title = COALESCE($3, title), summary = COALESCE($4, summary), body = COALESCE($5, body),
          cover_media_id = CASE WHEN $6::boolean THEN $7::uuid ELSE cover_media_id END,
          version = version + 1, updated_at = now()
         WHERE id = $1 AND author_id = $2 AND version = $8
         RETURNING id, author_id AS "authorId", title, slug, summary, body, status, visibility, version,
                   published_at AS "publishedAt", cover_media_id AS "coverMediaId", created_at AS "createdAt", updated_at AS "updatedAt"`,
        [id, user.id, input.title ?? null, input.summary ?? null, input.body ?? null,
          input.coverMediaId !== undefined, input.coverMediaId ?? null, input.version],
      );
      if (input.tagIds !== undefined) await replaceTags(client, id, input.tagIds);
      return update.rows[0];
    });
    reply.header('ETag', `"${(story as { version: number }).version}"`);
    return { data: story };
  });

  app.post('/api/v1/stories/:id/publish', { config: { authRequired: true, rateLimitMax: 15 } }, async () => {
    throw new AppError(501, 'NOT_INTEGRATED', 'Publish is unavailable for the MVP. No changes were made.');
  });

  app.post('/api/v1/stories/:id/unpublish', { config: { authRequired: true, rateLimitMax: 15 } }, async () => {
    throw new AppError(501, 'NOT_INTEGRATED', 'Unpublish is unavailable for the MVP. No changes were made.');
  });

  app.delete('/api/v1/stories/:id', { config: { authRequired: true } }, async () => {
    throw new AppError(501, 'NOT_INTEGRATED', 'Delete is unavailable for the MVP. No changes were made.');
  });

  app.get('/api/v1/stories', { config: { authOptional: true } }, async (request) => {
    const query = parseInput(feedQuerySchema, request.query);
    const limit = parsePageSize(query.limit);
    const cursor = decodeCursor(query.cursor);
    const params: unknown[] = [];
    const conditions = ["s.status = 'published'", 's.deleted_at IS NULL', "s.visibility = 'public'", "u.status = 'active'"];
    if (query.tag) {
      params.push(query.tag.toLowerCase());
      conditions.push(`EXISTS (SELECT 1 FROM story_tags st JOIN tags t ON t.id=st.tag_id WHERE st.story_id=s.id AND t.normalized_name=$${params.length})`);
    }
    if (query.author) {
      params.push(query.author.toLowerCase());
      conditions.push(`u.username_normalized=$${params.length}`);
    }
    if (cursor) {
      params.push(cursor.createdAt, cursor.id);
      conditions.push(`(s.published_at, s.id) < ($${params.length - 1}::timestamptz, $${params.length}::uuid)`);
    }
    params.push(limit + 1);
    const result = await requestDatabase(request).query(
      `SELECT ${publicColumns} FROM stories s JOIN users u ON u.id=s.author_id
       WHERE ${conditions.join(' AND ')} ORDER BY s.published_at DESC, s.id DESC LIMIT $${params.length}`,
      params,
    );
    const hasMore = result.rows.length > limit;
    const data = result.rows.slice(0, limit);
    const last = data.at(-1) as { publishedAt?: string; id?: string } | undefined;
    return { data, page: { nextCursor: hasMore && last?.publishedAt && last.id ? encodeCursor({ createdAt: last.publishedAt, id: last.id }) : null, hasMore } };
  });

  app.get('/api/v1/me/stories', { config: { authRequired: true } }, async (request) => {
    const user = requireUser(request);
    const query = parseInput(myStoriesQuerySchema, request.query);
    const limit = parsePageSize(query.limit);
    const cursor = decodeCursor(query.cursor);
    const params: unknown[] = [user.id, query.status];
    let cursorSql = '';
    if (cursor) {
      params.push(cursor.createdAt, cursor.id);
      cursorSql = `AND (s.created_at, s.id) < ($${params.length - 1}::timestamptz, $${params.length}::uuid)`;
    }
    params.push(limit + 1);
    const result = await requestDatabase(request).query(
      `SELECT s.id, s.title, s.slug, s.summary, s.status, s.version, s.published_at AS "publishedAt",
              s.created_at AS "createdAt", s.updated_at AS "updatedAt", s.cover_media_id AS "coverMediaId"
       FROM stories s WHERE s.author_id=$1 AND s.status=$2 AND s.deleted_at IS NULL ${cursorSql}
       ORDER BY s.created_at DESC, s.id DESC LIMIT $${params.length}`, params,
    );
    const hasMore = result.rows.length > limit;
    const data = result.rows.slice(0, limit);
    const last = data.at(-1) as { createdAt?: string; id?: string } | undefined;
    return { data, page: { nextCursor: hasMore && last?.createdAt && last.id ? encodeCursor({ createdAt: last.createdAt, id: last.id }) : null, hasMore } };
  });
}

async function validateTags(client: { query: (text: string, values?: unknown[]) => Promise<{ rowCount: number | null }> }, ids: string[]): Promise<void> {
  if (!ids.length) return;
  const result = await client.query('SELECT id FROM tags WHERE id = ANY($1::uuid[])', [ids]);
  if (result.rowCount !== ids.length) throw new AppError(400, 'INVALID_TAG', 'Satu atau lebih tag tidak valid.');
}

async function replaceTags(client: { query: (text: string, values?: unknown[]) => Promise<unknown> }, storyId: string, ids: string[]): Promise<void> {
  await client.query('DELETE FROM story_tags WHERE story_id=$1', [storyId]);
  if (!ids.length) return;
  await client.query('INSERT INTO story_tags (story_id, tag_id) SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING', [storyId, ids]);
}

async function validateCover(client: { query: (text: string, values?: unknown[]) => Promise<{ rowCount: number | null }> }, mediaId: string | null, ownerId: string): Promise<void> {
  if (!mediaId) return;
  const result = await client.query("SELECT 1 FROM media_assets WHERE id=$1 AND owner_id=$2 AND status='ready' AND purpose='cover'", [mediaId, ownerId]);
  if (!result.rowCount) throw new AppError(400, 'MEDIA_NOT_READY', 'Cover harus berupa media siap milik Anda.');
}

function slugify(value: string): string {
  return value.toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}
