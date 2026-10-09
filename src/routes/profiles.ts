import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { AppError } from '../errors.js';
import { parseInput, requireUser, usernameParamsSchema, uuidSchema } from '../validation.js';

const patchProfileSchema = z.object({
  username: z.string().trim().min(3).max(32).regex(/^[a-zA-Z0-9_]+$/).optional(),
  displayName: z.string().trim().min(1).max(80).nullable().optional(),
  bio: z.string().trim().max(500).nullable().optional(),
  avatarMediaId: uuidSchema.nullable().optional(),
}).strict().refine((value) => Object.keys(value).length > 0, 'Setidaknya satu field harus diubah.');

export async function registerProfileRoutes(app: FastifyInstance): Promise<void> {
  app.get('/api/v1/me', { config: { authRequired: true } }, async (request) => {
    const user = requireUser(request);
    const result = await app.pg.query(
      `SELECT u.id, u.username, u.display_name AS "displayName", u.bio, u.avatar_media_id AS "avatarMediaId",
              u.role, u.created_at AS "createdAt", u.updated_at AS "updatedAt"
       FROM users u WHERE u.id = $1 AND u.status = 'active'`, [user.id],
    );
    return { data: result.rows[0] };
  });

  app.patch('/api/v1/me', { config: { authRequired: true, rateLimitMax: 30 } }, async (request) => {
    const user = requireUser(request);
    const input = parseInput(patchProfileSchema, request.body);
    if (input.avatarMediaId) {
      const media = await app.pg.query(
        `SELECT id FROM media_assets WHERE id = $1 AND owner_id = $2 AND status = 'ready' AND purpose = 'avatar'`,
        [input.avatarMediaId, user.id],
      );
      if (!media.rowCount) throw new AppError(400, 'MEDIA_NOT_READY', 'Avatar harus berupa media siap milik Anda.');
    }
    const result = await app.pg.query(
      `UPDATE users SET
         username = COALESCE($2, username),
         username_normalized = COALESCE(lower($2), username_normalized),
         display_name = CASE WHEN $3::boolean THEN $4::varchar ELSE display_name END,
         bio = CASE WHEN $5::boolean THEN $6::varchar ELSE bio END,
         avatar_media_id = CASE WHEN $7::boolean THEN $8::uuid ELSE avatar_media_id END,
         updated_at = now()
       WHERE id = $1 AND status = 'active'
       RETURNING id, username, display_name AS "displayName", bio, avatar_media_id AS "avatarMediaId", role,
                 created_at AS "createdAt", updated_at AS "updatedAt"`,
      [user.id, input.username ?? null, input.displayName !== undefined, input.displayName ?? null,
        input.bio !== undefined, input.bio ?? null, input.avatarMediaId !== undefined, input.avatarMediaId ?? null],
    );
    if (!result.rowCount) throw new AppError(404, 'NOT_FOUND', 'Profil tidak ditemukan.');
    return { data: result.rows[0] };
  });

  app.get('/api/v1/users/:username', { config: { authOptional: true } }, async (request) => {
    const { username } = parseInput(usernameParamsSchema, request.params);
    const result = await app.pg.query(
      `SELECT u.id, u.username, u.display_name AS "displayName", u.bio, u.avatar_media_id AS "avatarMediaId",
              u.created_at AS "createdAt",
              (SELECT count(*)::int FROM follows f WHERE f.followed_id = u.id) AS "followerCount",
              (SELECT count(*)::int FROM follows f WHERE f.follower_id = u.id) AS "followingCount"
       FROM users u WHERE u.username_normalized = lower($1) AND u.status = 'active'`, [username],
    );
    if (!result.rowCount) throw new AppError(404, 'NOT_FOUND', 'Profil tidak ditemukan.');
    return { data: result.rows[0] };
  });

  app.get('/api/v1/tags', async () => {
    const result = await app.pg.query('SELECT id, name, normalized_name AS "normalizedName" FROM tags ORDER BY normalized_name');
    return { data: result.rows };
  });
}
