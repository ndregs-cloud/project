import { randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { AppError } from '../errors.js';
import { parseInput, requireUser, uuidSchema } from '../validation.js';

type Purpose = 'avatar' | 'cover' | 'feedback_screenshot';
const uploadSchema = z.object({
  purpose: z.enum(['avatar', 'cover', 'feedback_screenshot']),
  mimeType: z.enum(['image/jpeg', 'image/png', 'image/webp']),
  sizeBytes: z.number().int().min(1),
}).strict();
const idParams = z.object({ id: uuidSchema });
const extensionByMime: Record<string, string> = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };
const screenshotLimit = 2 * 1024 * 1024;

export async function registerMediaRoutes(app: FastifyInstance): Promise<void> {
  app.post('/api/v1/media/upload-intents', { config: { authRequired: true, rateLimitMax: 10 } }, async (request, reply) => {
    const user = requireUser(request);
    const input = parseInput(uploadSchema, request.body);
    const maxBytes = input.purpose === 'feedback_screenshot' ? screenshotLimit : app.config.UPLOAD_MAX_BYTES;
    if (input.sizeBytes > maxBytes) throw new AppError(413, 'FILE_TOO_LARGE', 'The image exceeds the permitted upload size.');
    const id = randomUUID();
    const objectKey = `pending/${user.id}/${id}.${extensionByMime[input.mimeType]}`;
    const uploadUrl = await app.mediaStorage.createUploadUrl(objectKey, input.mimeType, input.sizeBytes);
    const result = await app.pg.query(
      `INSERT INTO media_assets (id, owner_id, purpose, object_key, mime_type, size_bytes)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, purpose, mime_type AS "mimeType", size_bytes AS "sizeBytes", status, created_at AS "createdAt"`,
      [id, user.id, input.purpose satisfies Purpose, objectKey, input.mimeType, input.sizeBytes],
    );
    reply.code(201);
    return { data: { ...result.rows[0], uploadUrl, expiresInSeconds: app.config.UPLOAD_URL_TTL_SECONDS,
      requiredHeaders: { 'Content-Type': input.mimeType }, maxBytes } };
  });

  app.post('/api/v1/media/:id/complete', { config: { authRequired: true, rateLimitMax: 20 } }, async (request) => {
    const user = requireUser(request);
    const { id } = parseInput(idParams, request.params);
    const result = await app.pg.query<{ object_key: string; mime_type: 'image/jpeg' | 'image/png' | 'image/webp'; size_bytes: string; purpose: Purpose; status: string }>(
      'SELECT object_key, mime_type, size_bytes::text, purpose, status FROM media_assets WHERE id=$1 AND owner_id=$2', [id, user.id],
    );
    const row = result.rows[0];
    if (!row) throw new AppError(404, 'NOT_FOUND', 'Upload not found.');
    if (row.status === 'ready') return { data: { id, status: 'ready' } };
    if (row.status !== 'pending') throw new AppError(409, 'INVALID_STATE', 'Upload cannot be completed in its current state.');

    const claim = await app.pg.query(
      `UPDATE media_assets SET status='processing', updated_at=now()
       WHERE id=$1 AND owner_id=$2 AND status='pending' RETURNING id`, [id, user.id],
    );
    if (!claim.rowCount) throw new AppError(409, 'INVALID_STATE', 'Upload is already being verified.');
    const maxBytes = row.purpose === 'feedback_screenshot' ? screenshotLimit : app.config.UPLOAD_MAX_BYTES;
    const readyKey = `ready/${user.id}/${id}.${extensionByMime[row.mime_type]}`;
    let normalized: { sizeBytes: number; width: number; height: number; checksum: string };
    try {
      normalized = await app.mediaStorage.normalizeAndPromote(row.object_key, readyKey, row.mime_type, Number(row.size_bytes), maxBytes);
    } catch (error) {
      const invalid = error instanceof AppError && error.statusCode === 422;
      await app.pg.query('UPDATE media_assets SET status=$3::media_status, updated_at=now() WHERE id=$1 AND owner_id=$2 AND status=\'processing\'',
        [id, user.id, invalid ? 'rejected' : 'pending']);
      if (error instanceof AppError) throw error;
      throw new AppError(503, 'MEDIA_UNAVAILABLE', 'Media storage is temporarily unavailable.');
    }

    try {
      const ready = await app.pg.query(
        `UPDATE media_assets SET object_key=$3, size_bytes=$4, checksum=$5, status='ready', ready_at=now(), updated_at=now()
         WHERE id=$1 AND owner_id=$2 AND status='processing'
         RETURNING id, purpose, mime_type AS "mimeType", size_bytes AS "sizeBytes", status, ready_at AS "readyAt"`,
        [id, user.id, readyKey, normalized.sizeBytes, normalized.checksum],
      );
      if (!ready.rowCount) throw new AppError(409, 'INVALID_STATE', 'Upload changed during verification.');
      await app.mediaStorage.deleteObject(row.object_key).catch(() => undefined);
      return { data: { ...ready.rows[0], width: normalized.width, height: normalized.height } };
    } catch (error) {
      await app.mediaStorage.deleteObject(readyKey).catch(() => undefined);
      await app.pg.query("UPDATE media_assets SET status='pending', updated_at=now() WHERE id=$1 AND owner_id=$2 AND status='processing'", [id, user.id]).catch(() => undefined);
      if (error instanceof AppError) throw error;
      throw new AppError(503, 'MEDIA_UNAVAILABLE', 'Media could not be finalized.');
    }
  });

  app.get('/api/v1/media/:id', { config: { authOptional: true } }, async (request, reply) => {
    const { id } = parseInput(idParams, request.params);
    reply.header('Cache-Control', 'private, no-store, max-age=0, must-revalidate')
      .header('CDN-Cache-Control', 'no-store')
      .header('Surrogate-Control', 'no-store')
      .header('Pragma', 'no-cache')
      .header('Expires', '0');
    const result = await app.pg.query<{ object_key: string; mime_type: 'image/jpeg' | 'image/png' | 'image/webp' }>(
      `SELECT m.object_key, m.mime_type FROM media_assets m
       WHERE m.id=$1 AND m.status='ready' AND m.purpose <> 'feedback_screenshot' AND (
         ($2::uuid IS NOT NULL AND m.owner_id=$2 AND m.purpose='avatar')
         OR EXISTS (SELECT 1 FROM users u WHERE u.avatar_media_id=m.id AND u.status='active')
         OR EXISTS (
           SELECT 1 FROM stories s JOIN users creator ON creator.id=s.author_id
           WHERE s.cover_media_id=m.id AND s.deleted_at IS NULL AND creator.status='active'
             AND (
               (s.status='published' AND s.visibility='public')
               OR ($2::uuid IS NOT NULL AND s.author_id=$2 AND s.status='draft'
                 AND NOT EXISTS (SELECT 1 FROM media_key_revocations pending WHERE pending.media_id=m.id))
             )
         )
       )`, [id, request.user?.id ?? null],
    );
    if (!result.rowCount) throw new AppError(404, 'NOT_FOUND', 'Media not found.');
    const object = await app.mediaStorage.readObject(result.rows[0]!.object_key);
    reply.type(result.rows[0]!.mime_type).header('Content-Disposition', 'inline');
    if (typeof object.contentLength === 'number') reply.header('Content-Length', object.contentLength);
    return reply.send(object.body);
  });
}
