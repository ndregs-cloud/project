import type { FastifyInstance } from 'fastify';
import { requestDatabase } from '../db.js';
import { z } from 'zod';
import { AppError } from '../errors.js';
import { parseInput, requireUser, uuidSchema } from '../validation.js';

const idParams = z.object({ id: uuidSchema });

export async function registerMediaRoutes(app: FastifyInstance): Promise<void> {
  app.post('/api/v1/media/upload-intents', { config: { authRequired: true, rateLimitMax: 10 } }, async () => {
    throw new AppError(501, 'NOT_INTEGRATED', 'Media upload is unavailable for the MVP. No changes were made.');
  });

  app.post('/api/v1/media/:id/complete', { config: { authRequired: true, rateLimitMax: 20 } }, async () => {
    throw new AppError(501, 'NOT_INTEGRATED', 'Media upload is unavailable for the MVP. No changes were made.');
  });

  app.get('/api/v1/media/:id', { config: { authOptional: true } }, async (request, reply) => {
    const { id } = parseInput(idParams, request.params);
    reply.header('Cache-Control', 'private, no-store, max-age=0, must-revalidate')
      .header('CDN-Cache-Control', 'no-store')
      .header('Surrogate-Control', 'no-store')
      .header('Pragma', 'no-cache')
      .header('Expires', '0');
    const result = await requestDatabase(request).query<{ object_key: string; mime_type: 'image/jpeg' | 'image/png' | 'image/webp' }>(
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
                 AND NOT public.nova_rls_own_media_revocation_pending(m.id))
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
