import { z } from 'zod';
import type { FastifyRequest } from 'fastify';
import { AppError } from './errors.js';

export const uuidSchema = z.string().uuid();
export const idParamsSchema = z.object({ id: uuidSchema });
export const usernameParamsSchema = z.object({ username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_]+$/) });
export const tagIdsSchema = z.array(uuidSchema).max(8).refine((ids) => new Set(ids).size === ids.length, 'Tag tidak boleh duplikat.');

export function parseInput<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    const fields: Record<string, string> = {};
    for (const issue of parsed.error.issues) {
      const key = issue.path.join('.') || 'body';
      fields[key] ??= issue.message;
    }
    throw new AppError(400, 'VALIDATION_ERROR', 'Periksa kembali isian yang ditandai.', fields);
  }
  return parsed.data;
}

export function requireUser(request: FastifyRequest) {
  if (!request.user) throw new AppError(401, 'UNAUTHENTICATED', 'Autentikasi diperlukan.');
  return request.user;
}

export function requireModerator(request: FastifyRequest) {
  const user = requireUser(request);
  if (user.role !== 'moderator') {
    throw new AppError(403, 'FORBIDDEN', 'Akses moderator diperlukan.');
  }
  return user;
}

export function requireSupport(request: FastifyRequest) {
  const user = requireUser(request);
  if (user.role !== 'support') {
    throw new AppError(403, 'FORBIDDEN', 'Access for the support team is required.');
  }
  return user;
}

export function requireSecurityStaff(request: FastifyRequest) {
  const user = requireUser(request);
  if (user.role !== 'security') {
    throw new AppError(403, 'FORBIDDEN', 'Access for the security team is required.');
  }
  return user;
}

export function parsePageSize(value: unknown, fallback = 20): number {
  const parsed = z.coerce.number().int().min(1).max(50).safeParse(value ?? fallback);
  if (!parsed.success) throw new AppError(400, 'VALIDATION_ERROR', 'Ukuran halaman harus antara 1 dan 50.');
  return parsed.data;
}
