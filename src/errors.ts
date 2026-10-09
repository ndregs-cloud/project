import type { FastifyReply, FastifyRequest } from 'fastify';

export class AppError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
    public readonly fields?: Record<string, string>,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export function fail(statusCode: number, code: string, message: string, fields?: Record<string, string>): never {
  throw new AppError(statusCode, code, message, fields);
}

export function installErrorHandler(app: import('fastify').FastifyInstance): void {
  app.setErrorHandler((error: Error & { statusCode?: number; validation?: unknown; code?: string }, request: FastifyRequest, reply: FastifyReply) => {
    if (error instanceof AppError) {
      return reply.code(error.statusCode).send({
        error: {
          code: error.code,
          message: error.message,
          requestId: request.id,
          ...(error.fields ? { fields: error.fields } : {}),
        },
      });
    }

    if (error.validation) {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Periksa kembali isian yang ditandai.', requestId: request.id },
      });
    }

    if (error.statusCode === 413 || error.code === 'FST_ERR_CTP_BODY_TOO_LARGE') {
      return reply.code(413).send({
        error: { code: 'REQUEST_TOO_LARGE', message: 'Ukuran request melebihi batas.', requestId: request.id },
      });
    }
    if (error.statusCode === 415) {
      return reply.code(415).send({
        error: { code: 'UNSUPPORTED_MEDIA_TYPE', message: 'Tipe konten request tidak didukung.', requestId: request.id },
      });
    }

    if (error.code === '23505') {
      return reply.code(409).send({
        error: { code: 'CONFLICT', message: 'Data bertentangan dengan data yang sudah ada.', requestId: request.id },
      });
    }
    if (error.code === '23503' || error.code === '23514') {
      return reply.code(400).send({
        error: { code: 'VALIDATION_ERROR', message: 'Relasi atau nilai yang diberikan tidak valid.', requestId: request.id },
      });
    }

    request.log.error({ errorType: error.name, code: error.code }, 'Unhandled request error');
    return reply.code(500).send({
      error: { code: 'INTERNAL_ERROR', message: 'Terjadi kesalahan sementara.', requestId: request.id },
    });
  });
}
