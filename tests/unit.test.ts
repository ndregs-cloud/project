import { afterEach, describe, expect, it, vi } from 'vitest';
import { randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import type { Pool, PoolClient } from 'pg';
import type { MediaStorage } from '../src/storage/s3.js';
import { resolveIdentity } from '../src/auth.js';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { decodeCursor, encodeCursor } from '../src/cursor.js';
import { AppError } from '../src/errors.js';
import { signatureMatches } from '../src/storage/s3.js';
import { normalizeImageBuffer } from '../src/storage/s3.js';
import { parseInput } from '../src/validation.js';
import { z } from 'zod';
import sharp from 'sharp';

const apps: Array<Awaited<ReturnType<typeof buildApp>>> = [];
const ephemeralTestHmacKey = randomBytes(32).toString('hex');
function testConfig(environment: NodeJS.ProcessEnv = {}) {
  return loadConfig({ NODE_ENV: 'test', RATE_LIMIT_HMAC_KEY: ephemeralTestHmacKey, ...environment });
}
afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

describe('opaque cursor', () => {
  it('round-trips a stable timestamp and UUID', () => {
    const position = { createdAt: '2026-10-08T00:00:00.000Z', id: 'd3abde25-9cf1-45c4-98b1-5b5046947791' };
    expect(decodeCursor(encodeCursor(position))).toEqual(position);
  });

  it('rejects malformed and oversized cursor values', () => {
    expect(() => decodeCursor('not-json')).toThrow(AppError);
    expect(() => decodeCursor('x'.repeat(513))).toThrow(AppError);
    expect(decodeCursor(undefined)).toBeNull();
  });
});

describe('identity bootstrap security', () => {
  it('fails closed when the identity helper is missing and never issues direct users/auth_subject SQL', async () => {
    const statements: string[] = [];
    const query = vi.fn(async (sql: string) => {
      statements.push(sql);
      if (sql.includes('nova_auth_bootstrap_identity')) {
        throw Object.assign(new Error('sensitive helper and database detail'), { code: '42883' });
      }
      return { rows: [], rowCount: 0 };
    });
    const client = { query } as unknown as PoolClient;
    await expect(resolveIdentity(client)).rejects.toMatchObject({
      statusCode: 503, code: 'IDENTITY_UNAVAILABLE', message: 'Layanan identitas sementara tidak tersedia.',
    });
    expect(statements.some((statement) => /\bINSERT\s+INTO\s+(?:public\.)?users\b/i.test(statement))).toBe(false);
    expect(statements.some((statement) => /\bauth_subject\b/i.test(statement))).toBe(false);
  });
});

describe('validation and media signature checks', () => {
  it('defaults to production and requires explicit database URLs and principal roles', () => {
    expect(() => loadConfig({})).toThrow(/DATABASE_URL/);
    expect(() => loadConfig({ DATABASE_URL: 'postgres://app:secret@db.example:5432/nova', RATE_LIMIT_DATABASE_URL: 'postgres://limiter:secret@db.example:5432/nova' }))
      .toThrow(/MEDIA_REVOCATION_DATABASE_URL/);
    expect(loadConfig({
      DATABASE_URL: 'postgres://app:secret@db.example:5432/nova',
      RATE_LIMIT_DATABASE_URL: 'postgres://limiter:secret@db.example:5432/nova',
      MEDIA_REVOCATION_DATABASE_URL: 'postgres://worker:secret@db.example:5432/nova',
      DATABASE_ROLE: 'nova_fastify_runtime',
      RATE_LIMIT_DATABASE_ROLE: 'nova_rate_limiter_runtime',
      MEDIA_REVOCATION_DATABASE_ROLE: 'nova_media_revocation_worker',
      RATE_LIMIT_HMAC_KEY: ephemeralTestHmacKey,
    }).NODE_ENV).toBe('production');
    const productionRoles = {
      DATABASE_URL: 'postgres://app:secret@db.example:5432/nova',
      RATE_LIMIT_DATABASE_URL: 'postgres://limiter:secret@db.example:5432/nova',
      MEDIA_REVOCATION_DATABASE_URL: 'postgres://worker:secret@db.example:5432/nova',
      DATABASE_ROLE: 'nova_fastify_runtime',
      RATE_LIMIT_DATABASE_ROLE: 'nova_rate_limiter_runtime',
      MEDIA_REVOCATION_DATABASE_ROLE: 'nova_media_revocation_worker',
      RATE_LIMIT_HMAC_KEY: ephemeralTestHmacKey,
    };
    expect(() => loadConfig({ ...productionRoles, DATABASE_ROLE: undefined })).toThrow(/DATABASE_ROLE/);
    expect(() => loadConfig({ ...productionRoles, RATE_LIMIT_DATABASE_ROLE: undefined })).toThrow(/RATE_LIMIT_DATABASE_ROLE/);
    expect(() => loadConfig({ ...productionRoles, MEDIA_REVOCATION_DATABASE_ROLE: undefined })).toThrow(/MEDIA_REVOCATION_DATABASE_ROLE/);
    expect(() => loadConfig({ ...productionRoles, RATE_LIMIT_HMAC_KEY: undefined })).toThrow(/RATE_LIMIT_HMAC_KEY/);
    expect(() => loadConfig({ NODE_ENV: 'test' })).toThrow(/RATE_LIMIT_HMAC_KEY/);
    expect(() => loadConfig({ NODE_ENV: 'test', RATE_LIMIT_HMAC_KEY: 'invalid-short-key' })).toThrow(/RATE_LIMIT_HMAC_KEY/);
    expect(testConfig({
      DATABASE_ROLE: 'nova_fastify_runtime',
      RATE_LIMIT_DATABASE_ROLE: 'nova_rate_limiter_runtime',
      MEDIA_REVOCATION_DATABASE_ROLE: 'nova_media_revocation_worker',
    })).toMatchObject({
      DATABASE_ROLE: 'nova_fastify_runtime',
      RATE_LIMIT_DATABASE_ROLE: 'nova_rate_limiter_runtime',
      MEDIA_REVOCATION_DATABASE_ROLE: 'nova_media_revocation_worker',
    });
    expect(() => loadConfig({ NODE_ENV: 'test', DATABASE_ROLE: 'postgres' })).toThrow(/DATABASE_ROLE/);
    expect(loadConfig({ NODE_ENV: 'development' }).DATABASE_URL)
      .toBe('postgres://nova_local:nova-local-only-change-me@localhost:5432/nova');
  });

  it('requires HTTPS for configured production JWKS and S3 endpoints but permits local HTTP in development', () => {
    const production = {
      DATABASE_URL: 'postgres://app:secret@db.example:5432/nova',
      RATE_LIMIT_DATABASE_URL: 'postgres://limiter:secret@db.example:5432/nova',
      MEDIA_REVOCATION_DATABASE_URL: 'postgres://worker:secret@db.example:5432/nova',
      DATABASE_ROLE: 'nova_fastify_runtime',
      RATE_LIMIT_DATABASE_ROLE: 'nova_rate_limiter_runtime',
      MEDIA_REVOCATION_DATABASE_ROLE: 'nova_media_revocation_worker',
      RATE_LIMIT_HMAC_KEY: ephemeralTestHmacKey,
    };
    expect(() => loadConfig({ ...production, AUTH_JWKS_URL: 'http://identity.example/jwks' })).toThrow(/AUTH_JWKS_URL/);
    expect(() => loadConfig({ ...production, S3_ENDPOINT: 'http://storage.example' })).toThrow(/S3_ENDPOINT/);
    expect(loadConfig({ NODE_ENV: 'development', AUTH_JWKS_URL: 'http://127.0.0.1:8080/jwks' }).AUTH_JWKS_URL)
      .toBe('http://127.0.0.1:8080/jwks');
    expect(loadConfig({ ...production, AUTH_JWKS_URL: 'https://identity.example/jwks', S3_ENDPOINT: 'https://storage.example' }).NODE_ENV)
      .toBe('production');
  });

  it('maps invalid input to a structured validation error', () => {
    expect(() => parseInput(z.object({ title: z.string().min(1) }), { title: '' })).toThrowError(/Periksa kembali/);
  });

  it('accepts matching image signatures and rejects mismatched MIME claims', () => {
    expect(signatureMatches('image/png', Uint8Array.from([137, 80, 78, 71, 13, 10, 26, 10]))).toBe(true);
    expect(signatureMatches('image/png', Uint8Array.from([255, 216, 255]))).toBe(false);
    expect(signatureMatches('image/webp', new TextEncoder().encode('RIFFxxxxWEBP'))).toBe(true);
  });

  it('rejects invalid upload size, disallowed MIME, and signature before Sharp parsing', async () => {
    const validImage = await sharp({ create: { width: 2, height: 2, channels: 3, background: 'white' } }).png().toBuffer();
    await expect(normalizeImageBuffer(validImage, 'image/gif' as never, 1024)).rejects.toMatchObject({
      statusCode: 422, message: expect.stringContaining('does not match an allowed image type or size'),
    });
    await expect(normalizeImageBuffer(validImage, 'image/jpeg', 1024)).rejects.toMatchObject({
      statusCode: 422, message: expect.stringContaining('does not match an allowed image type or size'),
    });
    await expect(normalizeImageBuffer(validImage, 'image/png', validImage.length - 1)).rejects.toMatchObject({
      statusCode: 422, message: expect.stringContaining('does not match an allowed image type or size'),
    });
  });

  it('normalizes valid PNG and WebP uploads within the configured size limit', async () => {
    const source = sharp({ create: { width: 8, height: 6, channels: 3, background: { r: 40, g: 80, b: 120 } } });
    const cases = [
      { mime: 'image/png' as const, format: 'png' as const, input: await source.clone().png().toBuffer() },
      { mime: 'image/webp' as const, format: 'webp' as const, input: await source.clone().webp().toBuffer() },
    ];
    for (const image of cases) {
      const normalized = await normalizeImageBuffer(image.input, image.mime, 2 * 1024 * 1024);
      expect(normalized.sizeBytes).toBeLessThanOrEqual(2 * 1024 * 1024);
      expect((await sharp(normalized.buffer).metadata()).format).toBe(image.format);
    }
  });

  it('applies EXIF orientation and strips metadata from normalized images', async () => {
    const source = await sharp({ create: { width: 20, height: 10, channels: 3, background: { r: 20, g: 40, b: 60 } } })
      .jpeg().withMetadata({ orientation: 6 }).toBuffer();
    expect((await sharp(source).metadata()).orientation).toBe(6);
    const normalized = await normalizeImageBuffer(source, 'image/jpeg', 2 * 1024 * 1024);
    const metadata = await sharp(normalized.buffer).metadata();
    expect(metadata.orientation).toBeUndefined();
    expect([normalized.width, normalized.height]).toEqual([10, 20]);
    expect(normalized.checksum).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe('API smoke checks', () => {
  it('keeps health probes independent of PostgreSQL rate-limit storage', async () => {
    const query = vi.fn(async () => ({ rows: [], rowCount: 0 }));
    const fakePool = { query } as unknown as Pool;
    const storage = { close: vi.fn(async () => undefined) } as unknown as MediaStorage;
    const app = await buildApp({
      config: testConfig({ LOG_LEVEL: 'silent' }),
      pg: fakePool,
      rateLimitPg: fakePool,
      mediaStorage: storage,
    });
    apps.push(app);

    const response = await app.inject({ method: 'GET', url: '/healthz' });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'ok' });
    expect(response.headers['x-robots-tag']).toBe('noindex, nofollow, noarchive');
    expect(response.headers['x-request-id']).toMatch(/^req_/);
    expect(query).not.toHaveBeenCalled();
  });

  it('omits unavailable follower and following counts from public profiles instead of returning zero', async () => {
    const profile = {
      id: '11111111-1111-4111-8111-111111111111', username: 'reader', displayName: 'Reader',
      bio: null, avatarMediaId: null, createdAt: '2026-10-10T00:00:00.000Z',
    };
    const statements: string[] = [];
    const query = vi.fn(async (sql: string) => {
      statements.push(sql);
      if (sql.includes('nova_rate_limit_record')) return { rows: [{ hits: 1 }], rowCount: 1 };
      if (sql.includes('FROM users u WHERE u.username_normalized')) return { rows: [profile], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    });
    const fakePool = { query } as unknown as Pool;
    const storage = { close: vi.fn(async () => undefined) } as unknown as MediaStorage;
    const app = await buildApp({
      config: testConfig({ LOG_LEVEL: 'silent' }),
      pg: fakePool,
      rateLimitPg: fakePool,
      mediaStorage: storage,
    });
    apps.push(app);

    const response = await app.inject({ method: 'GET', url: '/api/v1/users/reader' });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ data: profile });
    expect(response.json().data).not.toHaveProperty('followerCount');
    expect(response.json().data).not.toHaveProperty('followingCount');
    const profileQuery = statements.find((sql) => sql.includes('FROM users u WHERE u.username_normalized'));
    expect(profileQuery).toBeDefined();
    expect(profileQuery).not.toMatch(/\bfollows\b|\bcount\s*\(/i);
  });

  it('requires a verified bearer token to create a draft', async () => {
    const fakePool = { query: vi.fn(async () => ({ rows: [], rowCount: 0 })) } as unknown as Pool;
    const storage = { close: vi.fn(async () => undefined) } as unknown as MediaStorage;
    const app = await buildApp({
      config: testConfig({ LOG_LEVEL: 'silent' }),
      pg: fakePool,
      rateLimitPg: fakePool,
      mediaStorage: storage,
    });
    apps.push(app);

    const response = await app.inject({ method: 'POST', url: '/api/v1/stories', payload: { title: 'Privat' } });
    expect(response.statusCode).toBe(401);
    expect(response.json().error).toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(response.json().error.requestId).toMatch(/^req_/);
  });

  it('applies the IP rate limit before rejecting a request without a token', async () => {
    const query = vi.fn(async () => ({ rows: [{ hits: 301 }], rowCount: 1 }));
    const fakePool = { query } as unknown as Pool;
    const storage = { close: vi.fn(async () => undefined) } as unknown as MediaStorage;
    const app = await buildApp({
      config: testConfig({ RATE_LIMIT_MAX: '1', LOG_LEVEL: 'silent' }),
      pg: fakePool,
      rateLimitPg: fakePool,
      mediaStorage: storage,
    });
    apps.push(app);

    const response = await app.inject({ method: 'POST', url: '/api/v1/stories', payload: { title: 'Anonymous request' } });
    expect(response.statusCode).toBe(429);
    expect(response.json().error).toMatchObject({ code: 'RATE_LIMITED' });
    expect(query).toHaveBeenCalledTimes(1);
  });
});

describe('cover access revocation', () => {
  it('rechecks a previously fetched API cover URL and prevents shared caching', async () => {
    let permitted = true;
    const query = vi.fn(async (sql: string) => {
      if (sql.includes('nova_rate_limit_record')) return { rows: [{ hits: 1 }], rowCount: 1 };
      return permitted
        ? { rows: [{ object_key: 'ready/fictional/cover.jpg', mime_type: 'image/jpeg' }], rowCount: 1 }
        : { rows: [], rowCount: 0 };
    });
    const fakePool = { query } as unknown as Pool;
    const image = Buffer.from('fictional-cover-bytes');
    const readObject = vi.fn(async () => ({ body: Readable.from([image]), contentLength: image.length }));
    const storage = { readObject, close: vi.fn(async () => undefined) } as unknown as MediaStorage;
    const app = await buildApp({
      config: testConfig({ LOG_LEVEL: 'silent' }),
      pg: fakePool,
      rateLimitPg: fakePool,
      mediaStorage: storage,
    });
    apps.push(app);

    const url = '/api/v1/media/11111111-1111-4111-8111-111111111111';
    const firstRead = await app.inject({ method: 'GET', url });
    expect(firstRead.statusCode).toBe(200);
    expect(firstRead.body).toBe(image.toString());
    expect(firstRead.headers.location).toBeUndefined();
    expect(firstRead.headers['cache-control']).toContain('no-store');
    expect(firstRead.headers['cdn-cache-control']).toBe('no-store');
    expect(firstRead.headers['surrogate-control']).toBe('no-store');

    permitted = false;
    const retryOfPreviouslyFetchedUrl = await app.inject({ method: 'GET', url });
    expect(retryOfPreviouslyFetchedUrl.statusCode).toBe(404);
    expect(retryOfPreviouslyFetchedUrl.headers['cache-control']).toContain('no-store');
    expect(readObject).toHaveBeenCalledTimes(1);
  });
});
