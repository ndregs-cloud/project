import { afterEach, describe, expect, it, vi } from 'vitest';
import { Readable } from 'node:stream';
import type { Pool } from 'pg';
import type { MediaStorage } from '../src/storage/s3.js';
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

describe('validation and media signature checks', () => {
  it('defaults to production and requires an explicit production database URL', () => {
    expect(() => loadConfig({})).toThrow(/DATABASE_URL/);
    expect(loadConfig({ DATABASE_URL: 'postgres://app:secret@db.example:5432/nova' }).NODE_ENV).toBe('production');
    expect(loadConfig({ NODE_ENV: 'development' }).DATABASE_URL)
      .toBe('postgres://nova_local:nova-local-only-change-me@localhost:5432/nova');
  });

  it('requires HTTPS for configured production JWKS and S3 endpoints but permits local HTTP in development', () => {
    const production = { DATABASE_URL: 'postgres://app:secret@db.example:5432/nova' };
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
      config: loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent' }),
      pg: fakePool,
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

  it('requires a verified bearer token to create a draft', async () => {
    const fakePool = { query: vi.fn(async () => ({ rows: [], rowCount: 0 })) } as unknown as Pool;
    const storage = { close: vi.fn(async () => undefined) } as unknown as MediaStorage;
    const app = await buildApp({
      config: loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent' }),
      pg: fakePool,
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
      config: loadConfig({ NODE_ENV: 'test', RATE_LIMIT_MAX: '1', LOG_LEVEL: 'silent' }),
      pg: fakePool,
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
      if (sql.includes('INSERT INTO rate_limit_buckets')) return { rows: [{ hits: 1 }], rowCount: 1 };
      return permitted
        ? { rows: [{ object_key: 'ready/fictional/cover.jpg', mime_type: 'image/jpeg' }], rowCount: 1 }
        : { rows: [], rowCount: 0 };
    });
    const fakePool = { query } as unknown as Pool;
    const image = Buffer.from('fictional-cover-bytes');
    const readObject = vi.fn(async () => ({ body: Readable.from([image]), contentLength: image.length }));
    const storage = { readObject, close: vi.fn(async () => undefined) } as unknown as MediaStorage;
    const app = await buildApp({
      config: loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent' }),
      pg: fakePool,
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
