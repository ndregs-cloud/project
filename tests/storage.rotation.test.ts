import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { MediaStorage, versionedObjectKey } from '../src/storage/s3.js';

const servers: Server[] = [];
const storages: MediaStorage[] = [];
afterEach(async () => {
  await Promise.all(storages.splice(0).map((storage) => storage.close()));
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

describe('S3 cover-key rotation', () => {
  it('copies to an uncacheable versioned key and makes a previously signed origin URL return 404', async () => {
    const bucket = 'nova-test-private';
    const oldKey = 'ready/fictional/cover.jpg';
    const contents = Buffer.from('fictional cover bytes');
    const objects = new Map([[oldKey, contents]]);
    const requests: Array<{ method: string; path: string; copySource?: string; cacheControl?: string }> = [];
    let suppressDelete = false;
    const server = createServer((request, response) => {
      const path = decodeURIComponent(new URL(request.url ?? '/', 'http://localhost').pathname);
      const prefix = `/${bucket}/`;
      const key = path.startsWith(prefix) ? path.slice(prefix.length) : '';
      const copySource = request.headers['x-amz-copy-source'];
      requests.push({
        method: request.method ?? '', path,
        ...(typeof copySource === 'string' ? { copySource } : {}),
        ...(typeof request.headers['cache-control'] === 'string' ? { cacheControl: request.headers['cache-control'] } : {}),
      });

      if (request.method === 'HEAD') {
        const object = objects.get(key);
        if (!object) { response.writeHead(404).end(); return; }
        response.writeHead(200, {
          'Content-Length': object.length,
          'Content-Type': 'image/jpeg',
          'Cache-Control': 'private, max-age=300',
        }).end();
        return;
      }
      if (request.method === 'PUT' && typeof copySource === 'string') {
        const copiedKey = decodeURIComponent(copySource.replace(/^\/?[^/]+\//, ''));
        const object = objects.get(copiedKey);
        if (!object) { response.writeHead(404).end(); return; }
        objects.set(key, object);
        response.writeHead(200, { 'Content-Type': 'application/xml' })
          .end('<CopyObjectResult><LastModified>2026-10-08T00:00:00.000Z</LastModified><ETag>"fixture-etag"</ETag></CopyObjectResult>');
        return;
      }
      if (request.method === 'DELETE') {
        if (!suppressDelete) objects.delete(key);
        response.writeHead(204).end();
        return;
      }
      if (request.method === 'GET') {
        const object = objects.get(key);
        if (!object) { response.writeHead(404).end(); return; }
        response.writeHead(200, { 'Content-Type': 'image/jpeg', 'Cache-Control': 'private, no-store' }).end(object);
        return;
      }
      response.writeHead(405).end();
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    servers.push(server);
    const port = (server.address() as AddressInfo).port;
    const storage = new MediaStorage(loadConfig({
      NODE_ENV: 'test', LOG_LEVEL: 'silent',
      S3_ENDPOINT: `http://127.0.0.1:${port}`, S3_REGION: 'us-east-1', S3_BUCKET: bucket,
      S3_ACCESS_KEY_ID: 'test-access-key', S3_SECRET_ACCESS_KEY: 'test-only-secret', S3_FORCE_PATH_STYLE: 'true',
    }));
    storages.push(storage);

    const client = new S3Client({
      region: 'us-east-1', endpoint: `http://127.0.0.1:${port}`, forcePathStyle: true,
      credentials: { accessKeyId: 'test-access-key', secretAccessKey: 'test-only-secret' },
    });
    const oldUrl = await getSignedUrl(client, new GetObjectCommand({ Bucket: bucket, Key: oldKey }), { expiresIn: 60 });
    const destinationKey = versionedObjectKey(oldKey);
    await storage.copyObjectToKey(oldKey, destinationKey);
    suppressDelete = true;
    await expect(storage.deleteObject(oldKey)).rejects.toThrow('Object remains readable after deletion.');
    const oldResponseWhileUnverified = await fetch(oldUrl);
    expect(oldResponseWhileUnverified.status).toBe(200);
    suppressDelete = false;
    await storage.deleteObject(oldKey);
    const oldResponse = await fetch(oldUrl);
    const newResponse = await fetch(await getSignedUrl(client, new GetObjectCommand({ Bucket: bucket, Key: destinationKey }), { expiresIn: 60 }));
    await client.destroy();

    expect(destinationKey).not.toBe(oldKey);
    expect(oldResponse.status).toBe(404);
    expect(newResponse.status).toBe(200);
    expect(Buffer.from(await newResponse.arrayBuffer())).toEqual(contents);
    expect(requests.map((request) => request.method)).toEqual(['HEAD', 'PUT', 'DELETE', 'HEAD', 'GET', 'DELETE', 'HEAD', 'GET', 'GET']);
    expect(requests[1]?.copySource).toContain('/ready/fictional/cover.jpg');
    expect(requests[1]?.cacheControl).toContain('no-store');
  });
});
