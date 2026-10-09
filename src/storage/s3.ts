import { createHash, randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import { CopyObjectCommand, DeleteObjectCommand, GetObjectCommand, HeadObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import sharp from 'sharp';
import type { AppConfig } from '../config.js';
import { AppError } from '../errors.js';

const formatByMime = { 'image/jpeg': 'jpeg', 'image/png': 'png', 'image/webp': 'webp' } as const;
type AllowedImageMime = keyof typeof formatByMime;

export class ObjectCopyError extends Error {
  constructor() {
    super('S3 object copy failed.');
    this.name = 'ObjectCopyError';
  }
}

export class MediaStorage {
  private readonly client: S3Client | null;
  constructor(private readonly config: AppConfig) {
    const ready = Boolean(config.S3_BUCKET && config.S3_ACCESS_KEY_ID && config.S3_SECRET_ACCESS_KEY);
    this.client = ready ? new S3Client({
      region: config.S3_REGION,
      ...(config.S3_ENDPOINT ? { endpoint: config.S3_ENDPOINT } : {}),
      forcePathStyle: config.S3_FORCE_PATH_STYLE,
      credentials: { accessKeyId: config.S3_ACCESS_KEY_ID!, secretAccessKey: config.S3_SECRET_ACCESS_KEY! },
    }) : null;
  }

  async createUploadUrl(key: string, mimeType: AllowedImageMime, sizeBytes: number): Promise<string> {
    const { client, bucket } = this.requireReady();
    const command = new PutObjectCommand({ Bucket: bucket, Key: key, ContentType: mimeType, ContentLength: sizeBytes });
    return getSignedUrl(client, command, { expiresIn: this.config.UPLOAD_URL_TTL_SECONDS });
  }

  async normalizeAndPromote(
    sourceKey: string,
    readyKey: string,
    mimeType: AllowedImageMime,
    expectedBytes: number,
    maxBytes: number,
  ): Promise<{ sizeBytes: number; width: number; height: number; checksum: string }> {
    const { client, bucket } = this.requireReady();
    let head;
    try {
      head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: sourceKey }));
    } catch {
      throw new AppError(422, 'MEDIA_NOT_UPLOADED', 'The upload is not available for verification.');
    }
    const declaredMime = head.ContentType?.split(';')[0]?.trim().toLowerCase();
    if (!isAllowedImageMime(mimeType) || !Number.isSafeInteger(expectedBytes) || expectedBytes < 1 ||
        !Number.isSafeInteger(maxBytes) || maxBytes < 1 || expectedBytes > maxBytes ||
        head.ContentLength !== expectedBytes || declaredMime !== mimeType) {
      throw new AppError(422, 'MEDIA_INVALID', 'The uploaded file does not match its declared type or size.');
    }

    const object = await client.send(new GetObjectCommand({ Bucket: bucket, Key: sourceKey }));
    if (!object.Body) throw new AppError(422, 'MEDIA_INVALID', 'The uploaded image could not be read.');
    const input = Buffer.from(await object.Body.transformToByteArray());
    if (input.length !== expectedBytes || input.length > maxBytes) {
      throw new AppError(422, 'MEDIA_INVALID', 'The uploaded file exceeds the permitted size.');
    }
    const normalized = await normalizeImageBuffer(input, mimeType, maxBytes);
    await client.send(new PutObjectCommand({
      Bucket: bucket, Key: readyKey, Body: normalized.buffer, ContentType: mimeType,
      ContentLength: normalized.sizeBytes, CacheControl: 'private, max-age=300',
    }));
    // The browser's signed PUT can only mutate this quarantine key; the ready object has a distinct key.
    return {
      sizeBytes: normalized.sizeBytes,
      width: normalized.width,
      height: normalized.height,
      checksum: normalized.checksum,
    };
  }

  async deleteObject(key: string): Promise<void> {
    const { client, bucket } = this.requireReady();
    await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
    try {
      await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    } catch (error) {
      if (isObjectNotFound(error)) return;
      throw error;
    }
    throw new Error('Object remains readable after deletion.');
  }

  async copyObjectToKey(sourceKey: string, destinationKey: string): Promise<void> {
    const { client, bucket } = this.requireReady();
    try {
      const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: sourceKey }));
      const copySource = `/${bucket}/${sourceKey.split('/').map(encodeURIComponent).join('/')}`;
      await client.send(new CopyObjectCommand({
        Bucket: bucket,
        Key: destinationKey,
        CopySource: copySource,
        MetadataDirective: 'REPLACE',
        Metadata: head.Metadata ?? {},
        ContentType: head.ContentType ?? 'application/octet-stream',
        CacheControl: 'private, no-store, max-age=0, must-revalidate',
        ...(head.ContentDisposition ? { ContentDisposition: head.ContentDisposition } : {}),
        ...(head.ContentEncoding ? { ContentEncoding: head.ContentEncoding } : {}),
        ...(head.ContentLanguage ? { ContentLanguage: head.ContentLanguage } : {}),
        ...(head.WebsiteRedirectLocation ? { WebsiteRedirectLocation: head.WebsiteRedirectLocation } : {}),
        ...(head.Expires ? { Expires: head.Expires } : {}),
      }));
    } catch {
      throw new ObjectCopyError();
    }
  }

  async createFeedbackScreenshotReadUrl(key: string, expiresIn = 60): Promise<string> {
    const { client, bucket } = this.requireReady();
    return getSignedUrl(client, new GetObjectCommand({
      Bucket: bucket,
      Key: key,
      ResponseContentDisposition: 'inline',
      ResponseCacheControl: 'private, no-store, max-age=0, must-revalidate',
    }), { expiresIn });
  }

  async readObject(key: string): Promise<{ body: Readable; contentLength?: number }> {
    const { client, bucket } = this.requireReady();
    let object;
    try {
      object = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
    } catch {
      throw new AppError(503, 'MEDIA_UNAVAILABLE', 'Media storage is temporarily unavailable.');
    }
    if (!object.Body) throw new AppError(503, 'MEDIA_UNAVAILABLE', 'Media storage returned an empty object.');
    return {
      body: Readable.fromWeb(object.Body.transformToWebStream()),
      ...(typeof object.ContentLength === 'number' ? { contentLength: object.ContentLength } : {}),
    };
  }

  async close(): Promise<void> { await this.client?.destroy(); }

  private requireReady(): { client: S3Client; bucket: string } {
    if (!this.client || !this.config.S3_BUCKET) {
      throw new AppError(503, 'MEDIA_NOT_CONFIGURED', 'Media storage is not configured.');
    }
    return { client: this.client, bucket: this.config.S3_BUCKET };
  }
}

export function versionedObjectKey(sourceKey: string): string {
  const separator = sourceKey.lastIndexOf('/');
  const prefix = separator >= 0 ? sourceKey.slice(0, separator + 1) : '';
  const basename = separator >= 0 ? sourceKey.slice(separator + 1) : sourceKey;
  return `${prefix}${randomUUID()}-${basename}`;
}

export async function normalizeImageBuffer(
  input: Buffer,
  mimeType: AllowedImageMime,
  maxBytes: number,
): Promise<{ buffer: Buffer; sizeBytes: number; width: number; height: number; checksum: string }> {
  // Reject untrusted MIME, byte length, and magic-byte mismatches before Sharp parses the payload.
  if (!isAllowedImageMime(mimeType) || !Number.isSafeInteger(maxBytes) || maxBytes < 1 ||
      input.length === 0 || input.length > maxBytes || !signatureMatches(mimeType, input)) {
    throw new AppError(422, 'MEDIA_INVALID', 'The uploaded file does not match an allowed image type or size.');
  }
  let metadata: Awaited<ReturnType<ReturnType<typeof sharp>['metadata']>>;
  try {
    metadata = await sharp(input, { failOn: 'error', limitInputPixels: 25_000_000 }).metadata();
  } catch {
    throw new AppError(422, 'MEDIA_INVALID', 'The uploaded file is not a valid image.');
  }
  const expectedFormat = formatByMime[mimeType];
  if (metadata.format !== expectedFormat || !metadata.width || !metadata.height ||
      metadata.width > 8192 || metadata.height > 8192 || metadata.width * metadata.height > 25_000_000 ||
      (metadata.pages ?? 1) > 1) {
    throw new AppError(422, 'MEDIA_INVALID', 'The image format or dimensions are not allowed.');
  }

  let buffer: Buffer;
  try {
    const pipeline = sharp(input, { failOn: 'error', limitInputPixels: 25_000_000 }).rotate();
    if (mimeType === 'image/jpeg') buffer = await pipeline.jpeg({ quality: 86, mozjpeg: true }).toBuffer();
    else if (mimeType === 'image/png') buffer = await pipeline.png({ compressionLevel: 9 }).toBuffer();
    else buffer = await pipeline.webp({ quality: 86 }).toBuffer();
  } catch {
    throw new AppError(422, 'MEDIA_INVALID', 'The image could not be safely normalized.');
  }
  if (buffer.length === 0 || buffer.length > maxBytes) throw new AppError(422, 'MEDIA_INVALID', 'The normalized image exceeds the permitted size.');
  const output = await sharp(buffer, { failOn: 'error' }).metadata();
  if (!output.width || !output.height) throw new AppError(422, 'MEDIA_INVALID', 'The normalized image could not be verified.');
  return {
    buffer,
    sizeBytes: buffer.length,
    width: output.width,
    height: output.height,
    checksum: createHash('sha256').update(buffer).digest('hex'),
  };
}

export function signatureMatches(mimeType: string, bytes: Uint8Array): boolean {
  if (mimeType === 'image/jpeg') return bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  if (mimeType === 'image/png') return bytes.length >= 8 && [137, 80, 78, 71, 13, 10, 26, 10].every((byte, index) => bytes[index] === byte);
  if (mimeType === 'image/webp') {
    return bytes.length >= 12 && String.fromCharCode(...bytes.slice(0, 4)) === 'RIFF' && String.fromCharCode(...bytes.slice(8, 12)) === 'WEBP';
  }
  return false;
}

function isAllowedImageMime(mimeType: string): mimeType is AllowedImageMime {
  return Object.prototype.hasOwnProperty.call(formatByMime, mimeType);
}

function isObjectNotFound(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const value = error as { name?: unknown; Code?: unknown; code?: unknown; $metadata?: { httpStatusCode?: unknown } };
  return value.$metadata?.httpStatusCode === 404 ||
    value.name === 'NotFound' || value.name === 'NoSuchKey' || value.Code === 'NoSuchKey' || value.code === 'NoSuchKey';
}
