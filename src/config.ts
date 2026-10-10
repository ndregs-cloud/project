import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('production'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  DATABASE_URL: z.string().min(1).optional(),
  RATE_LIMIT_DATABASE_URL: z.string().min(1).optional(),
  MEDIA_REVOCATION_DATABASE_URL: z.string().min(1).optional(),
  DATABASE_ROLE: z.enum(['nova_fastify_runtime']).optional(),
  RATE_LIMIT_DATABASE_ROLE: z.enum(['nova_rate_limiter_runtime']).optional(),
  MEDIA_REVOCATION_DATABASE_ROLE: z.enum(['nova_media_revocation_worker']).optional(),
  DATABASE_POOL_MAX: z.coerce.number().int().min(1).max(100).default(10),
  CORS_ORIGINS: z.string().default('http://localhost:5173'),
  TRUST_PROXY: z.string().default(''),
  NOINDEX: z.enum(['true', 'false']).default('true').transform((value) => value === 'true'),
  AUTH_JWKS_URL: z.string().url().optional(),
  AUTH_ISSUER: z.string().url().optional(),
  AUTH_AUDIENCE: z.string().min(1).optional(),
  S3_ENDPOINT: z.string().url().optional(),
  S3_REGION: z.string().default('us-east-1'),
  S3_BUCKET: z.string().optional(),
  S3_ACCESS_KEY_ID: z.string().optional(),
  S3_SECRET_ACCESS_KEY: z.string().optional(),
  S3_FORCE_PATH_STYLE: z.enum(['true', 'false']).default('true').transform((value) => value === 'true'),
  UPLOAD_MAX_BYTES: z.coerce.number().int().min(1024).max(25 * 1024 * 1024).default(5 * 1024 * 1024),
  UPLOAD_URL_TTL_SECONDS: z.coerce.number().int().min(60).max(900).default(300),
  FEEDBACK_RETENTION_DAYS: z.coerce.number().int().min(7).max(365).default(90),
  SECURITY_REPORT_RETENTION_DAYS: z.coerce.number().int().min(30).max(730).default(180),
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(120),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1000).default(60_000),
  RATE_LIMIT_HMAC_KEY: z.string().min(32).optional(),
});

export type AppConfig = Omit<z.infer<typeof envSchema>, 'DATABASE_URL' | 'RATE_LIMIT_HMAC_KEY'> & {
  DATABASE_URL: string;
  RATE_LIMIT_HMAC_KEY: string;
};

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    const keys = [...new Set(parsed.error.issues.map((issue) => issue.path.join('.')))];
    throw new Error(`Invalid environment configuration (${keys.join(', ')})`);
  }
  const config = parsed.data;
  if (config.NODE_ENV === 'production' && !config.DATABASE_URL) {
    throw new Error('Invalid environment configuration (DATABASE_URL)');
  }
  if (config.NODE_ENV === 'production' && !config.RATE_LIMIT_DATABASE_URL) {
    throw new Error('Invalid environment configuration (RATE_LIMIT_DATABASE_URL)');
  }
  if (config.NODE_ENV === 'production' && !config.MEDIA_REVOCATION_DATABASE_URL) {
    throw new Error('Invalid environment configuration (MEDIA_REVOCATION_DATABASE_URL)');
  }
  if (config.NODE_ENV === 'production') {
    for (const key of ['DATABASE_ROLE', 'RATE_LIMIT_DATABASE_ROLE', 'MEDIA_REVOCATION_DATABASE_ROLE'] as const) {
      if (!config[key]) throw new Error(`Invalid environment configuration (${key})`);
    }
    if (!config.RATE_LIMIT_HMAC_KEY) throw new Error('Invalid environment configuration (RATE_LIMIT_HMAC_KEY)');
  }
  if (config.NODE_ENV === 'test' && !config.RATE_LIMIT_HMAC_KEY) {
    throw new Error('Invalid environment configuration (RATE_LIMIT_HMAC_KEY)');
  }
  if (config.NODE_ENV === 'production') {
    for (const key of ['AUTH_JWKS_URL', 'S3_ENDPOINT'] as const) {
      const endpoint = config[key];
      if (endpoint && new URL(endpoint).protocol !== 'https:') {
        throw new Error(`Invalid environment configuration (${key})`);
      }
    }
  }
  return {
    ...config,
    // A fixed convenience fallback is limited to development; test and production require an explicit key.
    DATABASE_URL: config.DATABASE_URL ?? 'postgres://nova_local:nova-local-only-change-me@localhost:5432/nova',
    RATE_LIMIT_HMAC_KEY: config.RATE_LIMIT_HMAC_KEY ?? 'nova-local-development-rate-limit-hmac-key',
  };
}
