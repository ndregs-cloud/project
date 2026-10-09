import './env.js';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { loadConfig } from './config.js';
import { assertLocalMigrationTarget } from './migration-safety.js';
import { pool, closePool } from './db.js';

const config = loadConfig();
assertLocalMigrationTarget(config.DATABASE_URL, config.NODE_ENV);

const migrations = [
  { version: '001_initial_schema', path: resolve(process.cwd(), 'migrations/001_initial_schema.sql') },
  { version: '002_media_key_revocations', path: resolve(process.cwd(), 'migrations/002_media_key_revocations.sql') },
  { version: '003_removal_pending', path: resolve(process.cwd(), 'migrations/003_removal_pending.sql') },
];
const client = await pool.connect();
try {
  await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
  )`);
  await client.query('BEGIN');
  await client.query('SELECT pg_advisory_xact_lock($1)', [726190421]);
  for (const migration of migrations) {
    const existing = await client.query('SELECT 1 FROM schema_migrations WHERE version=$1', [migration.version]);
    if (existing.rowCount) {
      console.info(`Migration ${migration.version} already applied`);
      continue;
    }
    const sql = await readFile(migration.path, 'utf8');
    await client.query(sql);
    await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [migration.version]);
    console.info(`Applied ${migration.version}`);
  }
  await client.query('COMMIT');
} catch (error) {
  await client.query('ROLLBACK').catch(() => undefined);
  console.error('Migration failed:', error instanceof Error ? error.message : 'unknown error');
  process.exitCode = 1;
} finally {
  client.release();
  await closePool();
}
