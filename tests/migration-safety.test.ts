import { describe, expect, it } from 'vitest';
import { assertLocalMigrationTarget } from '../src/migration-safety.js';

describe('assertLocalMigrationTarget', () => {
  it('allows disposable loopback PostgreSQL in development and test', () => {
    expect(() => assertLocalMigrationTarget('postgres://user:password@localhost:5432/nova', 'development')).not.toThrow();
    expect(() => assertLocalMigrationTarget('postgresql://user:password@127.0.0.1:5432/nova_test', 'test')).not.toThrow();
  });

  it('rejects a remote host even in development', () => {
    expect(() => assertLocalMigrationTarget('postgresql://user:password@db.example.supabase.co:5432/postgres', 'development'))
      .toThrow(/loopback PostgreSQL/);
  });

  it('rejects loopback URLs outside development and test', () => {
    expect(() => assertLocalMigrationTarget('postgres://user:password@localhost:5432/nova', 'production'))
      .toThrow(/local-only/);
    expect(() => assertLocalMigrationTarget('postgres://user:password@localhost:5432/nova', undefined))
      .toThrow(/local-only/);
  });

  it('rejects invalid and non-PostgreSQL URLs', () => {
    expect(() => assertLocalMigrationTarget('not-a-url', 'test')).toThrow(/valid local PostgreSQL URL/);
    expect(() => assertLocalMigrationTarget('https://localhost/nova', 'test')).toThrow(/loopback PostgreSQL/);
  });
});
