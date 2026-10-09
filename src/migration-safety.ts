const LOCAL_POSTGRES_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

export function assertLocalMigrationTarget(databaseUrl: string, nodeEnv: string | undefined): void {
  if (nodeEnv !== 'development' && nodeEnv !== 'test') {
    throw new Error(
      'The custom migration runner is local-only. Use NODE_ENV=development or test with disposable local PostgreSQL; use Supabase CLI for Supabase projects.',
    );
  }

  let target: URL;
  try {
    target = new URL(databaseUrl);
  } catch {
    throw new Error('The custom migration runner requires a valid local PostgreSQL URL.');
  }

  if (
    (target.protocol !== 'postgres:' && target.protocol !== 'postgresql:') ||
    !LOCAL_POSTGRES_HOSTS.has(target.hostname.toLowerCase())
  ) {
    throw new Error(
      'The custom migration runner is restricted to loopback PostgreSQL. Use Supabase CLI for Supabase projects.',
    );
  }
}
