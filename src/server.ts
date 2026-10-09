import './env.js';
import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { closePool } from './db.js';

const config = loadConfig();
const app = await buildApp({ config });

try {
  await app.listen({ host: config.HOST, port: config.PORT });
  app.log.info({ host: config.HOST, port: config.PORT }, 'NOVA API listening');
} catch (error) {
  app.log.error({ err: error }, 'Server startup failed');
  await app.close();
  await closePool();
  process.exitCode = 1;
}

const shutdown = async (signal: string) => {
  app.log.info({ signal }, 'Graceful shutdown started');
  await app.close();
  await closePool();
};
process.once('SIGINT', () => { void shutdown('SIGINT'); });
process.once('SIGTERM', () => { void shutdown('SIGTERM'); });
