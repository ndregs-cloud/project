import { randomBytes } from 'node:crypto';

// A test-only ephemeral pepper. Never inherit or log a production/Supabase value.
if (process.env.NODE_ENV === 'test') {
  process.env.RATE_LIMIT_HMAC_KEY = randomBytes(32).toString('hex');
}
