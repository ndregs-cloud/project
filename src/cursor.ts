import { Buffer } from 'node:buffer';
import { z } from 'zod';
import { AppError } from './errors.js';

const cursorSchema = z.object({
  createdAt: z.string().datetime({ offset: true }),
  id: z.string().uuid(),
});

export interface CursorPosition {
  createdAt: string;
  id: string;
}

export function encodeCursor(position: CursorPosition): string {
  return Buffer.from(JSON.stringify(position), 'utf8').toString('base64url');
}

export function decodeCursor(value: string | undefined): CursorPosition | null {
  if (value === undefined) return null;
  if (value.length > 512) throw new AppError(400, 'INVALID_CURSOR', 'Cursor tidak valid.');
  try {
    const parsed: unknown = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
    const result = cursorSchema.safeParse(parsed);
    if (!result.success) throw new Error('Invalid cursor shape');
    return result.data;
  } catch {
    throw new AppError(400, 'INVALID_CURSOR', 'Cursor tidak valid.');
  }
}
