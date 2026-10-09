import 'fastify';

export interface AuthUser {
  id: string;
  subject: string;
  username: string;
  role: 'reader' | 'moderator' | 'support' | 'security' | 'admin';
}

declare module 'fastify' {
  interface FastifyRequest {
    user: AuthUser | null;
  }
  interface FastifyContextConfig {
    authRequired?: boolean;
    authOptional?: boolean;
  }
}
