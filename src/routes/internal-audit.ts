import type { FastifyInstance } from 'fastify';

export type StaffAuditEvent =
  | 'content_report.read' | 'content_report.status_changed'
  | 'feedback.read' | 'feedback.screenshot_read' | 'feedback.status_changed' | 'feedback.metrics_read'
  | 'security_report.read' | 'security_report.status_changed' | 'security_report.metrics_read'
  | 'moderation_reports.metrics_read';

export async function auditStaffAccess(
  app: FastifyInstance,
  staffId: string,
  eventType: StaffAuditEvent,
  resourceId: string | null,
  metadata: Record<string, unknown> = {},
): Promise<void> {
  await app.pg.query(
    `INSERT INTO staff_access_audit (staff_id, event_type, resource_id, metadata)
     VALUES ($1, $2, $3, $4::jsonb)`,
    [staffId, eventType, resourceId, JSON.stringify(metadata)],
  );
}

export async function auditStaffAccessMany(
  app: FastifyInstance,
  staffId: string,
  eventType: StaffAuditEvent,
  resourceIds: string[],
): Promise<void> {
  if (resourceIds.length === 0) return;
  await app.pg.query(
    `INSERT INTO staff_access_audit (staff_id, event_type, resource_id)
     SELECT $1, $2, ids.resource_id FROM unnest($3::uuid[]) AS ids(resource_id)`,
    [staffId, eventType, resourceIds],
  );
}
