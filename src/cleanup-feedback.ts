import { pool, closePool } from './db.js';
import { loadConfig } from './config.js';
import { MediaStorage } from './storage/s3.js';

const config = loadConfig();
const mediaStorage = new MediaStorage(config);

async function run(): Promise<void> {
  const mediaToDelete = await pool.query<{ id: string; objectKey: string }>(
    `SELECT m.id,m.object_key AS "objectKey" FROM media_assets m
     WHERE (
       m.purpose='feedback_screenshot' AND (
         EXISTS (SELECT 1 FROM beta_feedback f WHERE f.screenshot_media_id=m.id AND f.expires_at<=now())
         OR (m.created_at<now()-interval '1 day' AND NOT EXISTS (
           SELECT 1 FROM beta_feedback f WHERE f.screenshot_media_id=m.id AND f.expires_at>now()
         ))
       )
     ) OR (
       m.status IN ('pending','processing','rejected') AND m.created_at<now()-interval '1 day'
       AND NOT EXISTS (SELECT 1 FROM users u WHERE u.avatar_media_id=m.id)
       AND NOT EXISTS (SELECT 1 FROM stories s WHERE s.cover_media_id=m.id)
     ) ORDER BY m.created_at LIMIT 500`,
  );

  // Delete private objects before database references; failed storage deletion leaves rows for a safe retry.
  for (const row of mediaToDelete.rows) await mediaStorage.deleteObject(row.objectKey);

  const client = await pool.connect();
  const mediaIds = mediaToDelete.rows.map((row) => row.id);
  let feedbackDeleted = 0;
  let securityReportsDeleted = 0;
  let auditRowsDeleted = 0;
  try {
    await client.query('BEGIN');
    const feedback = await client.query('DELETE FROM beta_feedback WHERE expires_at<=now()');
    feedbackDeleted = feedback.rowCount ?? 0;
    const security = await client.query('DELETE FROM security_reports WHERE expires_at<=now()');
    securityReportsDeleted = security.rowCount ?? 0;
    if (mediaIds.length) await client.query('DELETE FROM media_assets WHERE id=ANY($1::uuid[])', [mediaIds]);
    await client.query(
      `UPDATE media_assets SET status='pending',updated_at=now()
       WHERE status='processing' AND updated_at<now()-interval '15 minutes'`,
    );
    const audit = await client.query('DELETE FROM staff_access_audit WHERE expires_at<=now()');
    auditRowsDeleted = audit.rowCount ?? 0;
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  console.info(JSON.stringify({
    event: 'private_report_retention_cleanup',
    expiredFeedbackDeleted: feedbackDeleted,
    expiredSecurityReportsDeleted: securityReportsDeleted,
    screenshotsDeleted: mediaToDelete.rowCount ?? 0,
    expiredStaffAuditRowsDeleted: auditRowsDeleted,
  }));
}

try {
  await run();
} catch {
  console.error('Private report retention cleanup failed; inspect restricted operations logs.');
  process.exitCode = 1;
} finally {
  await mediaStorage.close();
  await closePool();
}
