# NOVA Beta Operations Runbook

## Pre-beta launch gate

- The development preview has a read-only backend connection for Discover/Story/cover. Write/Publish/account/feedback/reports remain disconnected or local; there is no real feedback/report intake, staff receipt, or status lookup there. Use only clearly labeled fictional data; do not accept real reports or feedback through the preview.
- Keep beta intake closed until the authenticated frontend/backend flows and the access-control, privacy, screenshot, and escalation checks pass in staging with least-privilege fictional accounts.
- Do not treat API route availability or a passing unit test alone as approval to open beta. Record staging results and request IDs in `SECURITY_STAGING_CHECKLIST.md`.

## Security review status before staging

**Current posture:** The static backend review and subsequent dependency audit identified nine items tracked as blocking gates in `SECURITY_STAGING_CHECKLIST.md`. The review is not evidence that any item was exploited in a running environment; do not declare an incident solely from these code findings. Beta remains closed, and no staging approval is implied by local retests.

- Keep an owner and status on every finding. Close only after the corresponding staging check passes and its safe evidence/request ID is recorded.
- For a suspended creator, verify direct Story links return a neutral `404`, the Story disappears from feeds, author search and bookmarks, comments are hidden/rejected, and a previously fetched API cover URL no longer returns bytes unless the same asset is still referenced by another eligible public Story. The integrated UI must hide actions, remove stale saved/comment/clap cache and show only `Story unavailable` without a suspension reason.
- Cover reads stream through `GET /api/v1/media/:id`; every origin request rechecks current Story and creator eligibility. The `hide_story`/`suspend_user` transaction copies affected covers to unique keys, switches DB pointers and records old keys in a durable outbox. If copying fails, the moderation transaction rolls back. If deletion or the following origin `HEAD` verification fails, the action is committed and returns `202` with `removal.status=pending`; never interpret it as a completed revocation. The report stays open with `removalPending=true` and `Removal pending`, and staff cannot action/close it until verified. The first retry is after 5 seconds, then backs off to a 5-minute cap; from the third failure onward, every retry emits an `error`-level escalation log and `escalated_at` remains recorded until cleanup. On successful verification, a matching info log states that escalation may be resolved. This repository does not configure a paging/log-alert destination. The owner chose to keep provider/CDN checks local-only for now; no R2 account, bucket, or test domain has been created, and no staging S3/CDN hostname, paging owner, or internal response target has been provided or approved. Do not test a real provider/CDN; before SEC-3 can close, provision an isolated staging target, confirm the test scope, assign an operations owner and response target, and verify alert routing. Keep the case open until origin absence is confirmed. A restored Story uses the new key.
- Cover responses must include `Cache-Control: private, no-store`, `CDN-Cache-Control: no-store`, and `Surrogate-Control: no-store`. Configure the CDN/reverse proxy to bypass cache for this route, then test both cold and warm-cache requests after takedown/suspension; never accept a stale cached `200` for the target Story.
- While deletion is pending, the legacy signed URL is not revoked: it can access the old key until deletion is verified or its original signature expires. The current code permits signed URL TTLs from 60 to 900 seconds (default 300); use the exact embedded expiry for each tested URL. A warmed CDN/browser cache, in-progress transfer, or downloaded image can outlive origin denial; record these residuals separately and do not claim a deployment-wide maximum until the real staging path is measured.
- During rollout, test an exact legacy S3 presigned cover URL issued before the proxy change after both actions; verify origin behavior and the same URL through any CDN/cache layer. Inject storage-delete and HEAD-verification failures: confirm `202` plus pending case state, durable retries, recurring error-level escalation after the third failed attempt, and transition to `Action taken` only after verification. Test a cover shared with a second still-public Story; takedown of one Story must not break the other, and the report remains pending until legacy-key revocation is verified. Verify staging copy/read/delete/HEAD permissions, provider behavior, and log-alert routing. Do not close SEC-3 or open beta before the integrated retest; see `SECURITY_STAGING_CHECKLIST.md`.
- Run Compose only with development-local credentials from `.env`; PostgreSQL and MinIO host ports must remain bound to `127.0.0.1`. Never reuse sample credentials in staging or production.
- After upgrading to Vitest 5.0.3, the current full and runtime-only dependency audits both report 0 vulnerabilities locally. GitHub Actions gates each run with `npm audit --audit-level=low` after `npm ci --no-audit`, covering the full lockfile including dev dependencies. Keep SEC-9 open until this CI gate passes and dependency verification is recorded for staging; see `SECURITY_STAGING_CHECKLIST.md`.

## Publish failures

1. Do not tell the creator the Story is published unless the API confirms success.
2. Check the creator's Draft is still present through the authenticated owner-only Draft view; a failed publish must not discard or overwrite it.
3. Record the approximate time and timezone, safe error/request ID, endpoint, and whether the failure repeats. Do not collect access tokens, passwords, private Story text, or screenshots automatically.
4. For a one-off transient failure, ask the creator to retry from the retained Draft. Escalate repeated failures to engineering with request IDs and redacted server logs; do not promise an ETA.
5. Verify that publishing was performed by the Draft owner and only by the explicit Publish action. `Preview` is read-only.

## Content and safety reports

1. Keep content reports in the moderator queue; assign one reviewer using a dedicated `moderator` account.
2. Open report evidence only when needed. Access is restricted to moderators and each staff read/status change is audited. Do not copy report details into broad chat, ordinary email, or public analytics.
3. Review the reported Story/profile/comment under the applicable policy. Record the decision and a short rationale in the staff action/audit trail.
4. Update the report to the safest shareable status: `Under review`, `Action taken`, `No violation found`, or `Closed`. Do not disclose enforcement against another account, promise a deadline, or imply appeals are available unless policy explicitly supports them.
5. Reopen only when an authorized reviewer determines more review is needed. Record the state transition; aggregate reopened counts are available to moderators.

## Security and privacy reports

1. Use the separate Security/Privacy queue; do not copy details to the content-report queue or ordinary email.
2. Assign a security reviewer using a dedicated `security` role. Restrict evidence to need-to-know staff; the inbox, detail reads, and status changes are audited.
3. Avoid requesting secrets. If a report includes a password, token, or key, do not repeat it in notes or notifications; follow the incident response process to revoke/rotate it.
4. Record a concise decision and safe status. Notify only that an update is available and direct the reporter to sign in; never send sensitive report details through ordinary email.

## Data access/deletion requests

1. Verify the requester's identity through the established account/IdP process and route the request to the designated privacy owner.
2. Do not read, export, modify, or delete account data based only on an unverified message or a claimed identity. Do not use the beta feedback or content-report workflow as a substitute for privacy-request handling.
3. The privacy owner documents the verified scope, decision, and completion under the applicable policy. Keep evidence minimal and access-controlled.

## Operational measures

Use only the role-restricted aggregate endpoints; never export raw report text to analytics:

- Moderators: `GET /api/v1/moderation/reports/metrics?days=30`
- Support: `GET /api/v1/internal/feedback/metrics?days=30`
- Security: `GET /api/v1/internal/security-reports/metrics?days=30`

Track category volume, average time from submission to first staff status response, recurring cases (staff-assigned recurrence keys or repeated report targets), and reopened counts. These are operational measures, not public/community analytics. Do not turn first-response metrics into a user-facing deadline unless an approved service policy defines one.

For cover removal escalation, monitor the durable outbox until each row disappears after origin verification. This query returns identifiers and retry metadata only:

```sql
SELECT a.target_type, a.target_id, COUNT(*) AS pending_keys,
       MAX(r.attempt_count) AS max_attempts, MIN(r.created_at) AS oldest_pending,
       MAX(r.escalated_at) AS escalated_at
FROM media_key_revocations r
LEFT JOIN moderation_actions a ON a.id = r.moderation_action_id
GROUP BY a.target_type, a.target_id
ORDER BY oldest_pending;
```

Route recurring error logs to the operations alert system. Resolve an alert only after the corresponding `Cover-key revocation verified; escalation may be resolved.` info event and the pending outbox row is gone; if a case is linked, confirm its reporter status is no longer `Removal pending`.

## Retention and staging

- Beta feedback: 90 days by default (`FEEDBACK_RETENTION_DAYS`).
- Security/privacy reports: 180 days by default (`SECURITY_REPORT_RETENTION_DAYS`).
- Staff access audit metadata: 365 days.
- Run `npm run cleanup:feedback` at least daily. It deletes expired records and private screenshot objects; investigate storage failures before manually deleting database records.
- Staging must use fictional accounts/content, least-privilege roles, no production credentials, and `NOINDEX=true`. Follow [SECURITY_STAGING_CHECKLIST.md](./SECURITY_STAGING_CHECKLIST.md) and retain only pass/fail, actor role, and request IDs as evidence.
