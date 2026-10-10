# NOVA Beta Operations Runbook

## Pre-beta launch gate

- The development preview has a read-only backend connection for Discover/Story/cover. Write/Publish/account/feedback/reports remain disconnected or local; there is no real feedback/report intake, staff receipt, or status lookup there. Use only clearly labeled fictional data; do not accept real reports or feedback through the preview.
- Keep beta intake closed until the authenticated frontend/backend flows and the access-control, privacy, screenshot, and escalation checks pass in staging with least-privilege fictional accounts.
- Do not treat API route availability or a passing unit test alone as approval to open beta. Record staging results and request IDs in `SECURITY_STAGING_CHECKLIST.md`.

## Security review status before staging

**Current posture:** The static backend review and subsequent dependency audit identified eleven items tracked as blocking gates in `SECURITY_STAGING_CHECKLIST.md`. The review is not evidence that any item was exploited in a running environment; do not declare an incident solely from these code findings. Beta remains closed, and no staging approval is implied by local retests.

- The startup validator requires the identity bootstrap and rate-limit helpers plus a public moderation runtime contract (`nova_moderate_hide_story`, versioned `nova_moderate_restore_story`, `nova_enqueue_media_key_revocation`, both actor predicates, the row-bound four-argument media-revocation worker predicate, and forced-RLS `public.media_no_media_required`). It pins ten exact SECURITY DEFINER body fingerprints and each helper's `prolang` and `provolatile`, including actor helpers and the worker predicate; it also verifies NOLOGIN owner/attributes, fixed `search_path`, exact EXECUTE ACLs, narrowly allowed schema/column privileges, and the queue's exact worker SELECT/UPDATE RLS policy set and expressions. The canonical migrations in this worktree do not install this contract; a disposable fixture mirrors it only for local tests. No production migration or least-privilege role/grant plan is approved or added here. Keep production startup fail-closed until that plan is approved, reviewed, and deployed; a test-only schema is not a substitute.

- Keep an owner and status on every finding. Close only after the corresponding staging check passes and its safe evidence/request ID is recorded.
- When suspension is integrated, verify direct Story links return a neutral `404`, the Story disappears from feeds, author search and bookmarks, comments are hidden/rejected, and a previously fetched API cover URL no longer returns bytes unless the same asset is still referenced by another eligible public Story. The integrated UI must hide actions, remove stale saved/comment/clap cache and show only `Story unavailable` without a suspension reason. At present, `suspend_user` and related unsupported writes fail closed with `501 NOT_INTEGRATED`; do not treat those acceptance checks as implemented behavior.
- Hide/restore, key rotation, queue insertion, and attempt-five behavior have disposable-fixture E2E/design evidence only. They are not production capabilities: canonical migrations do not install the required public moderation helpers/table and production startup must fail closed. Local tests use fake storage; no production copy/delete, revocation, purge verification, or finalizer is established. No authoritative full-purge verifier or application finalizer/resolution path exists; the production escalation owner, response target, and alert route remain unassigned. Do not mark a removal verified or a case `Action taken`/`Closed` from local tests or a successful storage `DELETE`. Before SEC-3 can close, provision an isolated staging target, approve/deploy the runtime contract, assign operations ownership and response target, provide an authorized finalization path, and verify alert routing.
- A lost moderation `COMMIT` acknowledgement is resolved only by a fresh, separately credentialed worker-pool read proving the exact action/media/outbox association. If confirmed, the route may return its committed pending response; if absent or unreadable, it returns neutral `503 TRANSACTION_OUTCOME_UNCONFIRMED`, preserves the copied destination, and requires a refresh before retry. This fallback creates no durable reconciliation record, automatic retry, or alert; if the warning is not retained and triaged, an orphan copy may persist indefinitely and there is no restart-resumable work item. The production reconciliation owner and response target remain unassigned. Never infer success, rollback, cleanup, or verified purge from an ambiguous response.
- Owner publish, unpublish, and delete are unavailable for this MVP and return `501 NOT_INTEGRATED` before Story lookup/mutation with an explicit no-change message. Do not direct creators to retry those unavailable transitions. That guarantee applies only to the known 501 response. For any ambiguous `5xx`, do not claim no changes or retry blindly; reread the Story and reconcile its current state first. Client responses must never expose raw PostgreSQL SQLSTATEs or database details.
- Cover responses must include `Cache-Control: private, no-store`, `CDN-Cache-Control: no-store`, and `Surrogate-Control: no-store`. Configure the CDN/reverse proxy to bypass cache for this route, then test both cold and warm-cache requests after takedown/suspension; never accept a stale cached `200` for the target Story.
- Any legacy signed-URL revocation, provider delete, cache invalidation, and transfer residual are unverified; no production signed-upload URL is issued by the active routes. Treat TTL ranges in code as configuration, not evidence of deployed behavior. A previously issued URL's exact expiry would need to be read from that URL and its issuance settings.
- Only after an approved runtime contract and isolated staging scope exist, test an exact legacy S3 presigned cover URL, origin/cache behavior, provider copy/read/delete/HEAD permissions, injected delete failures, attempt-five escalation, shared-cover behavior, and alert routing. The current `202`/pending/attempt-five observations come from disposable fake-storage tests, not staging. There is no application finalizer/resolution path; do not close SEC-3 or open beta without the authorized retest and a verified resolution process.
- Run Compose only with development-local credentials from `.env`; PostgreSQL and MinIO host ports must remain bound to `127.0.0.1`. Never reuse sample credentials in staging or production.
- After upgrading to Vitest 5.0.3, the current full and runtime-only dependency audits both report 0 vulnerabilities locally. GitHub Actions gates each run with `npm audit --audit-level=low` after `npm ci --no-audit`, covering the full lockfile including dev dependencies. Keep SEC-9 open until this CI gate passes and dependency verification is recorded for staging; see `SECURITY_STAGING_CHECKLIST.md`.

## Story transition API unavailable

1. Publish, unpublish, and delete are not integrated; each currently returns `501 NOT_INTEGRATED` before a Story lookup or mutation. The exact 501 response guarantees no changes were made.
2. The frontend “Publish locally” action stores only in this browser's demo library; it is not published to NOVA or shared with readers.
3. For any other or ambiguous `5xx`, do not claim rollback or no change. Refresh the Story and reconcile its persisted state before considering another action.
4. Do not loosen RLS or grant direct status updates to make these flows work. Re-enable a transition only after a narrow runtime helper and an approved, reviewed deployment contract are in place.
5. `Preview` remains read-only. Do not collect access tokens, passwords, private Story text, or screenshots automatically when recording failures.

## Local mutation contract and release gate

- Use [`ROUTE_SECURITY_INVENTORY.md`](./ROUTE_SECURITY_INVENTORY.md) for the audited method/path matrix, local RLS evidence, and named tests. “Locally tested” means the disposable PostgreSQL fixture only; it is not production availability or staging approval.
- Comment creation and all `DELETE /api/v1/comments/:id` requests return `501 NOT_INTEGRATED` before Story/comment lookup; public comment reads remain available. No author or moderator comment soft-delete is active. The `remove_comment` moderation action also returns `501` until a narrow approved helper exists.
- Assigning a non-null Story cover and attaching a feedback screenshot return `501` before Story/media lookup or case insert. Upload-intent and completion are unavailable; no upload URL or provider operation is performed by these routes.
- Profile/avatar, Story text/tag, follow/bookmark, report intake, feedback without screenshot, and security reports have runtime-role E2E coverage only against the disposable fixture. Comment deletion is explicitly unavailable. Production availability is not established while the production startup contract remains missing.
- `registerAuth()` installs the shared auth `preHandler` before route plugins. The `preHandler` calls `authenticateToken()`/`resolveIdentity()` for `authRequired` routes and for `authOptional` routes carrying a Bearer token; a verified first-time subject may be provisioned via the identity-bootstrap SECURITY DEFINER helper before the route handler. Fastify `onSend` invokes `commitRequestTransaction()`, thrown request errors are rolled back by `onError`, and `onResponse` provides defensive/fallback rollback cleanup for aborted or short-circuited responses. The `onSend` commit hook is not a generic HTTP-status-code gate. `GET /api/v1/me` is the PG17 E2E example, not the exclusive trigger. Bootstrap query errors/timeouts roll back and map to neutral `503 IDENTITY_UNAVAILABLE`; the PG17 test verifies timeout/no partial user.
- Every explicitly unintegrated `501` branch guarantees no domain or storage-provider mutation; authentication/rate-limit middleware can still run. For ambiguous non-`501` `5xx` responses, do not claim rollback/no change; re-read persisted state before retrying. Never expose SQLSTATE/database details.

## Media upload writes unavailable

- Upload-intent creation and completion return `501 NOT_INTEGRATED` before media-domain database reads/writes, upload URL signing, file validation, or storage/provider calls. Feedback screenshot attachment and new Story cover assignment are also `501`. Authentication and rate limiting still apply. The media read-proxy code path is locally fixture-tested only; production/provider behavior is not established.
- Do not describe this as `422` rejection, claim a media row was marked `rejected`/`ready`, or ask a user to retry an unavailable completion. Existing pending media rows remain unchanged.
- Re-enable upload writes only after the nonce-bound helper/trusted-verifier gateway is integrated, its narrow RLS contract is present in an approved canonical migration, and disposable PostgreSQL E2E verifies that all write paths and rollback/cancel behavior stay within that contract. The suggested 422 copy and new-intent recovery rule are future behavior, not the current API contract.

## Content and safety reports

1. Keep content reports in the moderator queue; assign one reviewer using a dedicated `moderator` account.
2. Open report evidence only when needed. Access is restricted to moderators and each staff read/status change is audited. Do not copy report details into broad chat, ordinary email, or public analytics.
3. Review the reported Story/profile/comment under the applicable policy. Record the decision and a short rationale in the staff action/audit trail.
4. Keep reporter-visible workflow status separate from media removal status. Show “Removal pending — cleanup could not be confirmed” only while the persisted removal flag is pending. Never replace `Under review` with a false completed status. Do not disclose enforcement against another account, promise a deadline, or imply appeals are available unless policy explicitly supports them.
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

For cover removal escalation, monitor the durable outbox, including terminal rows. At `attempt_count=5` with `escalated_at` set, no further automatic retry occurs; the row remains pending until an authorized finalization path resolves it. This query returns identifiers and retry metadata only:

```sql
SELECT a.target_type, a.target_id, COUNT(*) AS pending_keys,
       MAX(r.attempt_count) AS max_attempts, MIN(r.created_at) AS oldest_pending,
       MAX(r.escalated_at) AS escalated_at
FROM media_key_revocations r
LEFT JOIN moderation_actions a ON a.id = r.moderation_action_id
GROUP BY a.target_type, a.target_id
ORDER BY oldest_pending;
```

Route the attempt-five error log to an operations alert system once one is configured. `escalated_at` records a terminal escalation state but does not prove a page/contact was sent. There is no application-level finalizer/resolution path yet, so do not treat a storage-delete success or log event as verified purge, manually remove the queue row, or mark a linked report `Action taken`/`Closed`. Production escalation owner and response target remain unassigned and block closure; resolve only after an authorized finalizer records verified full purge, removes the queue row, and updates any linked case consistently.

## Rollback copy cleanup failures

- When moderation copies a cover and a transaction is definitely aborted, the request attempts a best-effort delete of that destination after rollback. If that delete also fails, an internal structured `media_revocation_copy_compensation_failed` warning records action/media IDs, `destinationKeyPresent=true`, error type, and `reconciliationRequired=true`; it does not record the destination key or a destination identifier.
- Destructive compensation after `COMMIT` is allowed only for the explicit PostgreSQL SQLSTATE abort allowlist. Any other result—including `58030`—is unconfirmed: first attempt a fresh-state confirmation; if it remains unresolved, preserve the destination copy, return neutral `503 TRANSACTION_OUTCOME_UNCONFIRMED`, and require the client to refresh authoritative Story/report state before retrying. Do not claim rollback, no change, or cleanup in this case.
- This warning is log-only: it is not a durable orphan-reconciliation record, queue entry, page, or contact. There is no automatic retry or restart-resumable record; if the warning is not retained and triaged, an orphaned copy can remain indefinitely. No alert is sent by this code, and no production response owner, response target, or alert route is configured. Treat cleanup as unresolved—not verified or closed—until an approved durable reconciliation/alert path and accountable owner are established; none is invented or implemented here.
- The failure response is neutral and requires refreshing the current Story and report state before retry. It must not expose the destination key/provider details or claim that no changes, cleanup, purge, or escalation notification occurred. Report workflow stays open; show “Removal pending — cleanup could not be confirmed” only when the persisted removal flag is actually pending.
- Investigate the structured log through approved restricted operations access. Do not copy destination keys into reporter-visible notes, manually close the report, or mark media verified. If the database outcome is ambiguous, query persisted Story/report/outbox state before taking another action.

## Retention and staging

- Beta feedback: 90 days by default (`FEEDBACK_RETENTION_DAYS`).
- Security/privacy reports: 180 days by default (`SECURITY_REPORT_RETENTION_DAYS`).
- Staff access audit metadata: 365 days.
- Run `npm run cleanup:feedback` at least daily. It deletes expired records and private screenshot objects; investigate storage failures before manually deleting database records.
- Staging must use fictional accounts/content, least-privilege roles, no production credentials, and `NOINDEX=true`. Follow [SECURITY_STAGING_CHECKLIST.md](./SECURITY_STAGING_CHECKLIST.md) and retain only pass/fail, actor role, and request IDs as evidence.
