# NOVA Staging Security Checklist

**Use only fictional test accounts and data.** Do not store access tokens, cookies, report text, private Story content, screenshots, secrets, or other sensitive request/response bodies in evidence. Record only the test name, pass/fail, actor role, timestamp, and `X-Request-Id` (or `not-issued` when a browser blocks the request before it reaches the API).

**Current launch status: beta intake must remain closed.** The development preview has a read-only backend connection for Discover/Story/cover; Write/Publish/account/feedback/reports remain disconnected or local. Do not accept real reports or feedback. Open beta only after authenticated flows and staging access, privacy, screenshot, and escalation checks pass with fictional, least-privilege accounts.

The authorization matrix is automated in `tests/authorization.integration.test.ts` and runs in CI against disposable PostgreSQL. The table below is the deployment/staging record; do not mark a row passed solely because the test source exists.

Latest local retest (2026-10-08), using Vitest 5.0.3 and a fresh disposable PostgreSQL database, passed **19/19 tests** (14 unit/API/storage and 5 PostgreSQL integration) and **83/83 request-level checks**. The ordinary `npm test` run is **14 passed / 5 skipped** unless PostgreSQL integration is enabled. Minimal evidence is generated at the git-ignored `artifacts/security-matrix.json`. The local S3 HTTP emulator verifies a signed origin URL remains usable after an ineffective delete and fails only after origin absence is verified. Real S3-compatible provider behavior, frontend/CDN/browser caches, warmed-cache invalidation, and external log-alert routing remain unverified. The owner chose to leave these checks `Not run`; no R2 account, bucket, or test domain was created. No staging S3/CDN hostname or paging owner/response target has been provided or approved; do not test real services until an isolated scope and owners are confirmed. This is **not** staging sign-off, so beta stays closed.

## Static-review findings — blocking before staging

Do not close any item from code changes alone. Each item stays `Open — staging retest required` until its named owner records staging evidence and request IDs below.

| ID and finding | Owner | Status | Local retest evidence (not staging sign-off) |
|---|---|---|---|
| SEC-1 — Require HTTPS for configured JWKS and S3 endpoints in production, including when `NODE_ENV` is omitted | Backend / Platform | Open — staging config retest required | Local unit tests verify omitted `NODE_ENV` defaults to production and production rejects HTTP JWKS/S3 endpoints. Verify actual staging values without recording secrets. |
| SEC-2 — Reject access tokens without numeric `exp` | Identity / Backend | Open — staging IdP retest required | `artifacts/security-matrix.json`, `token_without_exp_rejected` PASS, request `req_453d8ba7f0fc4c339398d73da4ab89bf`; the mock JWKS integration is not a real IdP test. |
| SEC-3 — Revoke suspended/taken-down Stories across feed/search, bookmarks, comments, cover URLs, and UI/cache | Backend + UX/Frontend + Operations | Open — integrated staging retest required | Local PostgreSQL tests cover `202` pending results, reporter/moderator visibility, premature-close rejection, three-failure escalation, owner API denial, shared-Story continuity, and case completion after delete plus origin `HEAD` verification. Local evidence is not staging. Real S3-compatible behavior, frontend caches, CDN invalidation, warmed legacy URLs, and external log-alert routing remain unverified. Do not close until integrated staging records origin/cache results and confirms alert routing. |
| SEC-4 — Apply IP rate limiting before auth rejects missing tokens | Backend / Platform | Open — staging load/config retest required | `tests/unit.test.ts`, `applies the IP rate limit before rejecting a request without a token`, PASS; `npm test` passed. This in-process fake-pool test has no HTTP request ID. |
| SEC-5 — Bind Compose ports to loopback and source local credentials from `.env` | Platform / DevEx | Open — staging/local deployment config retest required | `compose.yaml` now binds PostgreSQL and MinIO to `127.0.0.1`; credentials are required from local environment variables and the example values are marked development-only. Docker Compose execution was unavailable during this retest. |
| SEC-6 — Fail closed when `NODE_ENV` is omitted instead of silently enabling development guards | Backend / Platform | Open — staging config retest required | Verify deployed environment explicitly and confirm production HTTPS guards remain active; local tests do not constitute staging evidence. |
| SEC-7 — Require an explicit production `DATABASE_URL`; never use local fallback credentials in production | Backend / Platform | Open — staging config retest required | Verify the deployed secret is present without recording its value; local tests do not constitute staging evidence. |
| SEC-8 — Upgrade Sharp to patched 0.35.5 and reject upload size/type/allowlist failures before Sharp parsing | Backend | Open — staging upload retest required | Local tests pass for reject-before-parse size/MIME/signature cases and successful JPEG/PNG/WebP normalization; `sharp` resolves to 0.35.5 and `npm audit --omit=dev` reports 0 vulnerabilities. Verify actual uploads against staging S3 separately. |
| SEC-9 — Resolve vulnerable test dependencies found by full npm audit (`@vitest/mocker`, `tinypool`) | Backend / DevEx | Open — staging dependency verification required | After upgrading to Vitest 5.0.3, full `npm audit` and `npm audit --omit=dev` both report 0 vulnerabilities in the current lockfile. GitHub Actions now gates each run with `npm audit --audit-level=low` on the full lockfile after `npm ci --no-audit`, including dev dependencies. Keep this item open until the gate passes in CI and dependency verification is recorded for staging. |

| Check | Expected result | Result | Actor role | Request ID | Timestamp |
|---|---|---|---|---|---|
| Frontend write/intake flows | Write/Publish remain local-only/private; no persisted `Public` indicator and no real feedback/report intake | Not run | — | — | — |
| Stories-only MVP scope | No Book sample/model/endpoint is represented as a supported Story feature | Not run | — | — | — |
| Anonymous reads a private Draft | `404`; no Draft content | Not run | — | — | — |
| Different account reads a private Draft | `404`; no Draft content | Not run | reader | — | — |
| Different account edits/publishes a Draft | `404`; state unchanged | Not run | reader | — | — |
| Draft owner reads and publishes own Draft | Owner can read; only explicit Publish makes it public | Not run | reader/owner | — | — |
| Persisted Publish and unpublish | Owner receives `published/public/publishedAt` only after commit; anonymous read succeeds only then and returns `404` after unpublish | Not run | owner/anonymous | — | — |
| Suspended creator Story in feed/search/bookmarks | Story link returns `404` with no suspension reason; feed and author search omit it; existing bookmark is absent and new bookmark returns `404` | Not run | anonymous/reader | — | — |
| Reuse previously fetched API cover URL after `hide_story` | The same `GET /api/v1/media/:id` URL returns `404` for the taken-down Story, including for its owner, unless the asset is still legitimately referenced by another eligible public Story | Not run | anonymous/owner | — | — |
| Removal-pending case and alert path | Inject delete and origin-HEAD verification failures; action returns `202` with `removal.status=pending`, reporter and moderator see `Removal pending`, the report stays open, premature action/close is rejected, retries continue, and recurring error-level logs after three failures reach the configured operations alert route. Resolve the alert only on the matching info log emitted after verified origin absence; only then clear pending and mark the report `Action taken`. | Not run | moderator/reporter/operations | — | — |
| Shared cover used by another public Story | Take down or suspend one Story owner while another active creator's public Story references the same media; target Story is unavailable but the independent Story and its cover remain accessible through the API | Not run | anonymous | — | — |
| Cover response and CDN/shared-cache behavior | Origin sends `Cache-Control: private, no-store`, `CDN-Cache-Control: no-store`, and `Surrogate-Control: no-store`; CDN bypasses this path; repeat the previously fetched URL after takedown/suspension with a warm cache and confirm it does not serve stale `200` bytes | Not run | anonymous/operations | — | — |
| Legacy S3 presigned cover URL and warmed cache during rollout | With real staging S3, do not claim the old URL is revoked while deletion is pending. Reuse an exact pre-proxy URL after both actions; verify origin denial only after delete plus HEAD verification, confirm restored Story uses the new key, and test the old URL through a warm CDN/browser cache until denial or measured expiry/invalidation. Record the URL's original signed expiry, origin residual, and cache residual separately; verify provider copy/read/delete/HEAD permissions and semantics. | Not run | anonymous/operations | — | — |
| Suspended Story in frontend preview | Hide card/search/library and comment/save actions; show neutral `Story unavailable`; clear stale saved/comment/clap cache | Not run | anonymous | — | — |
| Client submits `author_id` or `role` | Rejected as unknown input; persisted author/role remain server-controlled | Not run | reader | — | — |
| Cross-origin Publish with a fake cookie and no bearer token | `401`; no `Access-Control-Allow-Origin` for an untrusted origin; cookies are not an auth mode | Not run | anonymous | — | — |
| Client supplies an upload object key | `400`; no signed URL is issued | Not run | reader | — | — |
| Pending media is read before verification | `404`; pending/quarantine objects are not readable | Not run | anonymous/owner | — | — |
| Completed upload after promotion | URL is bound to server-generated quarantine key; ready object uses a distinct immutable key | Not run | reader/owner | — | — |
| Reporter reads own report status | Protected status endpoint returns case ID and safe status label only | Not run | reporter | — | — |
| Another user reads report details/status | `404`; no report details | Not run | reader | — | — |
| Moderator reads report queue | Allowed; staff read/status transitions are audited | Not run | moderator | — | — |
| Reader or general admin reads moderation queue | `403`; moderation is moderator-role only | Not run | reader/admin | — | — |
| Support reads feedback; non-support reads it | Support allowed and audited; other roles `403` | Not run | support/reader | — | — |
| Security reads security/privacy reports; other roles read them | Security allowed and audited; other roles `403` | Not run | security/support | — | — |
| Feedback/security data appears in community feed/public analytics | Must not appear | Not run | — | — | — |
| Screenshot metadata and access | Allowlisted image only, max 2 MiB, re-encoded without EXIF; no public URL; support access is audited and short-lived | Not run | support | — | — |
| Upload validation order | Reject non-allowlisted MIME, mismatched byte signature, empty/oversized payload before Sharp parsing; valid JPEG/PNG/WebP still normalize and promote | Not run | owner | — | — |
| Retention cleanup | Expired report rows and attached screenshot objects are deleted; audit metadata expires separately | Not run | operator | — | — |

## Evidence handling

- Save the request ID from the response header only. Never save the `Authorization` header or cookie.
- Do not attach raw response bodies for reports, private Stories, user data, or screenshots.
- Record `Pass` or `Fail`, timestamp, actor role, and request ID in the table. For failures, add a minimal issue reference that contains no sensitive content.
- Use separate test accounts per role; do not grant broad roles just to make a check pass.
