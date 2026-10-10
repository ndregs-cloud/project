# NOVA Backend Route Security Inventory

**Scope and evidence.** This inventory covers the Fastify routes declared by the backend plus the CORS-generated preflight route. “Locally tested” means tests against disposable PostgreSQL 17.11 and/or fake storage; it is not staging or production evidence. Production startup remains fail-closed because the identity/rate-limit and public moderation/media runtime helper contracts and their approved deployment grants are absent from canonical migrations. No remote change, canonical migration, merge, or deployment is represented here.

| Method and path | Access / effect | Current contract and evidence |
|---|---|---|
| `GET /healthz` | Liveness; no database read | Available; unit-tested independently of PostgreSQL. |
| `GET /readyz` | Readiness; `SELECT 1` | Returns 503 on database query failure; route behavior not directly tested. |
| `GET /api/v1` | Static API name/version | Read-only; route not directly tested. |
| `OPTIONS *` (CORS-generated) | Preflight | Allowed origin/method/header behavior is configured in `src/app.ts`; no dedicated preflight E2E identified. |
| `GET /api/v1/me` | Authenticated profile read. The shared `registerAuth` `preHandler` runs `authenticateToken()`/`resolveIdentity()` before the protected handler and may invoke `public.nova_auth_bootstrap_identity(text)` for a verified first-time subject; `/me` is one example, not the exclusive trigger. | Not a pure read. Identity/bootstrap runs in the request transaction; Fastify `onSend` invokes `commitRequestTransaction()`, `onError` rolls back thrown request errors, and `onResponse` provides defensive rollback cleanup for aborted or short-circuited responses. Commit is not gated by a generic HTTP-status check. PG17.11 E2E exercises first-login provisioning via `/me`; an actual short statement-timeout test proves neutral `503 IDENTITY_UNAVAILABLE`, rollback/no partial user, no SQLSTATE leakage, and cleared request context. |
| `PATCH /api/v1/me` | Authenticated own profile write | Locally RLS-tested; role is database-derived, forged role input rejected; avatar may be cleared or reference an owned ready avatar. |
| `GET /api/v1/users/:username` | Public profile read | Follower/following counts are omitted, not returned as zero; unit contract test covers omission. |
| `GET /api/v1/tags` | Public catalogue read | Read-only curated tags; no tag write route. Dedicated route E2E not identified. |
| `POST /api/v1/stories` | Authenticated Story create | Creates a private Draft with server-derived author/state and curated tags; local RLS E2E. Non-null `coverMediaId` is a separate 501 branch below. |
| `POST /api/v1/stories` with non-null `coverMediaId` | Authenticated write attempt | `501 NOT_INTEGRATED` before Story insert/media lookup; no Story/tag/provider side effect; local PG regression. |
| `GET /api/v1/stories/:id` | Public or owner read | Public eligible Story or caller’s own Draft; other/private Drafts are neutral 404; local authorization E2E. |
| `PATCH /api/v1/stories/:id` | Owner Story write | Versioned text/tag updates; `coverMediaId: null` intentionally detaches a reference only (not an upload). Current null-input test uses a Draft with no cover; non-null assignment is separately fail-closed with 501. |
| `PATCH /api/v1/stories/:id` with non-null `coverMediaId` | Owner write attempt | `501 NOT_INTEGRATED` before Story lookup/update; Story/version/tags remain unchanged; local PG regression. |
| `POST /api/v1/stories/:id/publish` | Authenticated transition | `501 NOT_INTEGRATED` before side effects; Story/action/outbox unchanged; local PG E2E. |
| `POST /api/v1/stories/:id/unpublish` | Authenticated transition | `501 NOT_INTEGRATED` before side effects; Story/action/outbox unchanged; local PG E2E. |
| `DELETE /api/v1/stories/:id` | Authenticated transition | `501 NOT_INTEGRATED` before side effects; Story/action/outbox unchanged; local PG E2E. |
| `GET /api/v1/stories` | Public feed read | Paginated public eligible Stories with optional tag/author filters; local authorization E2E. |
| `GET /api/v1/me/stories` | Authenticated own Story read | Paginated caller’s Drafts/published Stories; no direct successful-route test identified. |
| `PUT /api/v1/me/following/:userId` | Authenticated own follow write | Self-follow rejected; idempotent; local RLS E2E. |
| `DELETE /api/v1/me/following/:userId` | Authenticated own follow write | Own edge only; idempotent; local RLS E2E. |
| `GET /api/v1/me/following` | Authenticated own follow read | Reads only caller’s following edges; local RLS E2E. |
| `PUT /api/v1/me/bookmarks/:storyId` | Authenticated own bookmark write | Eligible public Story only; idempotent; local RLS E2E. |
| `DELETE /api/v1/me/bookmarks/:storyId` | Authenticated own bookmark write | Deletes own bookmark only; idempotent; local RLS E2E. |
| `GET /api/v1/me/bookmarks` | Authenticated own Library read | Own paginated bookmarks; ineligible/hidden Stories excluded; local RLS E2E. |
| `GET /api/v1/stories/:id/comments` | Public comment read | Visible comments on eligible public Story with comments open; local RLS E2E; reads remain available after unsupported writes. |
| `POST /api/v1/stories/:id/comments` | Authenticated comment write | `501 NOT_INTEGRATED` before Story lookup/domain side effect; PG regression asserts no side effects and no SQLSTATE leakage. |
| `DELETE /api/v1/comments/:id` | Authenticated comment write | `501 NOT_INTEGRATED` for author, moderator, and other callers before comment lookup; no comment/action/outbox change; PG regression. |
| `POST /api/v1/reports` | Authenticated report intake | Creates report after target validation; local RLS/privacy E2E. Response workflow status and removal state are distinct. |
| `GET /api/v1/me/reports` | Authenticated reporter read | Paginated own report status only; PG E2E covers cursor traversal, cross-reporter isolation, safe-field projection, and pending/non-pending removal state. |
| `GET /api/v1/me/reports/:id` | Authenticated reporter read | Reporter-only status; workflow status is independent of `removal.status`. The pending label is returned only when persisted `removal_pending=true`; local authorization E2E. |
| `GET /api/v1/moderation/reports` | Moderator queue read | Moderator-only report details; staff reads audited; local privacy/RLS E2E. |
| `PATCH /api/v1/moderation/reports/:id` | Moderator report write | `501 NOT_INTEGRATED`; report remains unchanged/open; local PG E2E. |
| `POST /api/v1/moderation/actions` (`hide_story` / `restore_story`) | Moderator transition | Fixture-only/local behavior, not production capability. Hide/restore, atomic action/outbox, exact `comments_open` restore, and RLS policy scope have disposable-PG evidence; startup remains blocked until approved public runtime contract is deployed. Failure responses must not expose storage keys/provider details; ambiguous failures require state refresh. |
| `POST /api/v1/moderation/actions` (`remove_comment`, `suspend_user`, `unsuspend_user`, other unsupported actions) | Moderator write attempt | `501 NOT_INTEGRATED` without domain/storage mutation; local PG E2E. |
| `GET /api/v1/moderation/reports/metrics` | Moderator aggregate read | Private aggregate with access audit; successful behavior not directly tested. |
| `POST /api/v1/feedback` without `screenshotMediaId` | Authenticated feedback intake | Creates case; local RLS E2E. |
| `POST /api/v1/feedback` with `screenshotMediaId` | Authenticated write attempt | `501 NOT_INTEGRATED` before media lookup/case insert/provider call; local PG regression. |
| `GET /api/v1/me/feedback/:id` | Authenticated reporter read | Reporter-only status link; local RLS E2E. |
| `GET /api/v1/internal/feedback` | Support queue read | Support-only, paginated, audited; authorized success path not directly tested. |
| `GET /api/v1/internal/feedback/metrics` | Support aggregate read | Support-only private metrics; unauthorized role denial tested; authorized success path not directly tested. |
| `GET /api/v1/internal/feedback/:id` | Support detail read | Support-only; role separation and local RLS tested. |
| `GET /api/v1/internal/feedback/:id/screenshot` | Support screenshot read | Short-lived redirect for pre-existing fixture object; local fixture only, not production storage evidence. New screenshot attachment is unavailable. |
| `PATCH /api/v1/internal/feedback/:id` | Support case update | Support-only status/resolution/recurrence update with audit; local RLS E2E. |
| `POST /api/v1/security-reports` | Authenticated security-report intake | Creates a private security/privacy case; local RLS E2E. |
| `GET /api/v1/me/security-reports/:id` | Authenticated reporter read | Reporter-only safe status; local RLS E2E. |
| `GET /api/v1/internal/security-reports` | Security queue read | Security-role paginated private queue; authorized success path not directly tested. |
| `GET /api/v1/internal/security-reports/metrics` | Security aggregate read | Security-role private metrics; authorized success path not directly tested. |
| `GET /api/v1/internal/security-reports/:id` | Security detail read | Security-role; role separation and local RLS tested. |
| `PATCH /api/v1/internal/security-reports/:id` | Security case update | Security-role status/resolution/recurrence update with audit; local RLS E2E. |
| `POST /api/v1/media/upload-intents` | Authenticated media write attempt | `501 NOT_INTEGRATED` before media lookup/write, signing, validation, or provider call; local PG E2E. |
| `POST /api/v1/media/:id/complete` | Authenticated media write attempt | `501 NOT_INTEGRATED` before media lookup, validation, promotion, or cleanup; local PG E2E. |
| `GET /api/v1/media/:id` | Eligible owner/public reader | No-store eligibility-checked proxy; disposable fixture/fake-storage tests only. Real provider/CDN behavior and cache purge are unverified. |

## Operational interpretation

- `registerAuth()` installs the shared auth `preHandler` before route plugins. For each `authRequired` route (and `authOptional` routes carrying a Bearer token), the `preHandler` calls `authenticateToken()`/`resolveIdentity()` and may invoke `public.nova_auth_bootstrap_identity(text)` for a verified first-time subject before the route handler. Fastify `onSend` calls `commitRequestTransaction()`; thrown request errors are rolled back by `onError`; `onResponse` is the defensive/fallback rollback cleanup for aborted or short-circuited responses. The `onSend` commit hook does not enforce a generic HTTP-status-code condition. `/api/v1/me` is the E2E example, not the only route that can trigger first-login provisioning.
- A `501 NOT_INTEGRATED` response on the explicitly documented branches guarantees no domain/provider mutation; authentication and rate-limit middleware may still run.
- For other `5xx` responses, do not claim rollback or no change. Refresh/read the relevant persisted state before retrying.
- `removal.status=pending` and the label “Removal pending — cleanup could not be confirmed” are exposed only when the report’s pending flag is persisted. A successful storage `DELETE` is not a verified purge. No reporter-facing escalation claim is made; `escalated_at` only records terminal escalation state and does not prove a page/contact was sent.
- The disposable reports-cleanup worker can select only `removal_pending` reports bound to a valid hidden Story/hide action. Its RLS predicate uses each report row's own target and does not trust caller target GUCs; tests show a conflicting or absent caller GUC cannot change row-bound eligibility. The enqueuer's separate read/update probes reject missing, malformed, mismatched-story, invalid-action, and non-hide-action bindings.
- Rollback copy cleanup is best effort. If it fails, the structured internal log records action/media IDs and `destinationKeyPresent=true`; it does not record the destination key or another destination identifier. This is log-only: there is no durable orphan record, automatic retry, restart-resumable reconciliation, configured alert/paging route, or assigned production owner/response target. If the warning is not retained and triaged, a copied object may remain indefinitely; no cleanup or purge is verified, and the report must not be closed on this evidence. Durable reconciliation, alert routing, and accountable ownership remain unresolved production gates. Never expose destination keys or provider details to readers.
- Local verification is not staging approval. Production remains fail-closed until the public runtime helper contract, least-privilege grants, operations owner, authorized finalization path, and staging checks are approved and deployed.
