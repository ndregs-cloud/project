# NOVA Backend MVP

> **Pre-beta gate:** The development preview has a read-only backend connection for Discover/Story/cover only; its local Write/Publish flow is a demo, not a server action. API routes exist in this codebase, but production availability is not established. Explicitly unintegrated writes return `501` before domain side effects. Use only fictional demo/test data; do not accept real reports or feedback, and do not open beta until the runtime contract and staging access, privacy, and escalation gates pass.

Backend API modular-monolith untuk NOVA, dibangun dengan **TypeScript, Fastify, dan PostgreSQL**. Berkas gambar disimpan terpisah di object storage S3-compatible. API menerima JSON dan menggunakan prefix `/api/v1`.

Use the mockup's English UI terms: **Story** is original creator writing; **Library** is saved Stories; **Discover** is the public feed; and the creator flow is **Write → Draft → Preview → Publish**. The API has Stories only—no Book model, sample, or endpoint. The development preview's Discover/Story/cover connection is read-only; “Publish locally” must stay local-only/private and must not display a persisted `Public` state.

## Fitur dalam codebase (availability belum ditetapkan)

- Routes for identity, profiles, Stories, social actions, reports, feedback/security intake, moderation, and media exist in the codebase; local fixture evidence and per-route status are listed in the [route security inventory](./ROUTE_SECURITY_INVENTORY.md). Do not infer production availability from a route existing.
- Safe reads and selected owner/staff write paths have disposable PostgreSQL RLS E2E coverage. Other write branches explicitly return `501 NOT_INTEGRATED` before domain/database or storage side effects; the exact matrix follows below.
- The production startup validator requires a public moderation runtime contract that is absent from canonical migrations in this worktree. Production availability therefore remains unestablished and startup must fail closed until an approved contract is deployed.
- OIDC bearer-token verification using JWKS; Zod request validation; consistent error shape, request IDs, redacted structured logs, CORS allowlist, security headers, and a PostgreSQL-backed IP/account limiter are present in source. Their deployment readiness is not implied by local tests.
- Versioned schema migrations, health/readiness checks, Compose for PostgreSQL and MinIO, and unit/API smoke tests are included in the codebase.

Licensed reading entitlements, payments/earnings, advanced search, personalized feeds, messaging, collaborative editing, blocking, backup providers, and deep analytics are outside the MVP.

## Persyaratan

- Node.js 22.12+, 24.x, atau 26+ dan npm (sesuai rentang engine yang dinyatakan paket).
- PostgreSQL 15+.
- Penyedia identitas OIDC yang menyediakan JWKS URI, issuer, dan audience untuk access token.
- Optional local S3-compatible storage for explicitly scoped disposable media-read tests. Active upload routes are unavailable; no upload bucket setup is required to use the MVP preview.

## Menjalankan secara lokal

```bash
cp .env.example .env
# Ubah AUTH_JWKS_URL, AUTH_ISSUER, dan AUTH_AUDIENCE ke penyedia OIDC Anda.
docker compose up -d
npm install
npm run migrate
npm run dev
```

API berjalan di `http://localhost:3000`. PostgreSQL dan MinIO Compose hanya dipetakan ke loopback (`127.0.0.1`); console MinIO tersedia di `http://localhost:9001`. Kredensial contoh pada `.env.example` hanya untuk development lokal; jangan gunakan kembali di staging/production. Do not create a bucket or try upload routes for MVP validation: upload-intent/completion and feedback screenshot attachment return `501` and do not issue signed upload URLs. Configure a local bucket only when explicitly exercising disposable media-read or support-screenshot tests; those do not verify a real provider.

Token akses harus berupa JWT dengan `sub`, issuer, audience, expiry, dan signature yang sesuai JWKS. Setelah JWT diverifikasi, **Permintaan terautentikasi pertama dapat memicu provisioning akun lokal** sebagai `reader_<random>`; ini dapat terjadi pada route terlindungi mana pun, bukan hanya `GET /api/v1/me`, dan tidak menyiratkan bahwa respons route harus 2xx. Username dapat diganti melalui `PATCH /api/v1/me`. **Tidak ada mode autentikasi palsu atau endpoint login development.**

## Perintah

```bash
npm run dev         # server dengan reload
npm run build       # artefak JavaScript ke dist/
npm start           # menjalankan build
npm run typecheck   # pemeriksaan TypeScript
npm test            # unit dan API smoke tests tanpa layanan eksternal
npm run migrate     # menerapkan migrasi yang belum tercatat
npm run cleanup:feedback # menghapus report dan screenshot yang melewati retensi
```

`npm run migrate` memakai tabel `schema_migrations`, advisory lock PostgreSQL, dan transaksi; runner ini dibatasi ke PostgreSQL disposable di loopback pada mode `development`/`test`, dan tidak boleh diarahkan ke Supabase atau database bersama. Riwayat kanonis untuk project Supabase adalah migrasi bertimestamp di `supabase/migrations/`; gunakan Supabase CLI (`supabase db push`) untuk perubahan remote. Jangan menduplikasi migrasi Supabase ke runner backend atau mengubah migrasi yang sudah diterapkan.

## Konfigurasi penting

Lihat `.env.example` untuk seluruh variabel. Tiga pengaturan autentikasi harus cocok dengan access token yang diterbitkan IdP. Nilai contoh di `.env.example` adalah kredensial lokal palsu; rahasia staging/production harus berada di environment/secret manager, bukan repository. Jika `NODE_ENV` tidak disetel, aplikasi menganggap runtime sebagai `production` (fail-closed); set `NODE_ENV=development` secara eksplisit hanya untuk lokal. Production wajib memiliki `DATABASE_URL` eksplisit—tidak memakai kredensial fallback lokal—dan menolak `AUTH_JWKS_URL` maupun `S3_ENDPOINT` yang tidak menggunakan HTTPS. Fallback database lokal hanya tersedia di development/test. `CORS_ORIGINS` menerima daftar origin dipisahkan koma. `TRUST_PROXY` (jika diatur) harus berisi alamat/CIDR reverse proxy yang benar-benar dipercaya; jangan mempercayai header forwarding dari klien langsung.

Di deployment publik, wajibkan HTTPS, set origin CORS yang tepat, lindungi secrets, aktifkan backup/restore teruji dan monitoring, tetapkan RPO/RTO, serta tinjau CSP/HSTS dan ukuran request. Pertahankan `NOINDEX=true` di staging (default mengirim `X-Robots-Tag: noindex, nofollow, noarchive`); ubah hanya untuk production setelah keputusan peluncuran/SEO yang disengaja. Rate limiter menyimpan counter di PostgreSQL agar konsisten antar instance. Untuk beban besar, ukur overhead query limiter dan pertimbangkan store khusus sebelum mengubah arsitektur.

## API route status matrix

The status below describes source behavior and local disposable-PostgreSQL evidence only—not production availability. The production startup validator requires `public.nova_moderate_hide_story(uuid,text)`, `public.nova_moderate_restore_story(uuid,uuid,text)`, `public.nova_enqueue_media_key_revocation(uuid,uuid,text,text)`, `public.nova_rls_valid_moderation_action(uuid)`, `public.nova_rls_own_media_revocation_pending(uuid)`, both actor predicates (`public.nova_rls_actor_active()`, `public.nova_rls_actor_has_role(text[])`), the row-bound worker predicate (`public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)`), forced-RLS `public.media_no_media_required`, and the exact worker queue RLS policy scope, plus reviewed least-privilege role grants. These are absent from canonical migrations in this worktree; production must remain fail-closed. No canonical or remote migration is claimed or changed. See the [complete method/path/test inventory](./ROUTE_SECURITY_INVENTORY.md).

| Method and path | Access | Current code contract and evidence |
|---|---|---|
| `GET /api/v1/me` | Login | Reads own profile. An authenticated request may trigger local reader provisioning through `nova_auth_bootstrap_identity(text)` in the request transaction; this can happen on any protected route, with `/me` as the PG17 E2E example rather than the exclusive trigger. |
| `PATCH /api/v1/me` | Login | Own profile and existing ready-avatar reference/clear are tested against disposable RLS; forged role is rejected. Production availability is not established. |
| `GET /api/v1/users/:username` | Public | Public profile read; follower/following counts are omitted, not sent as zero. |
| `GET /api/v1/tags` | Public | Read-only curated tag catalogue; no tag-catalogue write route is exposed. |
| `POST /api/v1/stories` | Login | Private draft create and curated tag insert have local owner-RLS E2E. |
| `GET /api/v1/stories/:id` | Public/owner | Public Story or own Draft read; private Drafts remain `404`. |
| `PATCH /api/v1/stories/:id` | Owner | Versioned text/tag update; `coverMediaId: null` intentionally detaches a reference only (not a media upload). The current local test submits null on a Draft with no cover; non-null assignment remains unavailable. |
| `POST /api/v1/stories` with non-null `coverMediaId` | Login | `501 NOT_INTEGRATED` before Story insert or media lookup; Story/tag state is unchanged and no provider is called. |
| `PATCH /api/v1/stories/:id` with non-null `coverMediaId` | Owner | `501 NOT_INTEGRATED` before Story lookup/update; Story/version/tag state is unchanged and no provider is called. |
| `POST /api/v1/stories/:id/publish` | Login | `501 NOT_INTEGRATED`; no Story/action/outbox changes. |
| `POST /api/v1/stories/:id/unpublish` | Login | `501 NOT_INTEGRATED`; no Story/action/outbox changes. |
| `DELETE /api/v1/stories/:id` | Login | `501 NOT_INTEGRATED`; no Story/action/outbox changes. |
| `GET /api/v1/stories`, `GET /api/v1/me/stories` | Public/login | Feed and own Story reads; local tests only. |
| `PUT`, `DELETE /api/v1/me/bookmarks/:storyId` | Login | Own bookmark insert/delete and idempotency are locally RLS-tested. |
| `GET /api/v1/me/bookmarks` | Login | Read own Library; local tests only. |
| `PUT`, `DELETE /api/v1/me/following/:userId` | Login | Own follow/unfollow and idempotency are locally RLS-tested. |
| `GET /api/v1/me/following` | Login | Read only own following edges; local RLS test. |
| `GET /api/v1/stories/:id/comments` | Public | Read visible comments; local fixture test. |
| `POST /api/v1/stories/:id/comments` | Login | `501 NOT_INTEGRATED` before Story lookup; no Story/comment/action/outbox mutation. Comment reads remain available. |
| `DELETE /api/v1/comments/:id` | Login | `501 NOT_INTEGRATED` before comment lookup for all callers; comment/action/outbox state remains unchanged. Author and moderator branches are covered by the local PG17 contract test; no comment soft-delete is active. |
| `POST /api/v1/reports` | Login | Create a report; local RLS/privacy E2E. |
| `GET /api/v1/me/reports`, `GET /api/v1/me/reports/:id` | Login | Reporter-only status reads; workflow status is separate from persisted `removal.status`. The “Removal pending — cleanup could not be confirmed” label appears only when `removal_pending=true` is persisted; local tests. |
| `PATCH /api/v1/moderation/reports/:id` | Moderator | `501 NOT_INTEGRATED`; report remains open and unchanged. |
| `POST /api/v1/moderation/actions` | Moderator | `hide_story`/`restore_story` have disposable-fixture E2E/design evidence only; production capability is not established and the runtime contract is missing from canonical migrations. Other actions, including comment removal and user suspension, return `501` without mutation. |
| `POST /api/v1/feedback` | Login | No-screenshot feedback insert is locally RLS-tested. Supplying `screenshotMediaId` returns `501` before media lookup or case insert. |
| `PATCH /api/v1/internal/feedback/:id` | Support | Status/resolution update plus audit is locally RLS-tested; production availability is not established. |
| `GET /api/v1/me/feedback/:id`, `/api/v1/internal/feedback/*` | Reporter/support | Protected status/detail reads are locally tested. Support access to an already-existing fixture screenshot is test-only; new attachments are unavailable. |
| `POST /api/v1/security-reports` | Login | Security/privacy report insert is locally RLS-tested. |
| `PATCH /api/v1/internal/security-reports/:id` | Security | Status update and audit are locally RLS-tested. |
| `GET /api/v1/me/security-reports/*`, `/api/v1/internal/security-reports/*` | Reporter/security | Protected reads are locally tested; not production sign-off. |
| `POST /api/v1/media/upload-intents`, `POST /api/v1/media/:id/complete` | Login | `501 NOT_INTEGRATED` before media-domain lookup/write, signing, validation, or provider call; pending rows remain unchanged. |
| `GET /api/v1/media/:id` | Eligible owner/public reader | Read proxy path has disposable-fixture/fake-storage tests only; real object storage/CDN behavior is unverified. |
| `GET /api/v1/moderation/reports`, `GET /api/v1/moderation/reports/metrics` | Moderator | Read-only queue/metrics code paths; local fixture evidence only. |
| `GET /api/v1/internal/feedback/metrics`, `GET /api/v1/internal/security-reports/metrics` | Support/security | Read-only private metrics and access audit; local fixture evidence only. |

After JWT signature verification, the first authenticated request may trigger creation of one local `reader` through `public.nova_auth_bootstrap_identity(text)` as part of the request transaction; this can occur on any protected route, and `GET /api/v1/me` is only the PG17.11 E2E example. An optional-auth route with a bearer token can also be the first authenticated request. Therefore `/api/v1/me` is not a pure read. A bootstrap query failure or PostgreSQL statement timeout is rolled back and mapped to the neutral `503 IDENTITY_UNAVAILABLE`; the timeout regression uses a short disposable-test timeout and verifies no partial user row, no SQLSTATE in the response, and cleared request GUCs. The production pool's normal statement timeout is 15 seconds; connection acquisition errors before the bootstrap transaction are outside this specific mapping.

All pagination uses opaque base64url cursors (timestamp + UUID), not offsets; `limit` is 1–50. Errors use `{ "error": { "code", "message", "requestId", "fields?" } }`; responses omit email and OIDC subject. For an explicitly documented `501`, the guarantee is no domain/database or provider side effect (auth/rate-limit middleware still applies). An ambiguous non-`501` `5xx` does not promise rollback or no change: refresh/read the relevant record before retrying. Responses must not expose SQLSTATE or database details.

Story restore's versioned `expectedHideActionId`, stale-state conflict, exact `commentsOpen` restore, moderation hide/restore, and outbox transitions are exercised only in disposable fixture tests. They are not production capabilities until the reviewed public helper/table contract and least-privilege roles are approved and deployed. Signing exercised by local tests uses fictional local credentials; active upload routes do not issue signed upload URLs.

**Production deployment blocker — runtime contract:** startup validation requires the public moderation helper signatures `nova_moderate_hide_story(uuid,text)`, `nova_moderate_restore_story(uuid,uuid,text)`, `nova_enqueue_media_key_revocation(uuid,uuid,text,text)`, `nova_rls_valid_moderation_action(uuid)`, `nova_rls_actor_active()`, `nova_rls_actor_has_role(text[])`, and `nova_rls_valid_media_revocation(uuid,uuid,text,uuid)`, the owner-scoped read predicate `nova_rls_own_media_revocation_pending(uuid)`, the exact `media_key_revocations` worker SELECT/UPDATE policy scope, plus `public.media_no_media_required` with forced RLS and required columns. The canonical migrations in this worktree do not install this contract; the disposable SQL fixture only mirrors it for local tests. No production migration or role/grant plan is claimed or added here. Production must remain fail-closed until an approved canonical migration and least-privilege grants are reviewed and deployed.

### Preview and API transition availability

- Routes for these flows exist in source, but production availability is not established; consult the API matrix and fixture-only evidence above. Write branches explicitly marked `501` make no domain changes.
- Publish, unpublish, and delete return `501 NOT_INTEGRATED`; “Publish locally” is a frontend demo that changes only the browser's demo library and does not publish to NOVA.
- Story create/edit reject client-supplied `status`/`visibility`; cover assignment is currently `501`. After any ambiguous non-`501` `5xx`, clients must refresh the relevant state before retrying.
- Keep every sample and UI label in the Stories-only product scope. Do not use “A book” as a demo Story or imply a Books feature.

## Aturan konten dan keselamatan

 Draft selalu `private`; create/patch are verified only against the disposable RLS fixture, not production. Publish, unpublish, delete, comment creation, all comment deletion, and non-null Story cover assignment return `501 NOT_INTEGRATED` without domain changes. Public feeds/bookmarks/comment reads contain only eligible published Stories; no comment soft-delete route is active. Body Story is limited to 100,000 characters, title 160, summary 500, comment 2,000, and tags 8. Content is **plain text**; clients must escape on render and the backend does not allow HTML/rich text.

Source includes a `GET /api/v1/media/:id` read proxy and hide/restore procedures exercised against disposable fixtures with fake storage only. This is not production capability: the public helper/table contract is absent from canonical migrations, startup must fail closed, and the validator pins exact SHA-256 fingerprints for required helper bodies. Provider/CDN behavior is unverified. No production cover move, takedown, or purge is claimed. Unsupported moderation actions—including `suspend_user`, `unsuspend_user`, and `remove_comment`—and report-status changes return `501 NOT_INTEGRATED` without mutation. Storage credentials and `DeleteObject`/`HeadObject` semantics require future isolated staging verification.

The local outbox worker fixture runs at most five deletion attempts with stored backoffs of 30 seconds, 2 minutes, 10 minutes, 30 minutes, and 2 hours. Attempt five sets `escalated_at`, logs an error, then stops; the row and action remain pending. This is local disposable-test behavior, not a production storage/purge guarantee. `escalated_at` records a terminal escalation state only; it does not prove a page/contact was sent. No authoritative full-purge verifier or application finalizer/resolution path exists, and no production escalation owner, response target, or alert routing is assigned; these remain release blockers.

Rollback copy cleanup is attempted only after a definite rollback and is best effort. If the `COMMIT` acknowledgement is lost, the service first destroys the original DB connection and performs a fresh, separately credentialed worker-pool read for the exact action/media/outbox association. If that read confirms the committed row, the normal committed pending response may be returned. If the read is absent or unavailable, the API returns neutral `503 TRANSACTION_OUTCOME_UNCONFIRMED`, omits a removal claim, preserves the copied destination, and requires a refresh before retrying. Safe internal logs contain action/media IDs and booleans only—never raw destination keys or provider details—and are not a durable reconciliation record, queue, or alert. There is no automatic orphan retry or restart-resumable work item; if the warning is not retained and triaged, a copied object may remain indefinitely. Do not claim cleanup/verification, and keep the report open. Durable reconciliation, alert/paging routing, an accountable production owner, and a response target remain unresolved release gates; no schema, queue, alert, or owner is implemented or designated here.

Read-proxy response code sets no-store headers, but cache behavior is not verified on a deployed CDN. Local fake-storage tests do not prove that an old signed URL is revoked, that a key was purged, or that caches/transfers/downloaded bytes are gone. Any TTL range in code is configuration evidence only; exact provider behavior and residual access need future staging measurement.

AWS documents strong read-after-write behavior for S3 object deletes, while presigned URLs are checked when each request begins and an already-started transfer can continue ([S3 consistency](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html), [presigned URL behavior](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)). CloudFront invalidation removes edge copies, but a viewer or corporate proxy may still retain a cached response ([CloudFront invalidation](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Invalidation.html)). These AWS guarantees are not proof that an arbitrary S3-compatible provider or the deployed CDN behaves the same way; no real-provider or warmed-cache behavior is claimed as verified.

Roles `moderator`, `support`, and `security` are separate and are not inherited from `admin`; they are stored in the database, never trusted from token/body input, and must be granted through a controlled process. Moderation actions store a reason and audit metadata. Require MFA for staff roles in the IdP and do not enable internal queues before response owners are assigned.

Database tidak memuat profil, cerita, audience count, atau kutipan demo. Bila fixture diperlukan untuk staging, gunakan data fiktif yang diberi label jelas, tanpa angka audiens/kutipan rekaan, tanpa kredensial produksi, dan dengan akun uji least-privilege. Backend ini belum menerima field tautan eksternal buatan pengguna; jika ditambahkan kemudian, validasi hanya skema `https:` (atau allowlist yang disetujui) dan tampilkan domain tujuan dengan jelas.

Feedback and security-report routes plus private staff views exist in source and have local disposable-fixture RLS tests; the development preview is not connected to them and production availability is not established. No email is sent. No real beta intake is authorized. New feedback without an attachment and security-report/status paths are tested locally; providing `screenshotMediaId` returns `501` before lookup/insert, upload routes return `501`, and active code does not issue signed upload URLs or process/re-encode user uploads. Support access/signing for an already-existing screenshot is fixture-only evidence. Retention defaults in source are 90 days for feedback, 180 days for security/privacy reports, and 365 days for staff access audit; the cleanup command requires separate local/staging verification.

## Verification and remaining gates

- **Latest local verification (2026-10-10):** `./node_modules/.bin/tsc --noEmit -p tsconfig.json` passed; `./node_modules/.bin/vitest run --reporter=dot` passed **20 tests**, with **20 opt-in PostgreSQL tests skipped** by default. A separate SHA-256-bound disposable PostgreSQL **17.11** E2E run passed **20/20** tests (authorization 5/5, startup/RLS 7/7, moderation/outbox 8/8). Exact commands/results, source patch, identical before/after hash check, per-suite logs, security matrix, and Security-review handoff are recorded under `/workspace/backend-rate-limit-rls-final47-evidence/`; the snapshot SHA-256 is in `source-snapshot-hash-check.txt`. Coverage includes incoming/transitive `SET ROLE` membership negatives; exact worker `UPDATE` allowlists; ten-helper body, `prolang`, and `provolatile` drift rejection; actor predicate owner/ACL/search-path/role/schema checks; row-bound media-worker predicate and exact SELECT/UPDATE policy-scope drift rejection; moderation runtime-contract validation (private fixture decoy rejected); authenticated-request local provisioning (E2E exercised via `/api/v1/me`) and a real PostgreSQL statement-timeout regression with neutral 503, rollback, and no SQLSTATE leakage; unknown `58030` COMMIT preservation/refresh behavior; exact published/visibility/comments-open restore state; attempt-five pending escalation without a verified-purge claim; omitted public follower counts; and fail-closed unintegrated transitions/comments/media writes. Rollback-copy orphan cleanup remains log-only without durable reconciliation, automatic retry, alert routing, or assigned owner/response target; this is an unresolved production gate, not a solved finding. These are local-only results; no production, staging, or Security sign-off is implied.
- **Frontend local verification:** typecheck, lint, and Next.js production build passed. The development preview has read-only backend integration for Discover/Story/cover; Write/Publish/account/feedback/reports remain disconnected or local. This does not verify authenticated or staging behavior, including live suspension propagation.
- PostgreSQL integration suites remain opt-in and are skipped by the ordinary `npm test`; the authorization, startup/RLS, and outbox suites were run separately on disposable local PostgreSQL 17.11. GitHub Actions provisions disposable PostgreSQL and uploads minimal evidence when CI runs.
- **Dependency audit:** after upgrading to Vitest **5.0.3**, both full `npm audit` and `npm audit --omit=dev` report **0 vulnerabilities** in the current lockfile. GitHub Actions now runs `npm audit --audit-level=low` after `npm ci --no-audit`; it audits the complete lockfile, including dev dependencies, and fails CI on any vulnerability. The local result does not replace successful CI or staging dependency verification.
- **Not verified:** a real OIDC provider, actual S3 object upload/download/promotion/rotation, Docker Compose execution, CDN cache-bypass/invalidation behavior, and staging verification with the frontend. The only URL-signing exercised was in local disposable tests with fictional credentials; active upload routes do not issue signed upload URLs. No real bucket or production credentials were used. There is no production claim that a key is revoked or purged, and no deployment-wide residual-access maximum is established. Beta remains blocked.
- Keep beta intake closed until authenticated frontend/backend flows and staging access, privacy, screenshot, and escalation checks pass. The development preview remains partly prototype-only; use the [runbook](./RUNBOOK.md) and [staging checklist](./SECURITY_STAGING_CHECKLIST.md).
