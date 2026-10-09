# NOVA Backend MVP

> **Pre-beta gate:** The development preview has a read-only backend connection for Discover/Story/cover only. Write/Publish/account/feedback/reports remain disconnected or local; feedback is not a staff receipt and its status lookup is unavailable. Use only fictional demo/test data, do not accept real reports or feedback, and do not open beta until authenticated flows and access, privacy, and escalation tests pass in staging.

Backend API modular-monolith untuk NOVA, dibangun dengan **TypeScript, Fastify, dan PostgreSQL**. Berkas gambar disimpan terpisah di object storage S3-compatible. API menerima JSON dan menggunakan prefix `/api/v1`.

Use the mockup's English UI terms: **Story** is original creator writing; **Library** is saved Stories; **Discover** is the public feed; and the creator flow is **Write → Draft → Preview → Publish**. The API has Stories only—no Book model, sample, or endpoint. The development preview's Discover/Story/cover connection is read-only; while Write/Publish remain disconnected, those flows must stay local-only/private and must not display a persisted `Public` state.

## Cakupan implementasi

- OIDC bearer-token verification menggunakan JWKS; identitas eksternal dipetakan ke akun lokal.
- Profil publik/pribadi, katalog tag, cerita draft privat, edit optimistic-concurrency, publish/unpublish, soft delete, dan discovery feed dengan cursor.
- Follow dan bookmark idempotent; komentar dangkal; laporan konten; antrean/status moderasi; tindakan moderator dengan audit trail.
- Upload gambar langsung ke object storage melalui URL bertanda tangan; ukuran byte, MIME allowlist, dan signature JPEG/PNG/WebP divalidasi sebelum bytes diparse, lalu gambar dinormalisasi sebelum media menjadi `ready`.
- Validasi request berbasis Zod, error shape konsisten, request ID, log terstruktur dengan redaksi, CORS allowlist, header keamanan, dan limiter IP/akun berbagi counter PostgreSQL.
- Migrasi skema berversi, health/readiness checks, Compose untuk PostgreSQL dan MinIO, serta unit/API smoke tests.

Licensed reading entitlements, payments/earnings, advanced search, personalized feeds, messaging, collaborative editing, blocking, backup providers, and deep analytics are outside the MVP.

## Persyaratan

- Node.js 22.12+, 24.x, atau 26+ dan npm (sesuai rentang engine yang dinyatakan paket).
- PostgreSQL 15+.
- Penyedia identitas OIDC yang menyediakan JWKS URI, issuer, dan audience untuk access token.
- Bucket object storage S3-compatible jika upload media akan digunakan.

## Menjalankan secara lokal

```bash
cp .env.example .env
# Ubah AUTH_JWKS_URL, AUTH_ISSUER, dan AUTH_AUDIENCE ke penyedia OIDC Anda.
docker compose up -d
npm install
npm run migrate
npm run dev
```

API berjalan di `http://localhost:3000`. PostgreSQL dan MinIO Compose hanya dipetakan ke loopback (`127.0.0.1`); console MinIO tersedia di `http://localhost:9001`. Kredensial contoh pada `.env.example` hanya untuk development lokal; jangan gunakan kembali di staging/production. Buat bucket bernama `nova-media` melalui console MinIO sebelum mencoba upload, atau sediakan bucket S3 lain. Sesuaikan origin CORS dan kredensial bucket di `.env`.

Token akses harus berupa JWT dengan `sub`, issuer, audience, expiry, dan signature yang sesuai JWKS. Pengguna lokal dibuat otomatis pada pemanggilan pertama; username sementara berbentuk `reader_<random>`, lalu dapat diganti melalui `PATCH /api/v1/me`. **Tidak ada mode autentikasi palsu atau endpoint login development.**

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

## Kontrak endpoint inti

| Metode dan path | Akses | Fungsi |
|---|---|---|
| `GET/PATCH /api/v1/me` | Login | Profil sendiri; `PATCH` tidak dapat mengubah role |
| `GET /api/v1/users/:username` | Publik | Profil publik tanpa email/subject |
| `GET /api/v1/tags` | Publik | Katalog tag |
| `POST /api/v1/stories` | Login | Membuat draft privat, boleh kosong |
| `GET /api/v1/stories/:id` | Publik/pemilik | Membaca cerita publik atau draft milik sendiri; konten privat lain selalu `404` |
| `PATCH /api/v1/stories/:id` | Pemilik | Menyimpan draft/perubahan dengan `version` terakhir pada body; konflik `409 VERSION_CONFLICT` |
| `POST /api/v1/stories/:id/publish` | Pemilik | Persists `status=published`, `visibility=public`, and `publishedAt`; only then returns success |
| `POST /api/v1/stories/:id/unpublish` | Pemilik | Mengembalikan cerita ke draft privat dan menutup komentar |
| `DELETE /api/v1/stories/:id` | Pemilik | Soft delete |
| `GET /api/v1/stories` | Publik | Discover feed terbaru, filter `tag`, `author`, `cursor`, `limit` |
| `GET /api/v1/me/stories?status=draft\|published` | Login | Daftar cerita sendiri dengan cursor |
| `PUT/DELETE /api/v1/me/bookmarks/:storyId` | Login | Menyimpan/menghapus bookmark |
| `GET /api/v1/me/bookmarks` | Login | Library: saved Stories dengan cursor |
| `PUT/DELETE /api/v1/me/following/:userId` | Login | Follow/unfollow; operasi idempotent |
| `GET /api/v1/me/following` | Login | Daftar akun yang diikuti |
| `GET/POST /api/v1/stories/:id/comments` | Publik/login | Membaca atau membuat komentar pada cerita publik yang terbuka |
| `DELETE /api/v1/comments/:id` | Penulis/moderator | Soft delete komentar |
| `POST /api/v1/reports` | Login | Melaporkan profil, cerita, atau komentar |
| `GET /api/v1/me/reports` | Login | Hanya melihat status laporan sendiri |
| `GET /api/v1/me/reports/:id` | Pemilik/login | Case status terproteksi; respons hanya case ID dan status aman |
| `POST /api/v1/feedback` | Login | Satu intake feedback beta dengan kategori tetap dan field bug kondisional |
| `GET /api/v1/me/feedback/:id` | Pemilik/login | Case status feedback sendiri |
| `POST /api/v1/security-reports` | Login | Jalur terpisah untuk eskalasi security/privacy; jangan masukkan password/token/secret |
| `/api/v1/internal/feedback/*` | Support only | Inbox feedback privat dan akses screenshot sementara yang diaudit |
| `/api/v1/internal/security-reports/*` | Security only | Inbox eskalasi privat yang diaudit |
| `/api/v1/moderation/*` | Moderator only | Antrean, transisi status report, dan tindakan moderasi beralasan/audited |
| `POST /api/v1/media/upload-intents` | Login | Membuat upload intent gambar terbatas |
| `POST /api/v1/media/:id/complete` | Pemilik | Memverifikasi objek dan mengubah status menjadi `ready` |
| `GET /api/v1/media/:id` | Pemilik/publik yang berhak | Mengalirkan media `ready` melalui API setelah memeriksa izin terkini; respons tidak boleh di-cache |

Semua daftar menggunakan cursor opaque (base64url posisi waktu + UUID), bukan offset. `limit` dibatasi 1–50. Error memakai `{ "error": { "code", "message", "requestId", "fields?" } }`. Respons tidak menyertakan email atau OIDC subject.

### Preview versus persisted Publish

- The development preview's backend connection is read-only. Until Write/Publish is connected to the authenticated API, keep those flows local-only; disable the `Public` visibility control and do not describe a local change as a published Story.
- Create and patch accept neither client-supplied `status` nor `visibility`. Only the authenticated owner can call the explicit Publish endpoint; its database transaction persists publication before returning `status: "published"`, `visibility: "public"`, and `publishedAt`.
- The client may show `Public` only from that successful persisted response or a subsequent authenticated read. Anonymous Story reads succeed only while the persisted state is public; `unpublish` restores a private Draft and anonymous reads return `404`.
- Keep every sample and UI label in the Stories-only product scope. Do not use “A book” as a demo Story or imply a Books feature.

## Aturan konten dan keselamatan

Draft selalu `private`; satu-satunya jalur publikasi adalah endpoint publish. Feed, bookmark, komentar, dan pembacaan publik hanya memuat cerita `published` yang belum dihapus. Body cerita dibatasi 100.000 karakter, judul 160, ringkasan 500, komentar 2.000, dan tag maksimal 8. Konten dikirim sebagai **teks biasa**; klien wajib melakukan escaping saat merender dan backend tidak mengizinkan HTML/rich text.

Cover publik dibaca melalui `GET /api/v1/media/:id`, bukan dengan URL S3 bertanda tangan. API memeriksa ulang status media, Story, dan kreator pada setiap permintaan; cover hanya dapat dibaca melalui Story aktif yang masih berhak atau Draft milik kreator aktif. Untuk `hide_story`/`suspend_user`, transaksi menyalin cover ke key unik, memperbarui pointer database, dan mencatat key lama dalam outbox. Setelah commit, target takedown tidak lagi dapat dibaca lewat API; pengecualian yang disengaja adalah aset yang juga dipakai Story publik lain yang tetap aktif, agar takedown satu Story tidak merusak Story lain. Jika salinan gagal, transaksi dan tindakan dibatalkan. Storage credentials must permit source reads/copies/writes, `DeleteObject`, and `HeadObject` verification; missing-key responses must be distinguishable from access-denied responses.

Penghapusan outbox baru dianggap terverifikasi setelah `DELETE` diikuti pemeriksaan `HEAD` yang memastikan key lama tidak ada. Jika penghapusan atau pemeriksaan gagal, tindakan tetap diterapkan dan `POST /api/v1/moderation/actions` mengembalikan `202 Accepted` dengan `removal.status: "pending"`—bukan `503` yang menyamarkan commit. Report terkait tetap terbuka (`status: reviewing`, `removalPending: true`, label `Removal pending`); moderator tidak dapat mengubahnya menjadi `Action taken` atau `Closed` sebelum semua revokasi target terverifikasi. Retry pertama berjalan setelah 5 detik, lalu memakai backoff sampai maksimum 5 menit. Mulai kegagalan ketiga, setiap retry mencatat log `error` berlevel alert; setelah verifikasi berhasil, log `info` memberi sinyal untuk menyelesaikan eskalasi. Alert-routing eksternal harus dikonfigurasi di deployment. Setelah semua key terkait tidak lagi terbaca di origin, report berubah menjadi `Action taken`.

Respons API cover juga mengirim `CDN-Cache-Control: no-store` dan `Surrogate-Control: no-store`; CDN/proxy bersama tetap harus melewati cache untuk jalur tersebut. Saat outbox berstatus pending, jangan menyatakan URL lama sudah dicabut: key sumber masih dapat diakses melalui URL bertanda tangan sampai penghapusan terverifikasi atau URL itu mencapai expiry aslinya. Konfigurasi kode menerima TTL 60–900 detik (default 300 detik); untuk URL lama, waktu expiry persis hanya dapat dipastikan dari URL dan konfigurasi saat URL diterbitkan. Retry penghapusan terus berlanjut tanpa batas sampai berhasil. Cache CDN/browser, transfer yang sudah dimulai, dan bytes yang telah diunduh dapat bertahan lebih lama atau tidak terbatas; purge cache dan batas residual hanya dapat ditetapkan dari pengujian deployment.

AWS documents strong read-after-write behavior for S3 object deletes, while presigned URLs are checked when each request begins and an already-started transfer can continue ([S3 consistency](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html), [presigned URL behavior](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)). CloudFront invalidation removes edge copies, but a viewer or corporate proxy may still retain a cached response ([CloudFront invalidation](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Invalidation.html)). These AWS guarantees are not proof that an arbitrary S3-compatible provider or the deployed CDN behaves the same way; no real-provider or warmed-cache behavior is claimed as verified.

Roles `moderator`, `support`, and `security` are separate and are not inherited from `admin`; they are stored in the database, never trusted from token/body input, and must be granted through a controlled process. Moderation actions store a reason and audit metadata. Require MFA for staff roles in the IdP and do not enable internal queues before response owners are assigned.

Database tidak memuat profil, cerita, audience count, atau kutipan demo. Bila fixture diperlukan untuk staging, gunakan data fiktif yang diberi label jelas, tanpa angka audiens/kutipan rekaan, tanpa kredensial produksi, dan dengan akun uji least-privilege. Backend ini belum menerima field tautan eksternal buatan pengguna; jika ditambahkan kemudian, validasi hanya skema `https:` (atau allowlist yang disetujui) dan tampilkan domain tujuan dengan jelas.

The backend API provides beta feedback and security/privacy reports through separate private tables; they never enter community feeds/public analytics, and no email is sent. **These intake routes are not connected to the current development preview**, so it must not be used to accept real reports or feedback. Once integrated, a submission returns a random case ID, initial `Received` status, and a protected status URL. Status labels are `Received`, `Under review`, `Removal pending`, `Action taken`, `No violation found`, and `Closed`; while removal is pending, the case remains open as `reviewing` and cannot be completed. Responses do not promise a deadline, reveal action against another account, or offer appeals. No notification integration exists; any future notification must be generic and direct the user to sign in, never include sensitive details. Feedback categories are bug, usability, performance/reliability, content/safety, and feature request; bug-specific fields are conditional. Screenshots are never auto-attached: only an explicitly selected PNG/JPEG/WebP up to 2 MiB is accepted, re-encoded to strip metadata, kept in a private bucket, and accessible only to support through short-lived audited URLs. Upload URLs address server-generated `pending/` keys only; completion re-encodes the bytes to a separate `ready/` key so an unexpired signed PUT cannot overwrite a ready asset. Configure object-storage lifecycle deletion for the `pending/` prefix after one day. Retention defaults: feedback 90 days, security/privacy reports 180 days, staff access audit 365 days. Run `npm run cleanup:feedback` at least daily.

## Verification and remaining gates

- **PostgreSQL-backed local retest (2026-10-08):** From a fresh disposable PostgreSQL database, all migrations applied; `npm run typecheck`, `npm run build`, and `RUN_INTEGRATION_TESTS=1 npm test` passed. The suite passed **19/19 tests** (14 unit/API/storage and 5 PostgreSQL integration) and produced **83/83 PASS** request-level checks in the git-ignored `artifacts/security-matrix.json`. Coverage includes committed `202` removal-pending responses, open reporter/moderator cases, denial of premature closure, fail-closed API access, a still-live shared Story, three failed retries with durable escalation, and completion only after successful delete plus origin `HEAD` verification. Copy failure still rolls back the moderation action. A local S3 HTTP emulator verifies that an old signed URL remains usable after an ineffective delete and fails only after source absence is confirmed; the new key remains readable. These fakes are not real S3/CDN evidence and do not sign off staging.
- **Frontend local verification:** typecheck, lint, and Next.js production build passed. The development preview has read-only backend integration for Discover/Story/cover; Write/Publish/account/feedback/reports remain disconnected or local. This does not verify authenticated or staging behavior, including live suspension propagation.
- The ordinary `npm test` command currently reports **14 passed and 5 skipped** because PostgreSQL integration tests are opt-in; with a disposable `DATABASE_URL` and `RUN_INTEGRATION_TESTS=1`, all **19/19** pass. GitHub Actions provisions disposable PostgreSQL and uploads minimal evidence when CI runs.
- **Dependency audit:** after upgrading to Vitest **5.0.3**, both full `npm audit` and `npm audit --omit=dev` report **0 vulnerabilities** in the current lockfile. GitHub Actions now runs `npm audit --audit-level=low` after `npm ci --no-audit`; it audits the complete lockfile, including dev dependencies, and fails CI on any vulnerability. The local result does not replace successful CI or staging dependency verification.
- **Not verified:** a real OIDC provider, actual S3 object upload/download/promotion/rotation, Docker Compose execution, CDN cache-bypass/invalidation behavior, and staging verification with the frontend. Upload URL signing was exercised using fictional local test credentials; no real bucket or production credentials were used. While deletion is pending, the old key is not claimed revoked; its signed URL remains usable until verified deletion or its original expiry. The configured signing TTL range is 60–900 seconds (default 300), but exact legacy expiry depends on the URL and settings at issuance. A warm CDN/browser cache, an in-progress transfer, or downloaded bytes may remain accessible after origin denial. Provider behavior and cache residual must be measured in staging; no deployment-wide residual-access maximum is established. Beta remains blocked.
- Keep beta intake closed until authenticated frontend/backend flows and staging access, privacy, screenshot, and escalation checks pass. The development preview remains partly prototype-only; use the [runbook](./RUNBOOK.md) and [staging checklist](./SECURITY_STAGING_CHECKLIST.md).
