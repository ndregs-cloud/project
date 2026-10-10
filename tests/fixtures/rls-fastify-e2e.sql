-- Fastify/RLS E2E compatibility helpers — DISPOSABLE POSTGRESQL 17 DATABASE ONLY.
-- Apply after local migrations 001-003 and rls-policy-prototype.sql. Never use remotely.
-- psql variables runtime_login, runtime_password, limiter_login, limiter_password,
-- worker_login and worker_password
-- must be unique disposable values; this file does not alter canonical migrations.

BEGIN;

DO $probe_roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='anon') THEN
    CREATE ROLE anon NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='authenticated') THEN
    CREATE ROLE authenticated NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='nova_unrelated_acl_probe') THEN
    CREATE ROLE nova_unrelated_acl_probe NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
END
$probe_roles$;
ALTER ROLE anon NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
ALTER ROLE authenticated NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
ALTER ROLE nova_unrelated_acl_probe NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;

DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='nova_auth_identity_owner') THEN
    CREATE ROLE nova_auth_identity_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
END
$role$;

ALTER ROLE nova_auth_identity_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT USAGE ON SCHEMA public TO nova_auth_identity_owner;
GRANT SELECT (id, auth_subject, username, role, status),
      INSERT (auth_subject, username, username_normalized)
  ON public.users TO nova_auth_identity_owner;

DROP POLICY IF EXISTS users_identity_bootstrap_select ON public.users;
DROP POLICY IF EXISTS users_identity_bootstrap_insert ON public.users;
CREATE POLICY users_identity_bootstrap_select ON public.users FOR SELECT TO nova_auth_identity_owner
  USING (current_user='nova_auth_identity_owner'
    AND auth_subject=NULLIF(pg_catalog.btrim(pg_catalog.current_setting('app.auth_subject',true)),''));
CREATE POLICY users_identity_bootstrap_insert ON public.users FOR INSERT TO nova_auth_identity_owner
  WITH CHECK (current_user='nova_auth_identity_owner'
    AND auth_subject=NULLIF(pg_catalog.btrim(pg_catalog.current_setting('app.auth_subject',true)),'')
    AND role::text='reader' AND status::text='active');

CREATE OR REPLACE FUNCTION public.nova_auth_bootstrap_identity(p_generated_username text)
RETURNS TABLE(id uuid, subject text, username text, role text, status text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE
  v_subject text;
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members membership
    JOIN pg_catalog.pg_roles login_role ON login_role.oid=membership.member
    JOIN pg_catalog.pg_roles runtime_role ON runtime_role.oid=membership.roleid
    WHERE runtime_role.rolname='nova_fastify_runtime'
      AND login_role.rolname=session_user
      AND login_role.rolcanlogin AND NOT login_role.rolinherit
      AND NOT login_role.rolsuper AND NOT login_role.rolbypassrls
      AND NOT login_role.rolcreaterole AND NOT login_role.rolcreatedb AND NOT login_role.rolreplication
      AND NOT membership.inherit_option AND membership.set_option AND NOT membership.admin_option
      AND NOT runtime_role.rolcanlogin AND NOT runtime_role.rolinherit
      AND NOT runtime_role.rolsuper AND NOT runtime_role.rolbypassrls
      AND NOT runtime_role.rolcreaterole AND NOT runtime_role.rolcreatedb AND NOT runtime_role.rolreplication
      AND (SELECT pg_catalog.count(*) FROM pg_catalog.pg_auth_members direct
           WHERE direct.member=login_role.oid)=1
      AND (SELECT pg_catalog.count(*) FROM pg_catalog.pg_auth_members wrappers
           WHERE wrappers.roleid=runtime_role.oid)=1
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members nested
           WHERE nested.member=runtime_role.oid)
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members assigned
           WHERE assigned.roleid=login_role.oid)
  ) THEN
    RAISE EXCEPTION 'identity bootstrap denied' USING ERRCODE='42501';
  END IF;
  v_subject := NULLIF(pg_catalog.btrim(pg_catalog.current_setting('app.auth_subject',true)),'');
  IF v_subject IS NULL OR pg_catalog.length(v_subject)>512
     OR p_generated_username !~ '^reader_[a-f0-9]{20}$' THEN
    RAISE EXCEPTION 'identity bootstrap denied' USING ERRCODE='42501';
  END IF;

  INSERT INTO public.users(auth_subject,username,username_normalized)
  VALUES(v_subject,p_generated_username,pg_catalog.lower(p_generated_username))
  ON CONFLICT(auth_subject) DO NOTHING;

  RETURN QUERY
    SELECT u.id,u.auth_subject::text,u.username::text,u.role::text,u.status::text
    FROM public.users AS u WHERE u.auth_subject=v_subject;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'identity bootstrap denied' USING ERRCODE='42501';
  END IF;
END
$function$;
ALTER FUNCTION public.nova_auth_bootstrap_identity(text) OWNER TO nova_auth_identity_owner;
REVOKE ALL ON FUNCTION public.nova_auth_bootstrap_identity(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_auth_bootstrap_identity(text)
  FROM anon,authenticated,nova_unrelated_acl_probe,nova_rate_limiter_runtime,nova_media_revocation_worker;
GRANT EXECUTE ON FUNCTION public.nova_auth_bootstrap_identity(text) TO nova_fastify_runtime;

REVOKE ALL ON FUNCTION public.nova_rate_limit_record(text,timestamptz)
  FROM PUBLIC,anon,authenticated,nova_unrelated_acl_probe,nova_fastify_runtime,nova_media_revocation_worker;
GRANT EXECUTE ON FUNCTION public.nova_rate_limit_record(text,timestamptz) TO nova_rate_limiter_runtime;

-- The limiter principal has no table privileges. Its only bucket access is the
-- single-key SECURITY DEFINER counter installed by rls-policy-prototype.sql.

-- Disposable NOINHERIT login wrappers can SET ROLE only to their matching
-- principal. The fixture may be loaded into multiple disposable databases on
-- one local cluster, so reuse an existing wrapper role rather than duplicating it.
SELECT pg_catalog.format(
  CASE WHEN EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=:'runtime_login')
    THEN 'ALTER ROLE %I WITH LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L'
    ELSE 'CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L'
  END,
  :'runtime_login', :'runtime_password') \gexec
SELECT pg_catalog.format('GRANT nova_fastify_runtime TO %I WITH INHERIT FALSE, SET TRUE, ADMIN FALSE', :'runtime_login') \gexec
SELECT pg_catalog.format(
  CASE WHEN EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=:'limiter_login')
    THEN 'ALTER ROLE %I WITH LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L'
    ELSE 'CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L'
  END,
  :'limiter_login', :'limiter_password') \gexec
SELECT pg_catalog.format('GRANT nova_rate_limiter_runtime TO %I WITH INHERIT FALSE, SET TRUE, ADMIN FALSE', :'limiter_login') \gexec
SELECT pg_catalog.format(
  CASE WHEN EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=:'worker_login')
    THEN 'ALTER ROLE %I WITH LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L'
    ELSE 'CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L'
  END,
  :'worker_login', :'worker_password') \gexec
SELECT pg_catalog.format('GRANT nova_media_revocation_worker TO %I WITH INHERIT FALSE, SET TRUE, ADMIN FALSE', :'worker_login') \gexec

-- Fixed disposable actors/assets let the full Fastify test exercise an atomic hide+enqueue.
INSERT INTO public.users(id,auth_subject,username,username_normalized,role,status) VALUES
  ('e1000000-0000-4000-8000-000000000001','nova-rls-e2e:moderator','e2e_moderator','e2e_moderator','moderator','active'),
  ('e1000000-0000-4000-8000-000000000002','nova-rls-e2e:cover-owner','e2e_cover_owner','e2e_cover_owner','reader','active')
ON CONFLICT (id) DO NOTHING;
INSERT INTO public.media_assets(id,owner_id,purpose,object_key,mime_type,size_bytes,checksum,status,ready_at) VALUES
  ('e2000000-0000-4000-8000-000000000001','e1000000-0000-4000-8000-000000000002','cover',
   'ready/e1000000-0000-4000-8000-000000000002/e2000000-0000-4000-8000-000000000001.jpg',
   'image/jpeg',512,repeat('a',64),'ready',pg_catalog.now()),
  ('e2000000-0000-4000-8000-000000000002','e1000000-0000-4000-8000-000000000002','cover',
   'ready/e1000000-0000-4000-8000-000000000002/e2000000-0000-4000-8000-000000000002.jpg',
   'image/jpeg',512,repeat('b',64),'ready',pg_catalog.now()),
  ('e2000000-0000-4000-8000-000000000003','e1000000-0000-4000-8000-000000000002','cover',
   'ready/e1000000-0000-4000-8000-000000000002/e2000000-0000-4000-8000-000000000003.jpg',
   'image/jpeg',512,repeat('c',64),'ready',pg_catalog.now())
ON CONFLICT (id) DO NOTHING;
INSERT INTO public.stories(id,author_id,title,slug,summary,body,status,visibility,version,published_at,cover_media_id,comments_open) VALUES
  ('e3000000-0000-4000-8000-000000000001','e1000000-0000-4000-8000-000000000002',
   'Disposable cover moderation story','disposable-cover-moderation','',
   'Local test content only.','published','public',1,pg_catalog.now(),
   'e2000000-0000-4000-8000-000000000001',true),
  ('e3000000-0000-4000-8000-000000000002','e1000000-0000-4000-8000-000000000002',
   'Disposable no-media restore story','disposable-no-media-restore','',
   'Local test content only.','published','public',1,pg_catalog.now(),NULL,false),
  ('e3000000-0000-4000-8000-000000000003','e1000000-0000-4000-8000-000000000002',
   'Disposable publish contract story','disposable-publish-contract','',
   'Local test content only.','draft','private',1,NULL,NULL,false),
  ('e3000000-0000-4000-8000-000000000004','e1000000-0000-4000-8000-000000000002',
   'Disposable acknowledged-commit story','disposable-acknowledged-commit','',
   'Local test content only.','published','public',1,pg_catalog.now(),
   'e2000000-0000-4000-8000-000000000002',true),
  ('e3000000-0000-4000-8000-000000000005','e1000000-0000-4000-8000-000000000002',
   'Disposable unresolved-commit story','disposable-unresolved-commit','',
   'Local test content only.','published','public',1,pg_catalog.now(),
   'e2000000-0000-4000-8000-000000000003',true)
ON CONFLICT (id) DO NOTHING;
INSERT INTO public.comments(id,story_id,author_id,body,status) VALUES
  ('e5000000-0000-4000-8000-000000000001','e3000000-0000-4000-8000-000000000001',
   'e1000000-0000-4000-8000-000000000002','Disposable comment for moderation guard','visible')
ON CONFLICT (id) DO NOTHING;
INSERT INTO public.reports(id,reporter_id,target_type,target_id,reason,details,status) VALUES
  ('e6000000-0000-4000-8000-000000000001','e1000000-0000-4000-8000-000000000002','story',
   'e3000000-0000-4000-8000-000000000001','other','Local fixture only.','received'),
  ('e6000000-0000-4000-8000-000000000002','e1000000-0000-4000-8000-000000000002','story',
   'e3000000-0000-4000-8000-000000000002','other','Open restore-conflict fixture only.','reviewing'),
  ('e6000000-0000-4000-8000-000000000003','e1000000-0000-4000-8000-000000000002','story',
   'e3000000-0000-4000-8000-000000000004','other','Local fixture only.','received'),
  ('e6000000-0000-4000-8000-000000000004','e1000000-0000-4000-8000-000000000002','story',
   'e3000000-0000-4000-8000-000000000005','other','Local fixture only.','received')
ON CONFLICT (id) DO NOTHING;

COMMIT;
