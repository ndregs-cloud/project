-- NOVA PostgreSQL 17 RLS prototype — DISPOSABLE DATABASE ONLY.
-- Run only as a superuser against a disposable database after migrations 001-003.
-- This file changes roles, default privileges, grants, triggers, and policies in that
-- database. It contains no remote URL and must NOT be applied to production/Supabase.
-- Source analyses are local design inputs only; they do not establish deployed state.
--
-- Fail closed: absent/blank/malformed identity GUCs do not authorize private access.
-- The current Fastify pool does not consistently set transaction-local identity; see
-- the companion Markdown and do not treat this fixture as deployable until that is fixed.

BEGIN;

-- Disposable-only attempt token: each processing generation gets a fresh nonce.
ALTER TABLE public.media_assets ADD COLUMN upload_nonce uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid();

-- Roles can be SET ROLE'd from the superuser session for local tests. Worker roles are
-- separate NOLOGIN principals; never grant worker membership/SET ROLE to the API role.
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_fastify_runtime') THEN
    CREATE ROLE nova_fastify_runtime NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_tag_catalog_writer') THEN
    CREATE ROLE nova_tag_catalog_writer NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_rate_limiter_runtime') THEN
    CREATE ROLE nova_rate_limiter_runtime NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_rate_limit_counter_owner') THEN
    CREATE ROLE nova_rate_limit_counter_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_media_revocation_worker') THEN
    CREATE ROLE nova_media_revocation_worker NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_reports_worker') THEN
    CREATE ROLE nova_reports_worker NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_feedback_cleanup') THEN
    CREATE ROLE nova_feedback_cleanup NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_security_reports_cleanup') THEN
    CREATE ROLE nova_security_reports_cleanup NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_audit_cleanup') THEN
    CREATE ROLE nova_audit_cleanup NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_fixture_migration_owner') THEN
    CREATE ROLE nova_fixture_migration_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_story_lifecycle_manager') THEN
    CREATE ROLE nova_story_lifecycle_manager NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_media_lifecycle_manager') THEN
    CREATE ROLE nova_media_lifecycle_manager NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_actor_predicate_owner') THEN
    CREATE ROLE nova_actor_predicate_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_media_state_predicate_owner') THEN
    CREATE ROLE nova_media_state_predicate_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_action_predicate_owner') THEN
    CREATE ROLE nova_action_predicate_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_media_predicate_owner') THEN
    CREATE ROLE nova_media_predicate_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_reports_predicate_owner') THEN
    CREATE ROLE nova_reports_predicate_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_media_reference_guard_owner') THEN
    CREATE ROLE nova_media_reference_guard_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_revocation_enqueuer_owner') THEN
    CREATE ROLE nova_revocation_enqueuer_owner NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_story_moderation_manager') THEN
    CREATE ROLE nova_story_moderation_manager NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_media_upload_verifier') THEN
    CREATE ROLE nova_media_upload_verifier NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_media_upload_gateway') THEN
    CREATE ROLE nova_media_upload_gateway NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_media_purge_verifier') THEN
    CREATE ROLE nova_media_purge_verifier NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_media_purge_gateway') THEN
    CREATE ROLE nova_media_purge_gateway NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_media_purge_attester') THEN
    CREATE ROLE nova_media_purge_attester NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nova_media_removal_authority') THEN
    CREATE ROLE nova_media_removal_authority NOLOGIN;
  END IF;
END
$roles$;

ALTER ROLE nova_fastify_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
ALTER ROLE nova_tag_catalog_writer NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_rate_limiter_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
ALTER ROLE nova_rate_limit_counter_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
ALTER ROLE nova_media_revocation_worker NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
ALTER ROLE nova_reports_worker NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_feedback_cleanup NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_security_reports_cleanup NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_audit_cleanup NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_fixture_migration_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_story_lifecycle_manager NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_media_lifecycle_manager NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_actor_predicate_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_media_state_predicate_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_action_predicate_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_media_predicate_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_reports_predicate_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_media_reference_guard_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_revocation_enqueuer_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_story_moderation_manager NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_media_upload_verifier NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_media_upload_gateway NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_media_purge_verifier NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_media_purge_gateway NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_media_purge_attester NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
ALTER ROLE nova_media_removal_authority NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

-- Remove stale role paths in this disposable fixture before re-granting its narrow surface.
DO $membership_reset$
DECLARE m record;
BEGIN
  FOR m IN
    SELECT granted.rolname AS granted_role, member.rolname AS member_role
    FROM pg_auth_members am
    JOIN pg_roles granted ON granted.oid=am.roleid
    JOIN pg_roles member ON member.oid=am.member
    WHERE granted.rolname IN ('nova_media_upload_gateway','nova_media_upload_verifier',
      'nova_media_purge_gateway','nova_media_purge_verifier','nova_media_purge_attester','nova_media_removal_authority')
       OR member.rolname IN ('nova_media_upload_gateway','nova_media_upload_verifier',
      'nova_media_purge_gateway','nova_media_purge_verifier','nova_media_purge_attester','nova_media_removal_authority')
  LOOP
    EXECUTE pg_catalog.format('REVOKE %I FROM %I',m.granted_role,m.member_role);
  END LOOP;
END
$membership_reset$;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM nova_media_upload_gateway,nova_media_upload_verifier,
  nova_media_purge_gateway,nova_media_purge_verifier,nova_media_purge_attester,nova_media_removal_authority;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM nova_media_upload_gateway,nova_media_upload_verifier,
  nova_media_purge_gateway,nova_media_purge_verifier,nova_media_purge_attester,nova_media_removal_authority;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM nova_media_upload_gateway,nova_media_upload_verifier,
  nova_media_purge_gateway,nova_media_purge_verifier,nova_media_purge_attester,nova_media_removal_authority;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO nova_fastify_runtime, nova_tag_catalog_writer,
  nova_rate_limiter_runtime, nova_rate_limit_counter_owner, nova_media_revocation_worker, nova_reports_worker,
  nova_feedback_cleanup, nova_security_reports_cleanup, nova_audit_cleanup,
  nova_story_lifecycle_manager, nova_media_lifecycle_manager, nova_fixture_migration_owner,
  nova_actor_predicate_owner, nova_media_state_predicate_owner, nova_action_predicate_owner,
  nova_media_predicate_owner, nova_reports_predicate_owner, nova_media_reference_guard_owner,
  nova_revocation_enqueuer_owner, nova_story_moderation_manager, nova_media_upload_verifier,nova_media_upload_gateway,
  nova_media_purge_verifier, nova_media_purge_gateway,nova_media_purge_attester,nova_media_removal_authority;
GRANT CREATE ON SCHEMA public TO nova_fixture_migration_owner;
GRANT CREATE ON SCHEMA public TO nova_story_lifecycle_manager,nova_media_lifecycle_manager,
  nova_actor_predicate_owner,nova_media_state_predicate_owner,nova_action_predicate_owner,
  nova_media_predicate_owner,nova_reports_predicate_owner,nova_media_reference_guard_owner,
  nova_revocation_enqueuer_owner,nova_story_moderation_manager;

-- Test defaults for a named disposable migration-owner role. This deliberately does not
-- guess the DDL owner used by any remote deployment.
ALTER DEFAULT PRIVILEGES FOR ROLE nova_fixture_migration_owner IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC, nova_fastify_runtime, nova_tag_catalog_writer,
    nova_rate_limiter_runtime, nova_media_revocation_worker, nova_reports_worker,
    nova_feedback_cleanup, nova_security_reports_cleanup, nova_audit_cleanup,
    nova_story_lifecycle_manager, nova_media_lifecycle_manager, nova_actor_predicate_owner,
    nova_media_state_predicate_owner, nova_action_predicate_owner, nova_media_predicate_owner,
    nova_reports_predicate_owner, nova_media_reference_guard_owner, nova_revocation_enqueuer_owner,
    nova_story_moderation_manager, nova_media_upload_verifier,nova_media_upload_gateway,
    nova_media_purge_verifier,nova_media_purge_gateway,nova_media_purge_attester,nova_media_removal_authority;
ALTER DEFAULT PRIVILEGES FOR ROLE nova_fixture_migration_owner IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC, nova_fastify_runtime, nova_tag_catalog_writer,
    nova_rate_limiter_runtime, nova_media_revocation_worker, nova_reports_worker,
    nova_feedback_cleanup, nova_security_reports_cleanup, nova_audit_cleanup,
    nova_story_lifecycle_manager, nova_media_lifecycle_manager, nova_actor_predicate_owner,
    nova_media_state_predicate_owner, nova_action_predicate_owner, nova_media_predicate_owner,
    nova_reports_predicate_owner, nova_media_reference_guard_owner, nova_revocation_enqueuer_owner,
    nova_story_moderation_manager, nova_media_upload_verifier,nova_media_upload_gateway,
    nova_media_purge_verifier,nova_media_purge_gateway,nova_media_purge_attester,nova_media_removal_authority;
-- Function EXECUTE is granted to PUBLIC by PostgreSQL's global defaults, so that
-- revoke must be global for this test owner; the other role revokes remain schema-local.
ALTER DEFAULT PRIVILEGES FOR ROLE nova_fixture_migration_owner
  REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE nova_fixture_migration_owner IN SCHEMA public
  REVOKE ALL ON FUNCTIONS FROM nova_fastify_runtime, nova_tag_catalog_writer,
    nova_rate_limiter_runtime, nova_media_revocation_worker, nova_reports_worker,
    nova_feedback_cleanup, nova_security_reports_cleanup, nova_audit_cleanup,
    nova_story_lifecycle_manager, nova_media_lifecycle_manager, nova_actor_predicate_owner,
    nova_media_state_predicate_owner, nova_action_predicate_owner, nova_media_predicate_owner,
    nova_reports_predicate_owner, nova_media_reference_guard_owner, nova_revocation_enqueuer_owner,
    nova_story_moderation_manager, nova_media_upload_verifier,nova_media_upload_gateway,
    nova_media_purge_verifier,nova_media_purge_gateway,nova_media_purge_attester,nova_media_removal_authority;

-- Safe context helpers. The UUID parser never casts absent, blank, or malformed text.
-- The SECURITY DEFINER checks are narrow boolean predicates; they avoid granting runtime
-- SELECT on users.auth_subject or users.role. The final fixture block assigns each definer
-- to a narrow NOLOGIN owner; fixed search_path and qualified names are deliberate.
CREATE OR REPLACE FUNCTION public.nova_rls_uid()
RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE
AS $$
  SELECT CASE WHEN x ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
              THEN x::uuid ELSE NULL::uuid END
  FROM (SELECT NULLIF(btrim(current_setting('app.user_id', true)), '') AS x) AS c
$$;

CREATE OR REPLACE FUNCTION public.nova_rls_subject()
RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT NULLIF(btrim(current_setting('app.auth_subject', true)), '') $$;

CREATE OR REPLACE FUNCTION public.nova_rls_actor_active()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.users AS u
    WHERE u.id = public.nova_rls_uid()
      AND u.auth_subject = public.nova_rls_subject()
      AND u.status::text = 'active'
  )
$$;

CREATE OR REPLACE FUNCTION public.nova_rls_actor_has_role(allowed text[])
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.users AS u
    WHERE u.id = public.nova_rls_uid()
      AND u.auth_subject = public.nova_rls_subject()
      AND u.status::text = 'active'
      AND u.role::text = NULLIF(btrim(current_setting('app.user_role', true)), '')
      AND u.role::text = ANY(allowed)
  )
$$;

REVOKE ALL ON FUNCTION public.nova_rls_uid() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_rls_subject() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_rls_actor_active() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_rls_actor_has_role(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.nova_rls_uid() TO nova_fastify_runtime;
GRANT EXECUTE ON FUNCTION public.nova_rls_subject() TO nova_fastify_runtime;
GRANT EXECUTE ON FUNCTION public.nova_rls_actor_active() TO nova_fastify_runtime;
GRANT EXECUTE ON FUNCTION public.nova_rls_actor_has_role(text[]) TO nova_fastify_runtime;

-- This boolean lookup is intentionally scoped to media owned by the active caller;
-- it cannot be used as a pending-state oracle for arbitrary UUIDs.
CREATE OR REPLACE FUNCTION public.nova_rls_own_media_revocation_pending(target uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.media_assets m
    JOIN public.users u ON u.id = m.owner_id
    WHERE pg_catalog.pg_has_role(session_user,'nova_fastify_runtime','SET')
      AND public.nova_rls_actor_active()
      AND public.nova_rls_actor_has_role(ARRAY['reader','moderator','support','security','admin'])
      AND m.id = target AND m.owner_id = public.nova_rls_uid()
      AND u.auth_subject = public.nova_rls_subject() AND u.status::text = 'active'
      AND EXISTS (SELECT 1 FROM public.media_key_revocations r WHERE r.media_id = m.id)
  )
$$;
REVOKE ALL ON FUNCTION public.nova_rls_own_media_revocation_pending(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.nova_rls_own_media_revocation_pending(uuid) TO nova_fastify_runtime;

-- Internal relationship predicates are installed before the policies that call them.
-- They are not public API lookups and their EXECUTE grants are narrowed below.
CREATE OR REPLACE FUNCTION public.nova_rls_valid_moderation_action(p_action_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.moderation_actions a
    WHERE a.id=p_action_id AND a.action='hide_story' AND a.target_type::text='story'
      AND EXISTS (SELECT 1 FROM public.stories s WHERE s.id=a.target_id AND s.status::text='removed'
        AND s.visibility::text='private' AND s.deleted_at IS NULL)
  )
$$;
CREATE OR REPLACE FUNCTION public.nova_rls_valid_media_revocation(
  p_media_id uuid,p_source_key text,p_action_id uuid
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $media_valid$
DECLARE v_action record; v_media record; v_ext text;
BEGIN
  IF p_media_id IS NULL OR p_source_key IS NULL OR p_action_id IS NULL THEN RETURN false; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_media_action_id',p_action_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_media_id',p_media_id::text,true);
  SELECT id,action,target_type,target_id INTO v_action FROM public.moderation_actions WHERE id=p_action_id;
  IF NOT FOUND OR v_action.action<>'hide_story' OR v_action.target_type::text<>'story' THEN RETURN false; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_media_story_id',v_action.target_id::text,true);
  SELECT id,owner_id,purpose,status,mime_type INTO v_media FROM public.media_assets WHERE id=p_media_id;
  IF NOT FOUND OR v_media.purpose<>'cover' OR v_media.status::text<>'ready' THEN RETURN false; END IF;
  v_ext:=CASE v_media.mime_type WHEN 'image/jpeg' THEN 'jpg' WHEN 'image/png' THEN 'png' WHEN 'image/webp' THEN 'webp' END;
  IF p_source_key IS DISTINCT FROM 'ready/'||v_media.owner_id::text||'/'||v_media.id::text||'.'||v_ext THEN RETURN false; END IF;
  RETURN EXISTS (SELECT 1 FROM public.stories s WHERE s.id=v_action.target_id
    AND s.cover_media_id=v_media.id AND s.author_id=v_media.owner_id
    AND s.status::text='removed' AND s.visibility::text='private' AND s.deleted_at IS NULL);
END $media_valid$;
CREATE OR REPLACE FUNCTION public.nova_rls_valid_media_revocation(
  p_revocation_id uuid,p_media_id uuid,p_source_key text,p_action_id uuid
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v_queue record; v_action record; v_media record; v_ext text;
BEGIN
  IF p_revocation_id IS NULL OR p_media_id IS NULL OR p_action_id IS NULL OR p_source_key IS NULL THEN RETURN false; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_media_revocation_id',p_revocation_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_media_action_id',p_action_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_media_id',p_media_id::text,true);
  SELECT id,media_id,source_key,moderation_action_id INTO v_queue
    FROM public.media_key_revocations WHERE id=p_revocation_id;
  IF NOT FOUND OR (v_queue.media_id,v_queue.source_key,v_queue.moderation_action_id)
      IS DISTINCT FROM (p_media_id,p_source_key,p_action_id) THEN RETURN false; END IF;
  SELECT id,action,target_type,target_id INTO v_action FROM public.moderation_actions WHERE id=p_action_id;
  IF NOT FOUND OR v_action.action<>'hide_story' OR v_action.target_type::text<>'story' THEN RETURN false; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_media_story_id',v_action.target_id::text,true);
  SELECT id,owner_id,purpose,status,mime_type INTO v_media FROM public.media_assets WHERE id=p_media_id;
  IF NOT FOUND OR v_media.purpose<>'cover' OR v_media.status::text<>'ready' THEN RETURN false; END IF;
  v_ext:=CASE v_media.mime_type WHEN 'image/jpeg' THEN 'jpg' WHEN 'image/png' THEN 'png' WHEN 'image/webp' THEN 'webp' END;
  IF p_source_key IS DISTINCT FROM 'ready/'||v_media.owner_id::text||'/'||v_media.id::text||'.'||v_ext THEN RETURN false; END IF;
  RETURN EXISTS (SELECT 1 FROM public.stories s WHERE s.id=v_action.target_id
    AND s.cover_media_id=v_media.id AND s.author_id=v_media.owner_id
    AND s.status::text='removed' AND s.visibility::text='private' AND s.deleted_at IS NULL);
END $$;
CREATE OR REPLACE FUNCTION public.nova_rls_valid_report_target(
  p_target_type report_target_type,p_target_id uuid
) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $report_target$
DECLARE v_action record;
BEGIN
  IF p_target_type::text<>'story' OR p_target_id IS NULL THEN RETURN false; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_reports_target_type',p_target_type::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_reports_target_id',p_target_id::text,true);
  SELECT id,action,target_type,target_id INTO v_action FROM public.moderation_actions
    WHERE target_type::text=p_target_type::text AND target_id=p_target_id AND action='hide_story';
  IF NOT FOUND OR v_action.target_type::text<>'story' OR v_action.target_id<>p_target_id THEN RETURN false; END IF;
  RETURN EXISTS (SELECT 1 FROM public.stories s WHERE s.id=p_target_id
    AND s.status::text='removed' AND s.visibility::text='private' AND s.deleted_at IS NULL);
END $report_target$;
CREATE OR REPLACE FUNCTION public.nova_rls_target_has_pending_revocation(
  p_target_type report_target_type,p_target_id uuid
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT EXISTS (SELECT 1 FROM public.media_key_revocations r
    JOIN public.moderation_actions a ON a.id=r.moderation_action_id
    WHERE a.target_type=p_target_type AND a.target_id=p_target_id
      AND public.nova_rls_valid_media_revocation(r.id,r.media_id,r.source_key,r.moderation_action_id))
$$;

-- In a disposable fixture, remove every prior policy on the 15 in-scope tables so an
-- unknown permissive policy cannot OR-open access. This is intentionally destructive
-- to policy metadata on these tables only; it does not touch application migrations.
DO $drop_policies$
DECLARE t text; p record;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'users','media_assets','tags','stories','story_tags','follows','bookmarks','comments',
    'reports','moderation_actions','beta_feedback','security_reports','staff_access_audit',
    'rate_limit_buckets','media_key_revocations'
  ] LOOP
    FOR p IN SELECT polname FROM pg_policy
             WHERE polrelid = to_regclass(format('public.%I', t))
    LOOP
      EXECUTE format('DROP POLICY %I ON public.%I', p.polname, t);
    END LOOP;
  END LOOP;
END
$drop_policies$;

-- Clear direct grants on fixture tables. No memberships are granted below.
REVOKE ALL PRIVILEGES ON TABLE public.users, public.media_assets, public.tags,
  public.stories, public.story_tags, public.follows, public.bookmarks, public.comments,
  public.reports, public.moderation_actions, public.beta_feedback, public.security_reports,
  public.staff_access_audit, public.rate_limit_buckets, public.media_key_revocations
  FROM PUBLIC, nova_fastify_runtime, nova_tag_catalog_writer, nova_rate_limiter_runtime,nova_rate_limit_counter_owner,
       nova_media_revocation_worker, nova_reports_worker, nova_feedback_cleanup,
       nova_security_reports_cleanup, nova_audit_cleanup, nova_story_lifecycle_manager,
       nova_media_lifecycle_manager, nova_fixture_migration_owner;

-- Apply ENABLE + FORCE to every protected table.
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY; ALTER TABLE public.users FORCE ROW LEVEL SECURITY;
ALTER TABLE public.media_assets ENABLE ROW LEVEL SECURITY; ALTER TABLE public.media_assets FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tags ENABLE ROW LEVEL SECURITY; ALTER TABLE public.tags FORCE ROW LEVEL SECURITY;
ALTER TABLE public.stories ENABLE ROW LEVEL SECURITY; ALTER TABLE public.stories FORCE ROW LEVEL SECURITY;
ALTER TABLE public.story_tags ENABLE ROW LEVEL SECURITY; ALTER TABLE public.story_tags FORCE ROW LEVEL SECURITY;
ALTER TABLE public.follows ENABLE ROW LEVEL SECURITY; ALTER TABLE public.follows FORCE ROW LEVEL SECURITY;
ALTER TABLE public.bookmarks ENABLE ROW LEVEL SECURITY; ALTER TABLE public.bookmarks FORCE ROW LEVEL SECURITY;
ALTER TABLE public.comments ENABLE ROW LEVEL SECURITY; ALTER TABLE public.comments FORCE ROW LEVEL SECURITY;
ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY; ALTER TABLE public.reports FORCE ROW LEVEL SECURITY;
ALTER TABLE public.moderation_actions ENABLE ROW LEVEL SECURITY; ALTER TABLE public.moderation_actions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.beta_feedback ENABLE ROW LEVEL SECURITY; ALTER TABLE public.beta_feedback FORCE ROW LEVEL SECURITY;
ALTER TABLE public.security_reports ENABLE ROW LEVEL SECURITY; ALTER TABLE public.security_reports FORCE ROW LEVEL SECURITY;
ALTER TABLE public.staff_access_audit ENABLE ROW LEVEL SECURITY; ALTER TABLE public.staff_access_audit FORCE ROW LEVEL SECURITY;
ALTER TABLE public.rate_limit_buckets ENABLE ROW LEVEL SECURITY; ALTER TABLE public.rate_limit_buckets FORCE ROW LEVEL SECURITY;
ALTER TABLE public.media_key_revocations ENABLE ROW LEVEL SECURITY; ALTER TABLE public.media_key_revocations FORCE ROW LEVEL SECURITY;

-- -----------------------------------------------------------------------------
-- USERS
-- -----------------------------------------------------------------------------
GRANT SELECT (id, username, username_normalized, display_name, bio, avatar_media_id,
              status, created_at, updated_at) ON public.users TO nova_fastify_runtime;
GRANT UPDATE (username, username_normalized, display_name, bio, avatar_media_id, updated_at, status)
  ON public.users TO nova_fastify_runtime;
CREATE POLICY users_read_scoped ON public.users FOR SELECT TO nova_fastify_runtime
  USING (status::text = 'active' OR id = public.nova_rls_uid()
         OR (public.nova_rls_actor_has_role(ARRAY['moderator']) AND status::text <> 'deleted'));
CREATE POLICY users_update_self_or_moderator ON public.users FOR UPDATE TO nova_fastify_runtime
  USING ((id = public.nova_rls_uid() AND public.nova_rls_actor_active())
         OR (public.nova_rls_actor_has_role(ARRAY['moderator']) AND status::text <> 'deleted'))
  WITH CHECK ((id = public.nova_rls_uid() AND public.nova_rls_actor_active() AND status::text = 'active')
         OR (public.nova_rls_actor_has_role(ARRAY['moderator']) AND status::text <> 'deleted'));

-- Prevent cross-user profile-column edits through the status grant; moderation can only
-- change status, and the app runtime cannot make a target's deleted status reversible.
CREATE OR REPLACE FUNCTION public.nova_users_update_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF current_user = 'nova_fastify_runtime' AND OLD.id IS DISTINCT FROM public.nova_rls_uid() THEN
    IF NOT public.nova_rls_actor_has_role(ARRAY['moderator'])
       OR OLD.status::text = 'deleted'
       OR NEW.status IS DISTINCT FROM OLD.status
       OR NEW.status::text NOT IN ('active','suspended')
       OR (to_jsonb(NEW) - ARRAY['status','updated_at']) IS DISTINCT FROM
          (to_jsonb(OLD) - ARRAY['status','updated_at']) THEN
      RAISE EXCEPTION 'cross-user user update denied' USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER nova_users_update_guard BEFORE UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.nova_users_update_guard();

-- -----------------------------------------------------------------------------
-- TAGS: public catalogue read; curated writes only via separate migration role.
-- -----------------------------------------------------------------------------
GRANT SELECT ON public.tags TO nova_fastify_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.tags TO nova_tag_catalog_writer;
CREATE POLICY tags_public_read ON public.tags FOR SELECT TO nova_fastify_runtime USING (true);
CREATE POLICY tags_catalog_writer ON public.tags FOR ALL TO nova_tag_catalog_writer
  USING (current_user = 'nova_tag_catalog_writer')
  WITH CHECK (current_user = 'nova_tag_catalog_writer');

-- -----------------------------------------------------------------------------
-- STORIES
-- -----------------------------------------------------------------------------
GRANT SELECT (id, author_id, title, slug, summary, body, status, visibility, version,
              published_at, cover_media_id, comments_open, created_at, updated_at, deleted_at)
  ON public.stories TO nova_fastify_runtime;
GRANT INSERT (id, author_id, title, slug, summary, body, cover_media_id)
  ON public.stories TO nova_fastify_runtime;
GRANT UPDATE (title, summary, body, cover_media_id, version, updated_at, status,
              visibility, published_at, comments_open, deleted_at)
  ON public.stories TO nova_fastify_runtime;
CREATE POLICY stories_read_scoped ON public.stories FOR SELECT TO nova_fastify_runtime
  USING ((status::text = 'published' AND visibility::text = 'public' AND deleted_at IS NULL
          AND EXISTS (SELECT 1 FROM public.users active_author WHERE active_author.id = author_id AND active_author.status::text = 'active'))
         OR (author_id = public.nova_rls_uid() AND public.nova_rls_actor_active())
         OR public.nova_rls_actor_has_role(ARRAY['moderator']));
CREATE POLICY stories_insert_owned_draft ON public.stories FOR INSERT TO nova_fastify_runtime
  WITH CHECK (author_id = public.nova_rls_uid() AND public.nova_rls_actor_active()
              AND status::text = 'draft' AND visibility::text = 'private' AND deleted_at IS NULL);
CREATE POLICY stories_update_owner ON public.stories FOR UPDATE TO nova_fastify_runtime
  USING (author_id = public.nova_rls_uid() AND public.nova_rls_actor_active() AND deleted_at IS NULL)
  WITH CHECK (author_id = public.nova_rls_uid() AND public.nova_rls_actor_active());
CREATE POLICY stories_update_moderator ON public.stories FOR UPDATE TO nova_fastify_runtime
  USING (public.nova_rls_actor_has_role(ARRAY['moderator']))
  WITH CHECK (public.nova_rls_actor_has_role(ARRAY['moderator']));

-- Owners may edit content but must use a controlled transition path to publish,
-- unpublish, or soft-delete. Cross-owner moderation state changes require an atomic
-- hide/restore procedure that creates a linked action in the same transaction.
CREATE OR REPLACE FUNCTION public.nova_stories_update_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE is_owner boolean;
BEGIN
  IF current_user = 'nova_story_moderation_manager' THEN
    RAISE EXCEPTION 'moderation manager guard is finalized below in this fixture transaction' USING ERRCODE = '42501';
  END IF;
  IF current_user = 'nova_story_lifecycle_manager' THEN
    RETURN NEW;
  END IF;
  IF current_user <> 'nova_fastify_runtime' THEN
    RETURN NEW;
  END IF;

  is_owner := OLD.author_id = public.nova_rls_uid() AND public.nova_rls_actor_active();
  IF is_owner THEN
    IF (NEW.status, NEW.visibility, NEW.published_at, NEW.deleted_at) IS DISTINCT FROM
       (OLD.status, OLD.visibility, OLD.published_at, OLD.deleted_at) THEN
      RAISE EXCEPTION 'story lifecycle transition requires the controlled path' USING ERRCODE = '42501';
    END IF;
    IF (to_jsonb(NEW) - ARRAY['title','summary','body','cover_media_id','comments_open','version','updated_at']) IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['title','summary','body','cover_media_id','comments_open','version','updated_at']) THEN
      RAISE EXCEPTION 'story owner update denied' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'cross-owner story update requires an atomic moderation procedure' USING ERRCODE = '42501';
END $$;
CREATE TRIGGER nova_stories_update_guard BEFORE UPDATE ON public.stories
  FOR EACH ROW EXECUTE FUNCTION public.nova_stories_update_guard();

-- Lifecycle path owned by a non-login, non-BYPASSRLS principal. It can only transition
-- the authenticated owner's own story; ordinary runtime DML cannot set lifecycle fields.
GRANT SELECT (id, author_id, status, deleted_at, title, body, version) ON public.stories TO nova_story_lifecycle_manager;
GRANT UPDATE (status, visibility, published_at, deleted_at, comments_open, version, updated_at)
  ON public.stories TO nova_story_lifecycle_manager;
GRANT EXECUTE ON FUNCTION public.nova_rls_uid() TO nova_story_lifecycle_manager;
GRANT EXECUTE ON FUNCTION public.nova_rls_actor_active() TO nova_story_lifecycle_manager;
CREATE POLICY stories_lifecycle_manager_read ON public.stories FOR SELECT TO nova_story_lifecycle_manager
  USING (author_id = public.nova_rls_uid() AND public.nova_rls_actor_active());
CREATE POLICY stories_lifecycle_manager_update ON public.stories FOR UPDATE TO nova_story_lifecycle_manager
  USING (author_id = public.nova_rls_uid() AND public.nova_rls_actor_active() AND deleted_at IS NULL)
  WITH CHECK (author_id = public.nova_rls_uid() AND public.nova_rls_actor_active());
CREATE OR REPLACE FUNCTION public.nova_transition_story(target uuid, transition text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE current_story public.stories%ROWTYPE;
BEGIN
  IF transition NOT IN ('publish','unpublish','soft_delete') THEN
    RAISE EXCEPTION 'unsupported story transition' USING ERRCODE = '22023';
  END IF;
  IF NOT public.nova_rls_actor_active() THEN
    RAISE EXCEPTION 'story transition denied' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO current_story FROM public.stories
   WHERE id = target AND author_id = public.nova_rls_uid() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'story transition denied' USING ERRCODE = '42501'; END IF;

  IF transition = 'publish' THEN
    IF current_story.status::text <> 'draft' OR current_story.deleted_at IS NOT NULL
       OR btrim(current_story.title) = '' OR btrim(current_story.body) = '' THEN
      RAISE EXCEPTION 'invalid publish transition' USING ERRCODE = '42501';
    END IF;
    UPDATE public.stories SET status='published', visibility='public', published_at=now(),
      comments_open=true, version=version+1, updated_at=now() WHERE id=target;
  ELSIF transition = 'unpublish' THEN
    IF current_story.status::text <> 'published' OR current_story.deleted_at IS NOT NULL THEN
      RAISE EXCEPTION 'invalid unpublish transition' USING ERRCODE = '42501';
    END IF;
    UPDATE public.stories SET status='draft', visibility='private', published_at=NULL,
      comments_open=false, version=version+1, updated_at=now() WHERE id=target;
  ELSE
    IF current_story.status::text = 'removed' OR current_story.deleted_at IS NOT NULL THEN
      RAISE EXCEPTION 'invalid soft-delete transition' USING ERRCODE = '42501';
    END IF;
    UPDATE public.stories SET status='removed', visibility='private', deleted_at=now(),
      comments_open=false, version=version+1, updated_at=now() WHERE id=target;
  END IF;
  RETURN true;
END $$;
ALTER FUNCTION public.nova_transition_story(uuid,text) OWNER TO nova_story_lifecycle_manager;
REVOKE ALL ON FUNCTION public.nova_transition_story(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.nova_transition_story(uuid,text) TO nova_fastify_runtime;

-- -----------------------------------------------------------------------------
-- STORY_TAGS: visible public/owner tags; owner insert/delete only.
-- -----------------------------------------------------------------------------
GRANT SELECT, INSERT, DELETE ON public.story_tags TO nova_fastify_runtime;
CREATE POLICY story_tags_read ON public.story_tags FOR SELECT TO nova_fastify_runtime
  USING (EXISTS (SELECT 1 FROM public.stories s WHERE s.id = story_tags.story_id
    AND s.deleted_at IS NULL AND (s.status::text = 'published' AND s.visibility::text = 'public'
      OR (s.author_id = public.nova_rls_uid() AND public.nova_rls_actor_active()))));
CREATE POLICY story_tags_insert_owner ON public.story_tags FOR INSERT TO nova_fastify_runtime
  WITH CHECK (EXISTS (SELECT 1 FROM public.stories s WHERE s.id = story_tags.story_id
    AND s.deleted_at IS NULL AND s.status::text <> 'removed'
    AND s.author_id = public.nova_rls_uid() AND public.nova_rls_actor_active()));
CREATE POLICY story_tags_delete_owner ON public.story_tags FOR DELETE TO nova_fastify_runtime
  USING (EXISTS (SELECT 1 FROM public.stories s WHERE s.id = story_tags.story_id
    AND s.deleted_at IS NULL AND s.status::text <> 'removed'
    AND s.author_id = public.nova_rls_uid() AND public.nova_rls_actor_active()));

-- -----------------------------------------------------------------------------
-- FOLLOWS: participant-only read, own create/delete. Public social counts need a
-- separate aggregate interface and are intentionally not enabled here.
-- -----------------------------------------------------------------------------
GRANT SELECT, INSERT, DELETE ON public.follows TO nova_fastify_runtime;
CREATE POLICY follows_select_own ON public.follows FOR SELECT TO nova_fastify_runtime
  USING (follower_id = public.nova_rls_uid() AND public.nova_rls_actor_active());
CREATE POLICY follows_insert_own ON public.follows FOR INSERT TO nova_fastify_runtime
  WITH CHECK (follower_id = public.nova_rls_uid() AND public.nova_rls_actor_active()
              AND EXISTS (SELECT 1 FROM public.users u WHERE u.id = follows.followed_id
                AND u.status::text = 'active'));
CREATE POLICY follows_delete_own ON public.follows FOR DELETE TO nova_fastify_runtime
  USING (follower_id = public.nova_rls_uid() AND public.nova_rls_actor_active());

-- -----------------------------------------------------------------------------
-- BOOKMARKS: private to owner; insert only for a currently public, active-author story.
-- -----------------------------------------------------------------------------
GRANT SELECT (user_id, story_id, created_at) ON public.bookmarks TO nova_fastify_runtime;
GRANT INSERT (user_id, story_id) ON public.bookmarks TO nova_fastify_runtime;
GRANT DELETE ON public.bookmarks TO nova_fastify_runtime;
CREATE POLICY bookmarks_select_own ON public.bookmarks FOR SELECT TO nova_fastify_runtime
  USING (user_id = public.nova_rls_uid() AND public.nova_rls_actor_active());
CREATE POLICY bookmarks_insert_public ON public.bookmarks FOR INSERT TO nova_fastify_runtime
  WITH CHECK (user_id = public.nova_rls_uid() AND public.nova_rls_actor_active()
    AND EXISTS (SELECT 1 FROM public.stories s WHERE s.id = bookmarks.story_id
      AND s.status::text = 'published' AND s.visibility::text = 'public'
      AND s.deleted_at IS NULL AND EXISTS (SELECT 1 FROM public.users active_author WHERE active_author.id = s.author_id AND active_author.status::text = 'active')));
CREATE POLICY bookmarks_delete_own ON public.bookmarks FOR DELETE TO nova_fastify_runtime
  USING (user_id = public.nova_rls_uid() AND public.nova_rls_actor_active());

-- -----------------------------------------------------------------------------
-- COMMENTS: public visible feed reads only; no direct runtime write privilege until
-- the canonical transactional comment-write contract is approved and deployed.
-- -----------------------------------------------------------------------------
REVOKE ALL PRIVILEGES ON TABLE public.comments FROM nova_fastify_runtime;
REVOKE INSERT (story_id, author_id, parent_id, body), UPDATE (status, deleted_at, updated_at)
  ON TABLE public.comments FROM nova_fastify_runtime;
GRANT SELECT (id, story_id, author_id, parent_id, body, status, created_at, updated_at, deleted_at)
  ON public.comments TO nova_fastify_runtime;
CREATE POLICY comments_read_feed ON public.comments FOR SELECT TO nova_fastify_runtime
  USING (status::text = 'visible' AND deleted_at IS NULL
    AND EXISTS (SELECT 1 FROM public.stories s WHERE s.id = comments.story_id
      AND s.status::text = 'published' AND s.visibility::text = 'public'
      AND s.deleted_at IS NULL AND s.comments_open AND EXISTS (SELECT 1 FROM public.users active_author WHERE active_author.id = s.author_id AND active_author.status::text = 'active'))
    AND EXISTS (SELECT 1 FROM public.users active_author WHERE active_author.id = author_id AND active_author.status::text = 'active'));
CREATE OR REPLACE FUNCTION public.nova_comments_moderation_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF current_user='nova_fastify_runtime' AND OLD.author_id IS DISTINCT FROM public.nova_rls_uid()
     AND (NEW.status IS DISTINCT FROM OLD.status OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at) THEN
    RAISE EXCEPTION 'cross-user comment removal requires an integrated moderation procedure' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER nova_comments_moderation_guard BEFORE UPDATE ON public.comments
  FOR EACH ROW EXECUTE FUNCTION public.nova_comments_moderation_guard();

-- -----------------------------------------------------------------------------
-- REPORTS: own read/create, moderator review, restricted report-cleanup worker.
-- -----------------------------------------------------------------------------
REVOKE ALL PRIVILEGES ON TABLE public.reports FROM nova_fastify_runtime;
REVOKE UPDATE (status, first_response_at, closed_at, reopen_count, updated_at, removal_pending)
  ON TABLE public.reports FROM nova_fastify_runtime;
GRANT SELECT ON public.reports TO nova_fastify_runtime;
GRANT INSERT (reporter_id, target_type, target_id, reason, details) ON public.reports TO nova_fastify_runtime;
GRANT SELECT (id,target_type,target_id,status,removal_pending,first_response_at,closed_at,reopen_count,updated_at),
  UPDATE (status,first_response_at,closed_at,reopen_count,updated_at,removal_pending)
  ON public.reports TO nova_revocation_enqueuer_owner;
GRANT SELECT (id, target_type, target_id, status, removal_pending) ON public.reports TO nova_reports_worker;
GRANT UPDATE (status, removal_pending, updated_at, closed_at) ON public.reports TO nova_reports_worker;
CREATE POLICY reports_read_scoped ON public.reports FOR SELECT TO nova_fastify_runtime
  USING (current_user = 'nova_fastify_runtime' AND public.nova_rls_actor_active()
          AND (reporter_id = public.nova_rls_uid() OR public.nova_rls_actor_has_role(ARRAY['moderator'])));
CREATE POLICY reports_enqueue_read ON public.reports FOR SELECT TO nova_revocation_enqueuer_owner
  USING (current_user='nova_revocation_enqueuer_owner' AND target_type::text='story'
    AND target_id::text=NULLIF(current_setting('nova.fixture_enqueue_story_id',true),'')
    AND EXISTS (SELECT 1 FROM public.moderation_actions a
      WHERE a.id::text=NULLIF(current_setting('nova.fixture_enqueue_action_id',true),'')
        AND a.target_type::text='story' AND a.target_id=reports.target_id AND a.action='hide_story'
        AND public.nova_rls_valid_moderation_action(a.id)));
CREATE POLICY reports_worker_read_removal_only ON public.reports FOR SELECT TO nova_reports_worker
  USING (current_user = 'nova_reports_worker'
    AND removal_pending
    AND public.nova_rls_valid_report_target(target_type,target_id));
CREATE POLICY reports_insert_own ON public.reports FOR INSERT TO nova_fastify_runtime
  WITH CHECK (public.nova_rls_actor_active() AND reporter_id = public.nova_rls_uid());
CREATE POLICY reports_enqueue_update ON public.reports FOR UPDATE TO nova_revocation_enqueuer_owner
  USING (current_user='nova_revocation_enqueuer_owner' AND target_type::text='story'
    AND target_id::text=NULLIF(current_setting('nova.fixture_enqueue_story_id',true),'')
    AND EXISTS (SELECT 1 FROM public.moderation_actions a
      WHERE a.id::text=NULLIF(current_setting('nova.fixture_enqueue_action_id',true),'')
        AND a.target_type::text='story' AND a.target_id=reports.target_id AND a.action='hide_story'
        AND public.nova_rls_valid_moderation_action(a.id)))
  WITH CHECK (current_user='nova_revocation_enqueuer_owner' AND target_type::text='story'
    AND target_id::text=NULLIF(current_setting('nova.fixture_enqueue_story_id',true),'')
    AND EXISTS (SELECT 1 FROM public.moderation_actions a
      WHERE a.id::text=NULLIF(current_setting('nova.fixture_enqueue_action_id',true),'')
        AND a.target_type::text='story' AND a.target_id=reports.target_id AND a.action='hide_story'
        AND public.nova_rls_valid_moderation_action(a.id))
    AND status::text='reviewing' AND removal_pending);
CREATE OR REPLACE FUNCTION public.nova_reports_moderation_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF current_user='nova_fastify_runtime'
     AND (NEW.status IS DISTINCT FROM OLD.status OR NEW.removal_pending IS DISTINCT FROM OLD.removal_pending) THEN
    RAISE EXCEPTION 'report status requires an integrated atomic procedure' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER nova_reports_moderation_guard BEFORE UPDATE ON public.reports
  FOR EACH ROW EXECUTE FUNCTION public.nova_reports_moderation_guard();
CREATE POLICY reports_worker_update_removal_only ON public.reports FOR UPDATE TO nova_reports_worker
  USING (current_user = 'nova_reports_worker' AND removal_pending
    AND public.nova_rls_valid_report_target(target_type,target_id))
  WITH CHECK (current_user = 'nova_reports_worker' AND status::text = 'actioned'
    AND removal_pending = false AND NOT public.nova_rls_target_has_pending_revocation(target_type,target_id));

-- -----------------------------------------------------------------------------
-- MODERATION_ACTIONS: staff read-only; atomic manager procedures create actions,
-- and only trusted purge finalization may mark a linked removal verified.
-- -----------------------------------------------------------------------------
GRANT SELECT (id, moderator_id, target_type, target_id, action, reason, metadata, created_at)
  ON public.moderation_actions TO nova_fastify_runtime;
CREATE POLICY moderation_actions_staff_read ON public.moderation_actions FOR SELECT TO nova_fastify_runtime
  USING (public.nova_rls_actor_has_role(ARRAY['moderator','admin']));

-- -----------------------------------------------------------------------------
-- MEDIA_ASSETS: owner upload/read; public linked media; limited staff moderation;
-- worker table access remains separate. Cross-table predicates are deliberately scoped.
-- -----------------------------------------------------------------------------
GRANT SELECT ON public.media_assets TO nova_fastify_runtime;
GRANT INSERT (id, owner_id, purpose, object_key, mime_type, size_bytes) ON public.media_assets TO nova_fastify_runtime;
-- Runtime may only claim/retry/reject a pending upload. Ready-state metadata and object
-- keys are writable only through controlled SECURITY DEFINER functions.
GRANT UPDATE (status, updated_at) ON public.media_assets TO nova_fastify_runtime;
GRANT SELECT (id, owner_id, purpose, status, object_key, mime_type,upload_nonce) ON public.media_assets TO nova_media_lifecycle_manager;
GRANT UPDATE (status, updated_at, object_key, size_bytes, checksum, ready_at,upload_nonce)
  ON public.media_assets TO nova_media_lifecycle_manager;
-- The revocation worker processes storage-key metadata from its outbox only; it has
-- no direct read or write privilege on media_assets or storage bytes.
CREATE POLICY media_assets_read_scoped ON public.media_assets FOR SELECT TO nova_fastify_runtime
  USING (
    (status::text = 'ready' AND purpose::text <> 'feedback_screenshot' AND (
      (purpose::text = 'avatar' AND owner_id = public.nova_rls_uid() AND public.nova_rls_actor_active())
      OR EXISTS (SELECT 1 FROM public.users u WHERE u.avatar_media_id = media_assets.id AND u.status::text = 'active')
      OR EXISTS (SELECT 1 FROM public.stories s WHERE s.cover_media_id = media_assets.id
        AND s.deleted_at IS NULL AND EXISTS (SELECT 1 FROM public.users active_author WHERE active_author.id = s.author_id AND active_author.status::text = 'active')
        AND ((s.status::text = 'published' AND s.visibility::text = 'public')
          OR (s.author_id = public.nova_rls_uid() AND s.status::text = 'draft' AND public.nova_rls_actor_active()
            AND NOT public.nova_rls_own_media_revocation_pending(media_assets.id))))
    ))
    OR (status::text = 'ready' AND purpose::text = 'feedback_screenshot'
      AND public.nova_rls_actor_has_role(ARRAY['support']))
    OR (status::text = 'ready' AND purpose::text = 'cover'
      AND public.nova_rls_actor_has_role(ARRAY['moderator','admin']))
    OR (owner_id = public.nova_rls_uid() AND public.nova_rls_actor_active()
      AND status::text <> 'ready')
  );
CREATE POLICY media_assets_insert_owner ON public.media_assets FOR INSERT TO nova_fastify_runtime
  WITH CHECK (owner_id = public.nova_rls_uid() AND public.nova_rls_actor_active());
CREATE POLICY media_assets_update_owner_or_staff ON public.media_assets FOR UPDATE TO nova_fastify_runtime
  USING ((owner_id = public.nova_rls_uid() AND public.nova_rls_actor_active())
      OR (purpose::text = 'cover' AND status::text = 'ready'
          AND public.nova_rls_actor_has_role(ARRAY['moderator','admin'])))
  WITH CHECK ((owner_id = public.nova_rls_uid() AND public.nova_rls_actor_active())
      OR (purpose::text = 'cover' AND status::text = 'ready'
          AND public.nova_rls_actor_has_role(ARRAY['moderator','admin'])));
CREATE POLICY media_assets_lifecycle_manager_read ON public.media_assets FOR SELECT TO nova_media_lifecycle_manager
  USING (owner_id = public.nova_rls_uid() AND public.nova_rls_actor_active());
CREATE POLICY media_assets_lifecycle_manager_update ON public.media_assets FOR UPDATE TO nova_media_lifecycle_manager
  USING (owner_id = public.nova_rls_uid() AND public.nova_rls_actor_active())
  WITH CHECK (owner_id = public.nova_rls_uid() AND public.nova_rls_actor_active());

-- -----------------------------------------------------------------------------
-- BETA_FEEDBACK: private reporter/staff access; dedicated expired-row cleanup.
-- -----------------------------------------------------------------------------
GRANT SELECT ON public.beta_feedback TO nova_fastify_runtime;
GRANT INSERT (reporter_id, category, summary, affected_flow, expected_behavior, actual_behavior,
  reproduction_steps, impact_frequency, workaround, device_info, browser_info, occurred_at,
  screenshot_media_id, expires_at) ON public.beta_feedback TO nova_fastify_runtime;
GRANT UPDATE (status, resolution, recurrence_key, reviewed_by, updated_at, first_response_at, reopen_count)
  ON public.beta_feedback TO nova_fastify_runtime;
GRANT SELECT (screenshot_media_id, expires_at), DELETE ON public.beta_feedback TO nova_feedback_cleanup;
CREATE POLICY beta_feedback_read ON public.beta_feedback FOR SELECT TO nova_fastify_runtime
  USING (expires_at > now() AND public.nova_rls_actor_active()
    AND (reporter_id = public.nova_rls_uid() OR public.nova_rls_actor_has_role(ARRAY['support','admin'])));
CREATE POLICY beta_feedback_insert ON public.beta_feedback FOR INSERT TO nova_fastify_runtime
  WITH CHECK (reporter_id = public.nova_rls_uid() AND public.nova_rls_actor_active());
CREATE POLICY beta_feedback_update ON public.beta_feedback FOR UPDATE TO nova_fastify_runtime
  USING (expires_at > now() AND public.nova_rls_actor_has_role(ARRAY['support','admin']))
  WITH CHECK (public.nova_rls_actor_has_role(ARRAY['support','admin'])
    AND reviewed_by = public.nova_rls_uid());
CREATE POLICY beta_feedback_cleanup_read ON public.beta_feedback FOR SELECT TO nova_feedback_cleanup
  USING (current_user = 'nova_feedback_cleanup' AND expires_at <= now());
CREATE POLICY beta_feedback_cleanup_delete ON public.beta_feedback FOR DELETE TO nova_feedback_cleanup
  USING (current_user = 'nova_feedback_cleanup' AND expires_at <= now());

-- -----------------------------------------------------------------------------
-- SECURITY_REPORTS: private reporter/staff access; separate expired-row cleanup.
-- -----------------------------------------------------------------------------
GRANT SELECT ON public.security_reports TO nova_fastify_runtime;
GRANT INSERT (reporter_id, category, summary, details, affected_flow, impact, expires_at)
  ON public.security_reports TO nova_fastify_runtime;
GRANT UPDATE (status, resolution, recurrence_key, reviewed_by, updated_at, first_response_at, reopen_count)
  ON public.security_reports TO nova_fastify_runtime;
GRANT SELECT (expires_at), DELETE ON public.security_reports TO nova_security_reports_cleanup;
CREATE POLICY security_reports_read ON public.security_reports FOR SELECT TO nova_fastify_runtime
  USING (public.nova_rls_actor_active()
    AND ((reporter_id = public.nova_rls_uid() AND expires_at > now())
      OR public.nova_rls_actor_has_role(ARRAY['security','admin'])));
CREATE POLICY security_reports_insert ON public.security_reports FOR INSERT TO nova_fastify_runtime
  WITH CHECK (reporter_id = public.nova_rls_uid() AND public.nova_rls_actor_active());
CREATE POLICY security_reports_update ON public.security_reports FOR UPDATE TO nova_fastify_runtime
  USING (expires_at > now() AND public.nova_rls_actor_has_role(ARRAY['security','admin']))
  WITH CHECK (expires_at > now() AND public.nova_rls_actor_has_role(ARRAY['security','admin'])
              AND reviewed_by = public.nova_rls_uid());
CREATE POLICY security_reports_cleanup_delete ON public.security_reports FOR DELETE TO nova_security_reports_cleanup
  USING (current_user = 'nova_security_reports_cleanup' AND expires_at <= now());

-- -----------------------------------------------------------------------------
-- STAFF_ACCESS_AUDIT: append-only runtime; separate retention worker.
-- -----------------------------------------------------------------------------
GRANT INSERT ON public.staff_access_audit TO nova_fastify_runtime;
GRANT SELECT (expires_at), DELETE ON public.staff_access_audit TO nova_audit_cleanup;
CREATE POLICY staff_audit_insert ON public.staff_access_audit FOR INSERT TO nova_fastify_runtime
  WITH CHECK (staff_id = public.nova_rls_uid() AND CASE event_type::text
    WHEN 'content_report.read' THEN public.nova_rls_actor_has_role(ARRAY['moderator','admin'])
    WHEN 'content_report.status_changed' THEN public.nova_rls_actor_has_role(ARRAY['moderator','admin'])
    WHEN 'moderation_reports.metrics_read' THEN public.nova_rls_actor_has_role(ARRAY['moderator','admin'])
    WHEN 'feedback.read' THEN public.nova_rls_actor_has_role(ARRAY['support','admin'])
    WHEN 'feedback.screenshot_read' THEN public.nova_rls_actor_has_role(ARRAY['support','admin'])
    WHEN 'feedback.status_changed' THEN public.nova_rls_actor_has_role(ARRAY['support','admin'])
    WHEN 'feedback.metrics_read' THEN public.nova_rls_actor_has_role(ARRAY['support','admin'])
    WHEN 'security_report.read' THEN public.nova_rls_actor_has_role(ARRAY['security','admin'])
    WHEN 'security_report.status_changed' THEN public.nova_rls_actor_has_role(ARRAY['security','admin'])
    WHEN 'security_report.metrics_read' THEN public.nova_rls_actor_has_role(ARRAY['security','admin'])
    ELSE false END);
CREATE POLICY staff_audit_cleanup_read ON public.staff_access_audit FOR SELECT TO nova_audit_cleanup
  USING (current_user = 'nova_audit_cleanup' AND expires_at <= statement_timestamp());
CREATE POLICY staff_audit_cleanup_delete ON public.staff_access_audit FOR DELETE TO nova_audit_cleanup
  USING (current_user = 'nova_audit_cleanup' AND expires_at <= statement_timestamp());

-- -----------------------------------------------------------------------------
-- RATE_LIMIT_BUCKETS: the runtime has EXECUTE only. Definer policies are pinned to
-- one transaction-local key; the caller cannot enumerate or directly mutate rows.
-- No cleanup role/path is installed: unbounded bucket retention is an unresolved
-- capacity risk until a separately reviewed, bounded janitor is designed.
-- -----------------------------------------------------------------------------
GRANT SELECT (bucket_key, window_start, hits), INSERT (bucket_key, window_start, hits),
  UPDATE (window_start, hits) ON public.rate_limit_buckets TO nova_rate_limit_counter_owner;
CREATE POLICY rate_limit_counter_read_one_key ON public.rate_limit_buckets FOR SELECT TO nova_rate_limit_counter_owner
  USING (current_user='nova_rate_limit_counter_owner'
    AND bucket_key=NULLIF(current_setting('nova.fixture_rate_limit_key',true),''));
CREATE POLICY rate_limit_counter_insert_one_key ON public.rate_limit_buckets FOR INSERT TO nova_rate_limit_counter_owner
  WITH CHECK (current_user='nova_rate_limit_counter_owner'
    AND bucket_key=NULLIF(current_setting('nova.fixture_rate_limit_key',true),'')
    AND bucket_key ~ '^[0-9a-f]{64}$' AND hits >= 1);
CREATE POLICY rate_limit_counter_update_one_key ON public.rate_limit_buckets FOR UPDATE TO nova_rate_limit_counter_owner
  USING (current_user='nova_rate_limit_counter_owner'
    AND bucket_key=NULLIF(current_setting('nova.fixture_rate_limit_key',true),''))
  WITH CHECK (current_user='nova_rate_limit_counter_owner'
    AND bucket_key=NULLIF(current_setting('nova.fixture_rate_limit_key',true),'')
    AND bucket_key ~ '^[0-9a-f]{64}$' AND hits >= 1);

CREATE OR REPLACE FUNCTION public.nova_rate_limit_record(p_bucket_key text,p_window_start timestamptz)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v_hits integer;
BEGIN
  IF NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_auth_members membership
       JOIN pg_catalog.pg_roles login_role ON login_role.oid=membership.member
       JOIN pg_catalog.pg_roles limiter_role ON limiter_role.oid=membership.roleid
       WHERE limiter_role.rolname='nova_rate_limiter_runtime'
         AND login_role.rolname=session_user
         AND login_role.rolcanlogin AND NOT login_role.rolinherit
         AND NOT login_role.rolsuper AND NOT login_role.rolbypassrls
         AND NOT login_role.rolcreaterole AND NOT login_role.rolcreatedb AND NOT login_role.rolreplication
         AND NOT membership.inherit_option AND membership.set_option AND NOT membership.admin_option
         AND NOT limiter_role.rolcanlogin AND NOT limiter_role.rolinherit
         AND NOT limiter_role.rolsuper AND NOT limiter_role.rolbypassrls
         AND NOT limiter_role.rolcreaterole AND NOT limiter_role.rolcreatedb AND NOT limiter_role.rolreplication
         AND (SELECT pg_catalog.count(*) FROM pg_catalog.pg_auth_members direct
              WHERE direct.member=login_role.oid)=1
         AND (SELECT pg_catalog.count(*) FROM pg_catalog.pg_auth_members wrappers
              WHERE wrappers.roleid=limiter_role.oid)=1
         AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members nested
              WHERE nested.member=limiter_role.oid)
         AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members assigned
              WHERE assigned.roleid=login_role.oid)
     )
     OR p_bucket_key IS NULL OR p_bucket_key !~ '^[0-9a-f]{64}$' OR p_window_start IS NULL THEN
    RAISE EXCEPTION 'rate limit counter request denied' USING ERRCODE='42501';
  END IF;
  PERFORM pg_catalog.set_config('nova.fixture_rate_limit_key',p_bucket_key,true);
  INSERT INTO public.rate_limit_buckets(bucket_key,window_start,hits)
  VALUES(p_bucket_key,p_window_start,1)
  ON CONFLICT(bucket_key) DO UPDATE SET
    hits=CASE WHEN public.rate_limit_buckets.window_start=EXCLUDED.window_start
      THEN public.rate_limit_buckets.hits+1 ELSE 1 END,
    window_start=EXCLUDED.window_start
  RETURNING hits INTO v_hits;
  RETURN v_hits;
END $$;
REVOKE ALL ON FUNCTION public.nova_rate_limit_record(text,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.nova_rate_limit_record(text,timestamptz) TO nova_rate_limiter_runtime;

-- -----------------------------------------------------------------------------
-- MEDIA_KEY_REVOCATIONS: staff enqueue/read; dedicated worker retries, while only
-- the trusted purge finalizer may delete a row after persistent verification.
-- -----------------------------------------------------------------------------
GRANT SELECT (id,media_id,source_key,moderation_action_id,attempt_count,retry_after,created_at,escalated_at),
      UPDATE (attempt_count,retry_after,escalated_at)
  ON public.media_key_revocations TO nova_media_revocation_worker;
CREATE UNIQUE INDEX IF NOT EXISTS nova_media_revocations_one_pending_per_asset
  ON public.media_key_revocations(media_id);
CREATE POLICY media_revocations_worker_read ON public.media_key_revocations FOR SELECT TO nova_media_revocation_worker
  USING (current_user = 'nova_media_revocation_worker'
    AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id));
CREATE POLICY media_revocations_worker_update ON public.media_key_revocations FOR UPDATE TO nova_media_revocation_worker
  USING (current_user = 'nova_media_revocation_worker'
    AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id))
  WITH CHECK (current_user = 'nova_media_revocation_worker'
    AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id));
-- -----------------------------------------------------------------------------
-- Local-only lifecycle, relation, worker-scope, and ACL guards.
-- SECURITY DEFINER owners/functions below are fixture implementation details only;
-- do not infer or copy these owners into a remote migration.
-- -----------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.nova_stories_avatar_reference_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.avatar_media_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.media_assets m WHERE m.id=NEW.avatar_media_id
      AND m.owner_id=NEW.id AND m.purpose='avatar' AND m.status::text='ready'
      AND NOT EXISTS (SELECT 1 FROM public.media_key_revocations r WHERE r.media_id=m.id)
  ) THEN
    RAISE EXCEPTION 'invalid avatar media reference' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER nova_users_avatar_reference_guard BEFORE INSERT OR UPDATE OF avatar_media_id ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.nova_stories_avatar_reference_guard();

CREATE OR REPLACE FUNCTION public.nova_stories_cover_reference_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.cover_media_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.media_assets m WHERE m.id=NEW.cover_media_id
      AND m.owner_id=NEW.author_id AND m.purpose='cover' AND m.status::text='ready'
      AND NOT EXISTS (SELECT 1 FROM public.media_key_revocations r WHERE r.media_id=m.id)
  ) THEN
    RAISE EXCEPTION 'invalid story cover media reference' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER nova_stories_cover_reference_guard BEFORE INSERT OR UPDATE OF cover_media_id,author_id ON public.stories
  FOR EACH ROW EXECUTE FUNCTION public.nova_stories_cover_reference_guard();

CREATE OR REPLACE FUNCTION public.nova_feedback_screenshot_reference_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.screenshot_media_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.media_assets m WHERE m.id=NEW.screenshot_media_id
      AND m.owner_id=NEW.reporter_id AND m.purpose='feedback_screenshot'
      AND m.status::text='ready'
  ) THEN
    RAISE EXCEPTION 'invalid feedback screenshot reference' USING ERRCODE='23514';
  END IF;
  IF NEW.screenshot_media_id IS NOT NULL AND NEW.expires_at <= now()
     AND (TG_OP='INSERT' OR NEW.screenshot_media_id IS DISTINCT FROM OLD.screenshot_media_id) THEN
    RAISE EXCEPTION 'expired feedback cannot attach a screenshot' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER nova_feedback_screenshot_reference_guard BEFORE INSERT OR UPDATE OF screenshot_media_id,reporter_id,expires_at ON public.beta_feedback
  FOR EACH ROW EXECUTE FUNCTION public.nova_feedback_screenshot_reference_guard();

CREATE OR REPLACE FUNCTION public.nova_media_insert_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE expected_ext text;
BEGIN
  IF current_user <> 'nova_fastify_runtime' THEN RETURN NEW; END IF;
  expected_ext := CASE NEW.mime_type WHEN 'image/jpeg' THEN 'jpg' WHEN 'image/png' THEN 'png' WHEN 'image/webp' THEN 'webp' END;
  IF NEW.owner_id IS DISTINCT FROM public.nova_rls_uid() OR NOT public.nova_rls_actor_active()
     OR NEW.status::text <> 'pending' OR NEW.ready_at IS NOT NULL OR NEW.checksum IS NOT NULL
     OR NEW.object_key <> 'pending/'||NEW.owner_id::text||'/'||NEW.id::text||'.'||expected_ext THEN
    RAISE EXCEPTION 'invalid pending media intent' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER nova_media_insert_guard BEFORE INSERT ON public.media_assets
  FOR EACH ROW EXECUTE FUNCTION public.nova_media_insert_guard();

CREATE OR REPLACE FUNCTION public.nova_media_update_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF current_user IN ('nova_fastify_runtime','nova_media_lifecycle_manager','nova_media_upload_verifier') THEN
    RAISE EXCEPTION 'media lifecycle transition requires the final nonce-bound procedure' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER nova_media_update_guard BEFORE UPDATE ON public.media_assets
  FOR EACH ROW EXECUTE FUNCTION public.nova_media_update_guard();

-- Proof-backed upload procedures are declared after the private verification schema below.
GRANT EXECUTE ON FUNCTION public.nova_rls_uid() TO nova_media_lifecycle_manager;
GRANT EXECUTE ON FUNCTION public.nova_rls_actor_active() TO nova_media_lifecycle_manager;
CREATE OR REPLACE FUNCTION public.nova_rls_valid_moderation_action(p_action_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.moderation_actions a
    WHERE a.id=p_action_id AND a.action='hide_story' AND a.target_type::text='story'
      AND EXISTS (SELECT 1 FROM public.stories s WHERE s.id=a.target_id AND s.status::text='removed'
        AND s.visibility::text='private' AND s.deleted_at IS NULL)
  )
$$;
CREATE OR REPLACE FUNCTION public.nova_rls_valid_media_revocation(p_media_id uuid,p_source_key text,p_action_id uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $media_valid$
DECLARE v_action record; v_media record; v_ext text;
BEGIN
  IF p_media_id IS NULL OR p_source_key IS NULL OR p_action_id IS NULL THEN RETURN false; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_media_action_id',p_action_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_media_id',p_media_id::text,true);
  SELECT id,action,target_type,target_id INTO v_action FROM public.moderation_actions WHERE id=p_action_id;
  IF NOT FOUND OR v_action.action<>'hide_story' OR v_action.target_type::text<>'story' THEN RETURN false; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_media_story_id',v_action.target_id::text,true);
  SELECT id,owner_id,purpose,status,mime_type INTO v_media FROM public.media_assets WHERE id=p_media_id;
  IF NOT FOUND OR v_media.purpose<>'cover' OR v_media.status::text<>'ready' THEN RETURN false; END IF;
  v_ext:=CASE v_media.mime_type WHEN 'image/jpeg' THEN 'jpg' WHEN 'image/png' THEN 'png' WHEN 'image/webp' THEN 'webp' END;
  IF p_source_key IS DISTINCT FROM 'ready/'||v_media.owner_id::text||'/'||v_media.id::text||'.'||v_ext THEN RETURN false; END IF;
  RETURN EXISTS (SELECT 1 FROM public.stories s WHERE s.id=v_action.target_id
    AND s.cover_media_id=v_media.id AND s.author_id=v_media.owner_id
    AND s.status::text='removed' AND s.visibility::text='private' AND s.deleted_at IS NULL);
END $media_valid$;
CREATE OR REPLACE FUNCTION public.nova_rls_valid_report_target(p_target_type report_target_type,p_target_id uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $report_target$
DECLARE v_action record;
BEGIN
  IF p_target_type::text<>'story' OR p_target_id IS NULL THEN RETURN false; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_reports_target_type',p_target_type::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_reports_target_id',p_target_id::text,true);
  SELECT id,action,target_type,target_id INTO v_action FROM public.moderation_actions
    WHERE target_type::text=p_target_type::text AND target_id=p_target_id AND action='hide_story';
  IF NOT FOUND OR v_action.target_type::text<>'story' OR v_action.target_id<>p_target_id THEN RETURN false; END IF;
  RETURN EXISTS (SELECT 1 FROM public.stories s WHERE s.id=p_target_id
    AND s.status::text='removed' AND s.visibility::text='private' AND s.deleted_at IS NULL);
END $report_target$;
CREATE OR REPLACE FUNCTION public.nova_rls_target_has_pending_revocation(p_target_type report_target_type,p_target_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT EXISTS (SELECT 1 FROM public.media_key_revocations r
    JOIN public.moderation_actions a ON a.id=r.moderation_action_id
    WHERE a.target_type=p_target_type AND a.target_id=p_target_id
      AND public.nova_rls_valid_media_revocation(r.id,r.media_id,r.source_key,r.moderation_action_id))
$$;

-- No direct runtime INSERT/UPDATE can attach arbitrary assets or keys. The function
-- accepts only the current moderator's valid hide/suspend action and the linked cover;
-- storage copying itself remains an external trusted operation.
CREATE OR REPLACE FUNCTION public.nova_enqueue_media_key_revocation(
  media_id uuid, action_id uuid, expected_source_key text, rotated_key text
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE item public.media_assets%ROWTYPE; action public.moderation_actions%ROWTYPE; new_id uuid;
DECLARE base_name text; prefix text; rotation_id text;
BEGIN
  IF NOT public.nova_rls_actor_has_role(ARRAY['moderator']) THEN
    RAISE EXCEPTION 'media revocation enqueue denied' USING ERRCODE='42501';
  END IF;
  SELECT * INTO action FROM public.moderation_actions WHERE id=action_id
    AND moderator_id=public.nova_rls_uid() FOR UPDATE;
  IF NOT FOUND OR NOT public.nova_rls_valid_moderation_action(action.id) THEN
    RAISE EXCEPTION 'media revocation enqueue denied' USING ERRCODE='42501';
  END IF;
  SELECT * INTO item FROM public.media_assets WHERE id=media_id FOR UPDATE;
  IF NOT FOUND OR item.purpose <> 'cover' OR item.status::text <> 'ready'
     OR item.object_key <> expected_source_key
     OR NOT public.nova_rls_valid_media_revocation(item.id,expected_source_key,action.id) THEN
    RAISE EXCEPTION 'media revocation enqueue denied' USING ERRCODE='42501';
  END IF;
  prefix := 'ready/'||item.owner_id::text||'/';
  base_name := item.id::text||'.'||CASE item.mime_type WHEN 'image/jpeg' THEN 'jpg' WHEN 'image/png' THEN 'png' WHEN 'image/webp' THEN 'webp' END;
  IF expected_source_key <> prefix||base_name OR rotated_key NOT LIKE prefix||'%-'||base_name THEN
    RAISE EXCEPTION 'media revocation enqueue denied' USING ERRCODE='42501';
  END IF;
  rotation_id := substring(rotated_key FROM length(prefix)+1 FOR length(rotated_key)-length(prefix)-length(base_name)-1);
  IF rotation_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'media revocation enqueue denied' USING ERRCODE='42501';
  END IF;
  UPDATE public.media_assets SET object_key=rotated_key,updated_at=now() WHERE id=item.id;
  INSERT INTO public.media_key_revocations(media_id,source_key,moderation_action_id)
    VALUES(item.id,expected_source_key,action.id) RETURNING id INTO new_id;
  RETURN new_id;
END $$;
REVOKE ALL ON FUNCTION public.nova_enqueue_media_key_revocation(uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.nova_enqueue_media_key_revocation(uuid,uuid,text,text) TO nova_fastify_runtime;

GRANT EXECUTE ON FUNCTION public.nova_rls_valid_moderation_action(uuid) TO nova_media_revocation_worker,nova_reports_worker;
GRANT EXECUTE ON FUNCTION public.nova_rls_valid_media_revocation(uuid,text,uuid) TO nova_revocation_enqueuer_owner;
GRANT EXECUTE ON FUNCTION public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)
  TO nova_media_revocation_worker,nova_reports_predicate_owner,nova_media_purge_verifier,
  nova_media_purge_attester,nova_media_removal_authority;
GRANT EXECUTE ON FUNCTION public.nova_rls_valid_report_target(report_target_type,uuid) TO nova_reports_worker;
GRANT EXECUTE ON FUNCTION public.nova_rls_target_has_pending_revocation(report_target_type,uuid) TO nova_reports_worker;
REVOKE ALL ON FUNCTION public.nova_stories_update_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_users_update_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_media_insert_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_media_update_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_stories_avatar_reference_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_stories_cover_reference_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_feedback_screenshot_reference_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_media_insert_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_rls_uid() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_rls_subject() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_rls_actor_active() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_rls_actor_has_role(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_rls_own_media_revocation_pending(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_rls_valid_moderation_action(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_rls_valid_media_revocation(uuid,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_rls_valid_report_target(report_target_type,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_rls_target_has_pending_revocation(report_target_type,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.nova_rls_uid() TO nova_fastify_runtime,nova_story_lifecycle_manager;
GRANT EXECUTE ON FUNCTION public.nova_rls_subject() TO nova_fastify_runtime;
GRANT EXECUTE ON FUNCTION public.nova_rls_actor_active() TO nova_fastify_runtime,nova_story_lifecycle_manager,nova_media_lifecycle_manager;
GRANT EXECUTE ON FUNCTION public.nova_rls_actor_has_role(text[]) TO nova_fastify_runtime;
REVOKE CREATE ON SCHEMA public FROM nova_story_lifecycle_manager,nova_media_lifecycle_manager;

CREATE OR REPLACE FUNCTION public.nova_reports_worker_update_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF current_user='nova_reports_worker' AND (
    NOT OLD.removal_pending OR NEW.removal_pending OR NEW.status::text <> 'actioned'
    OR NEW.closed_at IS NOT NULL OR NEW.first_response_at IS DISTINCT FROM OLD.first_response_at
    OR NEW.reopen_count IS DISTINCT FROM OLD.reopen_count
    OR (to_jsonb(NEW) - ARRAY['status','removal_pending','updated_at','closed_at']) IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['status','removal_pending','updated_at','closed_at'])
  ) THEN
    RAISE EXCEPTION 'report removal worker transition denied' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER nova_reports_worker_update_guard BEFORE UPDATE ON public.reports
  FOR EACH ROW EXECUTE FUNCTION public.nova_reports_worker_update_guard();

CREATE OR REPLACE FUNCTION public.nova_revocation_worker_update_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF current_user='nova_media_revocation_worker' AND (
    NEW.attempt_count <> OLD.attempt_count + 1 OR NEW.retry_after <= OLD.retry_after
    OR (NEW.attempt_count >= 3 AND NEW.escalated_at IS NULL)
    OR (to_jsonb(NEW) - ARRAY['attempt_count','retry_after','escalated_at']) IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['attempt_count','retry_after','escalated_at'])
  ) THEN
    RAISE EXCEPTION 'revocation retry transition denied' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER nova_revocation_worker_update_guard BEFORE UPDATE ON public.media_key_revocations
  FOR EACH ROW EXECUTE FUNCTION public.nova_revocation_worker_update_guard();

CREATE OR REPLACE FUNCTION public.nova_action_worker_update_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF current_user='nova_media_revocation_worker' THEN
    RAISE EXCEPTION 'revocation worker cannot certify storage purge' USING ERRCODE='42501';
  ELSIF current_user='nova_media_purge_verifier' THEN
    IF OLD.metadata->>'removalStatus' IS DISTINCT FROM 'pending'
       OR NEW.metadata->>'removalStatus' IS DISTINCT FROM 'verified'
       OR NEW.metadata->>'removalVerifiedAt' IS NULL
       OR (NEW.metadata - ARRAY['removalStatus','removalVerifiedAt']) IS DISTINCT FROM
          (OLD.metadata - ARRAY['removalStatus','removalVerifiedAt'])
       OR (to_jsonb(NEW)-'metadata') IS DISTINCT FROM (to_jsonb(OLD)-'metadata')
       OR NOT EXISTS (SELECT 1 FROM nova_security_fixture.media_purge_attestations v
         WHERE v.moderation_action_id=OLD.id AND v.attested_by='nova_media_purge_attester')
       OR NOT EXISTS (SELECT 1 FROM nova_security_fixture.media_removal_authoritative_outcomes o
         WHERE o.moderation_action_id=OLD.id AND o.outcome='media_removed_and_cache_purged'
           AND o.confirmed_by='nova_media_removal_authority'
           AND o.purge_scope='storage_object_and_all_cache_variants')
       OR EXISTS (SELECT 1 FROM public.media_key_revocations r WHERE r.moderation_action_id=OLD.id) THEN
      RAISE EXCEPTION 'trusted purge verification transition denied' USING ERRCODE='42501';
    END IF;
  ELSIF NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'direct moderation action update denied' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER nova_action_worker_update_guard BEFORE UPDATE ON public.moderation_actions
  FOR EACH ROW EXECUTE FUNCTION public.nova_action_worker_update_guard();
REVOKE ALL ON FUNCTION public.nova_reports_worker_update_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_revocation_worker_update_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_action_worker_update_guard() FROM PUBLIC;

-- Default-ACL regression: create future objects as the explicit test owner, assert no
-- PUBLIC/runtime access, then remove every probe object inside this fixture transaction.
SET ROLE nova_fixture_migration_owner;
CREATE TABLE public.nova_fixture_acl_table_probe(id integer);
CREATE SEQUENCE public.nova_fixture_acl_sequence_probe;
CREATE FUNCTION public.nova_fixture_acl_function_probe() RETURNS integer LANGUAGE sql AS 'SELECT 1';
RESET ROLE;
DO $acl_probe$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl
    WHERE c.oid='public.nova_fixture_acl_table_probe'::regclass
      AND acl.grantee IN (0,'nova_fastify_runtime'::regrole)
      AND acl.privilege_type='SELECT'
  ) THEN
    RAISE EXCEPTION 'future table default ACL is open';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('S',c.relowner))) acl
    WHERE c.oid='public.nova_fixture_acl_sequence_probe'::regclass
      AND acl.grantee IN (0,'nova_fastify_runtime'::regrole)
  ) THEN
    RAISE EXCEPTION 'future sequence default ACL is open';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_proc f CROSS JOIN LATERAL aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) acl
    WHERE f.oid='public.nova_fixture_acl_function_probe()'::regprocedure
      AND acl.grantee IN (0,'nova_fastify_runtime'::regrole)
      AND acl.privilege_type='EXECUTE'
  ) THEN
    RAISE EXCEPTION 'future function default EXECUTE is open';
  END IF;
END
$acl_probe$;
DROP FUNCTION public.nova_fixture_acl_function_probe();
DROP SEQUENCE public.nova_fixture_acl_sequence_probe;
DROP TABLE public.nova_fixture_acl_table_probe;

-- Local smoke-test examples (run separately on the disposable DB as a superuser):
--   SET ROLE nova_fastify_runtime;
--   SELECT count(*) FROM public.tags;                 -- public catalogue read
--   SELECT count(*) FROM public.bookmarks;            -- no context => no rows
--   RESET ROLE;
-- For authenticated tests, within a transaction set all context values from a verified
-- and DB-resolved fixture identity, then test owner operations. Never use request/body IDs.
-- SET ROLE nova_fastify_runtime;
-- BEGIN;
-- SELECT set_config('app.auth_subject','<verified test subject>',true);
-- SELECT set_config('app.user_id','<resolved test UUID>',true);
-- SELECT set_config('app.user_role','<resolved DB role>',true);
-- ...
-- ROLLBACK;


-- Security review follow-up, disposable fixture only: scoped SECURITY DEFINER owners,
-- atomic moderation, verifier-only upload completion, and bounded retry policy.

GRANT SELECT (id,auth_subject,status,role) ON public.users TO nova_actor_predicate_owner;
CREATE POLICY users_actor_predicate_owner_read ON public.users FOR SELECT TO nova_actor_predicate_owner
  USING (id=public.nova_rls_uid() AND auth_subject=public.nova_rls_subject());

GRANT SELECT (id,owner_id) ON public.media_assets TO nova_media_state_predicate_owner;
GRANT SELECT (media_id) ON public.media_key_revocations TO nova_media_state_predicate_owner;
CREATE POLICY media_state_predicate_owner_media_read ON public.media_assets FOR SELECT TO nova_media_state_predicate_owner
  USING (owner_id=public.nova_rls_uid() AND public.nova_rls_actor_active());
CREATE POLICY media_state_predicate_owner_revocation_read ON public.media_key_revocations FOR SELECT TO nova_media_state_predicate_owner
  USING (EXISTS (SELECT 1 FROM public.media_assets m WHERE m.id=media_id
    AND m.owner_id=public.nova_rls_uid() AND public.nova_rls_actor_active()));

GRANT SELECT (id,action,target_type,target_id) ON public.moderation_actions TO nova_action_predicate_owner;
GRANT SELECT (id,status,visibility,deleted_at) ON public.stories TO nova_action_predicate_owner;
CREATE POLICY action_predicate_owner_action_read ON public.moderation_actions FOR SELECT TO nova_action_predicate_owner
  USING (id::text=NULLIF(current_setting('nova.fixture_action_predicate_id',true),''));
CREATE POLICY action_predicate_owner_story_read ON public.stories FOR SELECT TO nova_action_predicate_owner
  USING (id::text=NULLIF(current_setting('nova.fixture_action_story_id',true),''));

GRANT SELECT (id,action,target_type,target_id) ON public.moderation_actions TO nova_media_predicate_owner;
GRANT SELECT (id,owner_id,purpose,status,mime_type) ON public.media_assets TO nova_media_predicate_owner;
GRANT SELECT (id,author_id,cover_media_id,status,visibility,deleted_at) ON public.stories TO nova_media_predicate_owner;
GRANT SELECT (id,media_id,source_key,moderation_action_id) ON public.media_key_revocations TO nova_media_predicate_owner;
CREATE POLICY media_predicate_owner_action_read ON public.moderation_actions FOR SELECT TO nova_media_predicate_owner
  USING (id::text=NULLIF(current_setting('nova.fixture_media_action_id',true),''));
CREATE POLICY media_predicate_owner_media_read ON public.media_assets FOR SELECT TO nova_media_predicate_owner
  USING (id::text=NULLIF(current_setting('nova.fixture_media_id',true),''));
CREATE POLICY media_predicate_owner_revocation_read ON public.media_key_revocations FOR SELECT TO nova_media_predicate_owner
  USING (current_user='nova_media_predicate_owner'
    AND id::text=NULLIF(current_setting('nova.fixture_media_revocation_id',true),''));
CREATE POLICY media_predicate_owner_story_read ON public.stories FOR SELECT TO nova_media_predicate_owner
  USING (id::text=NULLIF(current_setting('nova.fixture_media_story_id',true),'')
    OR (author_id::text=NULLIF(current_setting('nova.fixture_media_user_id',true),'')
      AND cover_media_id::text=NULLIF(current_setting('nova.fixture_media_id',true),'')
      AND status::text='published' AND visibility::text='public' AND deleted_at IS NULL));

GRANT SELECT (id,target_type,target_id,action,metadata) ON public.moderation_actions TO nova_reports_predicate_owner;
GRANT SELECT (id,media_id,source_key,moderation_action_id) ON public.media_key_revocations TO nova_reports_predicate_owner;
GRANT SELECT (id,cover_media_id,status,visibility,deleted_at) ON public.stories TO nova_reports_predicate_owner;
CREATE POLICY reports_predicate_owner_action_read ON public.moderation_actions FOR SELECT TO nova_reports_predicate_owner
  USING (target_type::text=NULLIF(current_setting('nova.fixture_reports_target_type',true),'')
    AND target_id::text=NULLIF(current_setting('nova.fixture_reports_target_id',true),''));
CREATE POLICY reports_predicate_owner_revocation_read ON public.media_key_revocations FOR SELECT TO nova_reports_predicate_owner
  USING (EXISTS (SELECT 1 FROM public.moderation_actions a WHERE a.id=moderation_action_id
    AND a.target_type::text=NULLIF(current_setting('nova.fixture_reports_target_type',true),'')
    AND a.target_id::text=NULLIF(current_setting('nova.fixture_reports_target_id',true),'')));
CREATE POLICY reports_predicate_owner_story_read ON public.stories FOR SELECT TO nova_reports_predicate_owner
  USING (id::text=NULLIF(current_setting('nova.fixture_reports_target_id',true),''));

CREATE SCHEMA nova_security_fixture;
REVOKE ALL ON SCHEMA nova_security_fixture FROM PUBLIC;
GRANT USAGE ON SCHEMA nova_security_fixture TO nova_media_purge_verifier,nova_media_upload_verifier,
  nova_media_lifecycle_manager,nova_reports_predicate_owner,nova_media_purge_attester,
  nova_story_moderation_manager;
CREATE TABLE nova_security_fixture.media_upload_verifications (
  media_id uuid PRIMARY KEY REFERENCES public.media_assets(id),
  owner_id uuid NOT NULL REFERENCES public.users(id),
  upload_nonce uuid NOT NULL,
  source_key text NOT NULL,
  storage_object_version text NOT NULL CHECK (pg_catalog.btrim(storage_object_version)<>'' AND pg_catalog.length(storage_object_version)<=300),
  measured_size bigint NOT NULL CHECK (measured_size>0),
  checksum_sha256 text NOT NULL CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
  audit_ref text NOT NULL CHECK (pg_catalog.btrim(audit_ref)<>'' AND pg_catalog.length(audit_ref)<=500),
  verified_by name NOT NULL,
  verified_at timestamptz NOT NULL
);
ALTER TABLE nova_security_fixture.media_upload_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE nova_security_fixture.media_upload_verifications FORCE ROW LEVEL SECURITY;
REVOKE ALL ON nova_security_fixture.media_upload_verifications FROM PUBLIC;
GRANT SELECT (media_id,owner_id,source_key,measured_size,checksum_sha256,audit_ref,verified_by,verified_at)
  ON nova_security_fixture.media_upload_verifications TO nova_media_upload_verifier,nova_media_lifecycle_manager;
GRANT SELECT (media_id,owner_id,upload_nonce,source_key,storage_object_version,measured_size,checksum_sha256,audit_ref,verified_by,verified_at)
  ON nova_security_fixture.media_upload_verifications TO nova_media_lifecycle_manager;
GRANT INSERT (media_id,owner_id,upload_nonce,source_key,storage_object_version,measured_size,checksum_sha256,audit_ref,verified_by,verified_at)
  ON nova_security_fixture.media_upload_verifications TO nova_media_upload_verifier;
GRANT DELETE ON nova_security_fixture.media_upload_verifications TO nova_media_lifecycle_manager;
CREATE POLICY upload_verifier_proof_read ON nova_security_fixture.media_upload_verifications FOR SELECT TO nova_media_upload_verifier
  USING (current_user='nova_media_upload_verifier'
    AND media_id::text=NULLIF(current_setting('nova.fixture_upload_media_id',true),''));
CREATE POLICY upload_verifier_proof_insert ON nova_security_fixture.media_upload_verifications FOR INSERT TO nova_media_upload_verifier
  WITH CHECK (current_user='nova_media_upload_verifier'
    AND media_id::text=NULLIF(current_setting('nova.fixture_upload_media_id',true),'')
    AND verified_by=current_user
    AND EXISTS (SELECT 1 FROM public.media_assets m WHERE m.id=nova_security_fixture.media_upload_verifications.media_id
      AND m.owner_id=nova_security_fixture.media_upload_verifications.owner_id
      AND m.upload_nonce=nova_security_fixture.media_upload_verifications.upload_nonce
      AND m.object_key=nova_security_fixture.media_upload_verifications.source_key
      AND m.status::text='processing'));
CREATE POLICY upload_manager_proof_read ON nova_security_fixture.media_upload_verifications FOR SELECT TO nova_media_lifecycle_manager
  USING (current_user='nova_media_lifecycle_manager'
    AND media_id::text=NULLIF(current_setting('nova.fixture_upload_media_id',true),''));
CREATE POLICY upload_manager_proof_delete ON nova_security_fixture.media_upload_verifications FOR DELETE TO nova_media_lifecycle_manager
  USING (current_user='nova_media_lifecycle_manager'
    AND media_id::text=NULLIF(current_setting('nova.fixture_upload_media_id',true),''));
GRANT SELECT (id,owner_id,purpose,status,object_key,mime_type,upload_nonce) ON public.media_assets TO nova_media_upload_verifier;
GRANT UPDATE (upload_nonce) ON public.media_assets TO nova_media_upload_verifier;
CREATE POLICY media_assets_upload_verifier_read ON public.media_assets FOR SELECT TO nova_media_upload_verifier
  USING (current_user='nova_media_upload_verifier'
    AND id::text=NULLIF(current_setting('nova.fixture_upload_media_id',true),'')
    AND status::text='processing');
-- The verifier has one-column UPDATE only because SELECT FOR UPDATE requires UPDATE
-- privilege; the row policy is limited to the exact processing attempt and the function
-- never changes the asset row.
CREATE POLICY media_assets_upload_verifier_lock ON public.media_assets FOR UPDATE TO nova_media_upload_verifier
  USING (current_user='nova_media_upload_verifier'
    AND id::text=NULLIF(current_setting('nova.fixture_upload_media_id',true),'')
    AND status::text='processing')
  WITH CHECK (current_user='nova_media_upload_verifier'
    AND id::text=NULLIF(current_setting('nova.fixture_upload_media_id',true),'')
    AND status::text='processing');
CREATE TABLE nova_security_fixture.media_purge_attestations (
  revocation_id uuid PRIMARY KEY,
  media_id uuid NOT NULL REFERENCES public.media_assets(id),
  moderation_action_id uuid NOT NULL REFERENCES public.moderation_actions(id),
  source_key text NOT NULL,
  storage_object_version text NOT NULL CHECK (pg_catalog.btrim(storage_object_version)<>'' AND pg_catalog.length(storage_object_version)<=300),
  attestation_ref text NOT NULL CHECK (pg_catalog.btrim(attestation_ref)<>'' AND pg_catalog.length(attestation_ref)<=500),
  attested_by name NOT NULL,
  attested_at timestamptz NOT NULL
);
ALTER TABLE nova_security_fixture.media_purge_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE nova_security_fixture.media_purge_attestations FORCE ROW LEVEL SECURITY;
REVOKE ALL ON nova_security_fixture.media_purge_attestations FROM PUBLIC;
GRANT SELECT (revocation_id,media_id,moderation_action_id,source_key,storage_object_version,attestation_ref,attested_by,attested_at)
  ON nova_security_fixture.media_purge_attestations TO nova_media_purge_verifier,nova_reports_predicate_owner;
GRANT INSERT (revocation_id,media_id,moderation_action_id,source_key,storage_object_version,attestation_ref,attested_by,attested_at)
  ON nova_security_fixture.media_purge_attestations TO nova_media_purge_attester;
GRANT SELECT (revocation_id,media_id,moderation_action_id,source_key,storage_object_version)
  ON nova_security_fixture.media_purge_attestations TO nova_media_removal_authority;
CREATE POLICY purge_verifier_verification_read ON nova_security_fixture.media_purge_attestations FOR SELECT TO nova_media_purge_verifier
  USING (current_user='nova_media_purge_verifier'
    AND revocation_id::text=NULLIF(current_setting('nova.fixture_purge_revocation_id',true),''));
CREATE POLICY purge_authority_attestation_read ON nova_security_fixture.media_purge_attestations FOR SELECT TO nova_media_removal_authority
  USING (current_user='nova_media_removal_authority'
    AND revocation_id::text=NULLIF(current_setting('nova.fixture_purge_revocation_id',true),''));
CREATE POLICY purge_attester_verification_insert ON nova_security_fixture.media_purge_attestations FOR INSERT TO nova_media_purge_attester
  WITH CHECK (current_user='nova_media_purge_attester'
    AND revocation_id::text=NULLIF(current_setting('nova.fixture_purge_revocation_id',true),'')
    AND media_id::text=NULLIF(current_setting('nova.fixture_purge_media_id',true),'')
    AND moderation_action_id::text=NULLIF(current_setting('nova.fixture_purge_action_id',true),'')
    AND source_key=NULLIF(current_setting('nova.fixture_purge_source_key',true),'')
    AND attested_by=current_user
    AND EXISTS (SELECT 1 FROM public.media_key_revocations r
      WHERE r.id=nova_security_fixture.media_purge_attestations.revocation_id
        AND r.media_id=nova_security_fixture.media_purge_attestations.media_id
        AND r.moderation_action_id=nova_security_fixture.media_purge_attestations.moderation_action_id
        AND r.source_key=nova_security_fixture.media_purge_attestations.source_key));
CREATE POLICY reports_predicate_owner_verification_read ON nova_security_fixture.media_purge_attestations
  FOR SELECT TO nova_reports_predicate_owner
  USING (EXISTS (SELECT 1 FROM public.moderation_actions a WHERE a.id=moderation_action_id
    AND a.target_type::text=NULLIF(current_setting('nova.fixture_reports_target_type',true),'')
    AND a.target_id::text=NULLIF(current_setting('nova.fixture_reports_target_id',true),'')));

CREATE TABLE nova_security_fixture.media_removal_authoritative_outcomes (
  revocation_id uuid PRIMARY KEY,
  media_id uuid NOT NULL REFERENCES public.media_assets(id),
  moderation_action_id uuid NOT NULL REFERENCES public.moderation_actions(id),
  source_key text NOT NULL,
  storage_object_version text NOT NULL CHECK (pg_catalog.btrim(storage_object_version)<>'' AND pg_catalog.length(storage_object_version)<=300),
  authority_reference text NOT NULL CHECK (pg_catalog.btrim(authority_reference)<>'' AND pg_catalog.length(authority_reference)<=500),
  purge_scope text NOT NULL CHECK (purge_scope='storage_object_and_all_cache_variants'),
  outcome text NOT NULL CHECK (outcome='media_removed_and_cache_purged'),
  confirmed_by name NOT NULL,
  confirmed_at timestamptz NOT NULL
);
ALTER TABLE nova_security_fixture.media_removal_authoritative_outcomes ENABLE ROW LEVEL SECURITY;
ALTER TABLE nova_security_fixture.media_removal_authoritative_outcomes FORCE ROW LEVEL SECURITY;
REVOKE ALL ON nova_security_fixture.media_removal_authoritative_outcomes FROM PUBLIC;
GRANT SELECT (revocation_id,media_id,moderation_action_id,source_key,storage_object_version,authority_reference,purge_scope,outcome,confirmed_by,confirmed_at)
  ON nova_security_fixture.media_removal_authoritative_outcomes TO nova_media_purge_verifier,nova_reports_predicate_owner;
GRANT INSERT (revocation_id,media_id,moderation_action_id,source_key,storage_object_version,authority_reference,purge_scope,outcome,confirmed_by,confirmed_at)
  ON nova_security_fixture.media_removal_authoritative_outcomes TO nova_media_purge_verifier;
CREATE POLICY purge_verifier_authoritative_outcome_read ON nova_security_fixture.media_removal_authoritative_outcomes FOR SELECT TO nova_media_purge_verifier
  USING (current_user='nova_media_purge_verifier'
    AND revocation_id::text=NULLIF(current_setting('nova.fixture_purge_revocation_id',true),''));
CREATE POLICY purge_verifier_outcome_insert ON nova_security_fixture.media_removal_authoritative_outcomes FOR INSERT TO nova_media_purge_verifier
  WITH CHECK (current_user='nova_media_purge_verifier'
    AND revocation_id::text=NULLIF(current_setting('nova.fixture_purge_revocation_id',true),'')
    AND media_id::text=NULLIF(current_setting('nova.fixture_purge_media_id',true),'')
    AND moderation_action_id::text=NULLIF(current_setting('nova.fixture_purge_action_id',true),'')
    AND source_key=NULLIF(current_setting('nova.fixture_purge_source_key',true),'')
    AND confirmed_by='nova_media_removal_authority'
    AND purge_scope='storage_object_and_all_cache_variants' AND outcome='media_removed_and_cache_purged'
    AND EXISTS (SELECT 1 FROM nova_security_fixture.media_purge_attestations a
      WHERE a.revocation_id=nova_security_fixture.media_removal_authoritative_outcomes.revocation_id
        AND a.media_id=nova_security_fixture.media_removal_authoritative_outcomes.media_id
        AND a.moderation_action_id=nova_security_fixture.media_removal_authoritative_outcomes.moderation_action_id
        AND a.source_key=nova_security_fixture.media_removal_authoritative_outcomes.source_key
        AND a.storage_object_version=nova_security_fixture.media_removal_authoritative_outcomes.storage_object_version));
CREATE POLICY reports_predicate_owner_authoritative_outcome_read
  ON nova_security_fixture.media_removal_authoritative_outcomes FOR SELECT TO nova_reports_predicate_owner
  USING (EXISTS (SELECT 1 FROM public.moderation_actions a WHERE a.id=moderation_action_id
    AND a.target_type::text=NULLIF(current_setting('nova.fixture_reports_target_type',true),'')
    AND a.target_id::text=NULLIF(current_setting('nova.fixture_reports_target_id',true),'')));

-- Disposable simulation of the intended public runtime contract; this is not a canonical migration.
-- The private-schema decoy below must never satisfy production startup validation.
CREATE TABLE public.media_no_media_required (
  action_id uuid PRIMARY KEY REFERENCES public.moderation_actions(id),
  target_story_id uuid NOT NULL REFERENCES public.stories(id),
  result text NOT NULL CHECK (result='no_media_required'),
  recorded_by name NOT NULL,
  recorded_at timestamptz NOT NULL
);
ALTER TABLE public.media_no_media_required ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.media_no_media_required FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.media_no_media_required FROM PUBLIC;
GRANT INSERT (action_id,target_story_id,result,recorded_by,recorded_at)
  ON public.media_no_media_required TO nova_story_moderation_manager;
GRANT SELECT (action_id,target_story_id,result)
  ON public.media_no_media_required TO nova_reports_predicate_owner;
GRANT REFERENCES (id) ON public.moderation_actions,public.stories TO nova_story_moderation_manager;
CREATE POLICY story_manager_no_media_insert ON public.media_no_media_required FOR INSERT TO nova_story_moderation_manager
  WITH CHECK (current_user='nova_story_moderation_manager'
    AND action_id::text=NULLIF(current_setting('nova.fixture_story_action_id',true),'')
    AND target_story_id::text=NULLIF(current_setting('nova.fixture_story_id',true),'')
    AND result='no_media_required' AND recorded_by=current_user
    AND EXISTS (SELECT 1 FROM public.stories s WHERE s.id=target_story_id AND s.cover_media_id IS NULL
      AND s.status::text='removed' AND s.visibility::text='private' AND s.deleted_at IS NULL)
    AND EXISTS (SELECT 1 FROM public.moderation_actions a WHERE a.id=action_id
      AND a.moderator_id=public.nova_rls_uid()
      AND a.target_id=target_story_id AND a.action='hide_story'));
CREATE POLICY reports_predicate_no_media_read ON public.media_no_media_required FOR SELECT TO nova_reports_predicate_owner
  USING (EXISTS (SELECT 1 FROM public.moderation_actions a WHERE a.id=action_id
    AND a.target_type::text=NULLIF(current_setting('nova.fixture_reports_target_type',true),'')
    AND a.target_id::text=NULLIF(current_setting('nova.fixture_reports_target_id',true),'')));

-- Deliberately unusable test-schema decoy: production validation must require the public contract above.
CREATE TABLE nova_security_fixture.media_no_media_required (
  action_id uuid PRIMARY KEY,
  target_story_id uuid NOT NULL,
  result text NOT NULL,
  recorded_by name NOT NULL,
  recorded_at timestamptz NOT NULL
);
ALTER TABLE nova_security_fixture.media_no_media_required ENABLE ROW LEVEL SECURITY;
ALTER TABLE nova_security_fixture.media_no_media_required FORCE ROW LEVEL SECURITY;
REVOKE ALL ON nova_security_fixture.media_no_media_required FROM PUBLIC;
REVOKE USAGE ON SCHEMA nova_security_fixture FROM nova_story_moderation_manager,nova_revocation_enqueuer_owner;

GRANT SELECT (id,media_id,source_key,moderation_action_id,attempt_count,retry_after,escalated_at),
  DELETE ON public.media_key_revocations TO nova_media_purge_verifier;
GRANT UPDATE (attempt_count) ON public.media_key_revocations TO nova_media_purge_verifier;
GRANT SELECT (id,media_id,source_key,moderation_action_id)
  ON public.media_key_revocations TO nova_media_purge_attester,nova_media_removal_authority;
CREATE POLICY media_revocations_purge_attester_read ON public.media_key_revocations FOR SELECT TO nova_media_purge_attester
  USING (current_user='nova_media_purge_attester'
    AND id::text=NULLIF(current_setting('nova.fixture_purge_revocation_id',true),'')
    AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id));
CREATE POLICY media_revocations_removal_authority_read ON public.media_key_revocations FOR SELECT TO nova_media_removal_authority
  USING (current_user='nova_media_removal_authority'
    AND id::text=NULLIF(current_setting('nova.fixture_purge_revocation_id',true),'')
    AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id));
CREATE POLICY media_revocations_purge_verifier_read ON public.media_key_revocations FOR SELECT TO nova_media_purge_verifier
  USING (current_user='nova_media_purge_verifier'
    AND (id::text=NULLIF(current_setting('nova.fixture_purge_revocation_id',true),'')
      OR moderation_action_id::text=NULLIF(current_setting('nova.fixture_purge_action_id',true),''))
    AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id));
CREATE POLICY media_revocations_purge_verifier_lock ON public.media_key_revocations FOR UPDATE TO nova_media_purge_verifier
  USING (current_user='nova_media_purge_verifier'
    AND id::text=NULLIF(current_setting('nova.fixture_purge_revocation_id',true),'')
    AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id))
  WITH CHECK (current_user='nova_media_purge_verifier'
    AND id::text=NULLIF(current_setting('nova.fixture_purge_revocation_id',true),'')
    AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id));
CREATE POLICY media_revocations_purge_verifier_delete ON public.media_key_revocations FOR DELETE TO nova_media_purge_verifier
  USING (current_user='nova_media_purge_verifier'
    AND id::text=NULLIF(current_setting('nova.fixture_purge_revocation_id',true),'')
    AND EXISTS (SELECT 1 FROM nova_security_fixture.media_purge_attestations v
      WHERE v.revocation_id=media_key_revocations.id AND v.media_id=media_key_revocations.media_id
        AND v.moderation_action_id=media_key_revocations.moderation_action_id
        AND v.source_key=media_key_revocations.source_key)
    AND EXISTS (SELECT 1 FROM nova_security_fixture.media_removal_authoritative_outcomes o
      WHERE o.revocation_id=media_key_revocations.id AND o.media_id=media_key_revocations.media_id
        AND o.moderation_action_id=media_key_revocations.moderation_action_id
        AND o.source_key=media_key_revocations.source_key
        AND o.purge_scope='storage_object_and_all_cache_variants'
        AND o.outcome='media_removed_and_cache_purged'));
GRANT SELECT (id,action,metadata) ON public.moderation_actions TO nova_media_purge_verifier;
GRANT UPDATE (metadata) ON public.moderation_actions TO nova_media_purge_verifier;
CREATE POLICY moderation_actions_purge_verifier_read ON public.moderation_actions FOR SELECT TO nova_media_purge_verifier
  USING (current_user='nova_media_purge_verifier'
    AND id::text=NULLIF(current_setting('nova.fixture_purge_action_id',true),''));
CREATE POLICY moderation_actions_purge_verifier_update ON public.moderation_actions FOR UPDATE TO nova_media_purge_verifier
  USING (current_user='nova_media_purge_verifier'
    AND id::text=NULLIF(current_setting('nova.fixture_purge_action_id',true),'')
    AND action='hide_story' AND metadata->>'removalStatus'='pending')
  WITH CHECK (current_user='nova_media_purge_verifier'
    AND id::text=NULLIF(current_setting('nova.fixture_purge_action_id',true),'')
    AND action='hide_story' AND metadata->>'removalStatus'='verified');

GRANT SELECT (id,owner_id,purpose,status) ON public.media_assets TO nova_media_reference_guard_owner;
GRANT SELECT (media_id) ON public.media_key_revocations TO nova_media_reference_guard_owner;
CREATE POLICY media_reference_guard_media_read ON public.media_assets FOR SELECT TO nova_media_reference_guard_owner
  USING (id::text=NULLIF(current_setting('nova.fixture_reference_media_id',true),''));
CREATE POLICY media_reference_guard_revocation_read ON public.media_key_revocations FOR SELECT TO nova_media_reference_guard_owner
  USING (media_id::text=NULLIF(current_setting('nova.fixture_reference_media_id',true),''));

GRANT SELECT (id,moderator_id,target_type,target_id,action) ON public.moderation_actions TO nova_revocation_enqueuer_owner;
GRANT SELECT (id,owner_id,purpose,object_key,mime_type,status), UPDATE (object_key,updated_at)
  ON public.media_assets TO nova_revocation_enqueuer_owner;
GRANT SELECT (id,author_id,cover_media_id,status,visibility,deleted_at) ON public.stories TO nova_revocation_enqueuer_owner;
GRANT INSERT (id,media_id,source_key,moderation_action_id) ON public.media_key_revocations TO nova_revocation_enqueuer_owner;
CREATE POLICY revocation_enqueuer_action_read ON public.moderation_actions FOR SELECT TO nova_revocation_enqueuer_owner
  USING (id::text=NULLIF(current_setting('nova.fixture_enqueue_action_id',true),''));
CREATE POLICY revocation_enqueuer_media_read ON public.media_assets FOR SELECT TO nova_revocation_enqueuer_owner
  USING (id::text=NULLIF(current_setting('nova.fixture_enqueue_media_id',true),''));
CREATE POLICY revocation_enqueuer_media_update ON public.media_assets FOR UPDATE TO nova_revocation_enqueuer_owner
  USING (id::text=NULLIF(current_setting('nova.fixture_enqueue_media_id',true),''))
  WITH CHECK (id::text=NULLIF(current_setting('nova.fixture_enqueue_media_id',true),''));
CREATE POLICY revocation_enqueuer_story_read ON public.stories FOR SELECT TO nova_revocation_enqueuer_owner
  USING (id::text=NULLIF(current_setting('nova.fixture_enqueue_story_id',true),'')
    OR (author_id::text=NULLIF(current_setting('nova.fixture_enqueue_user_id',true),'')
      AND cover_media_id::text=NULLIF(current_setting('nova.fixture_enqueue_media_id',true),'')
      AND status::text='published' AND visibility::text='public' AND deleted_at IS NULL));
CREATE POLICY revocation_enqueuer_revocation_insert ON public.media_key_revocations FOR INSERT TO nova_revocation_enqueuer_owner
  WITH CHECK (media_id::text=NULLIF(current_setting('nova.fixture_enqueue_media_id',true),'')
    AND moderation_action_id::text=NULLIF(current_setting('nova.fixture_enqueue_action_id',true),''));

GRANT SELECT (id,author_id,status,visibility,deleted_at,version,published_at,title,body,cover_media_id,comments_open),
  UPDATE (status,visibility,comments_open,published_at,version,updated_at)
  ON public.stories TO nova_story_moderation_manager;
GRANT SELECT (id,moderator_id,target_type,target_id,action,metadata,created_at),
  INSERT (id,moderator_id,target_type,target_id,action,reason,metadata)
  ON public.moderation_actions TO nova_story_moderation_manager;
CREATE POLICY story_moderation_manager_story_read ON public.stories FOR SELECT TO nova_story_moderation_manager
  USING (id::text=NULLIF(current_setting('nova.fixture_story_id',true),'')
    AND public.nova_rls_actor_active() AND public.nova_rls_actor_has_role(ARRAY['moderator','admin']));
CREATE POLICY story_moderation_manager_story_update ON public.stories FOR UPDATE TO nova_story_moderation_manager
  USING (id::text=NULLIF(current_setting('nova.fixture_story_id',true),'')
    AND public.nova_rls_actor_active() AND public.nova_rls_actor_has_role(ARRAY['moderator','admin']))
  WITH CHECK (id::text=NULLIF(current_setting('nova.fixture_story_id',true),'')
    AND public.nova_rls_actor_active() AND public.nova_rls_actor_has_role(ARRAY['moderator','admin']));
CREATE POLICY story_moderation_manager_action_read ON public.moderation_actions FOR SELECT TO nova_story_moderation_manager
  USING (id::text=NULLIF(current_setting('nova.fixture_story_action_id',true),'')
    OR (target_type::text='story' AND target_id::text=NULLIF(current_setting('nova.fixture_story_id',true),'')
      AND action='hide_story' AND NULLIF(current_setting('nova.fixture_story_action_type',true),'')='restore_story'));
CREATE POLICY story_moderation_manager_action_insert ON public.moderation_actions FOR INSERT TO nova_story_moderation_manager
  WITH CHECK (id::text=NULLIF(current_setting('nova.fixture_story_action_id',true),'')
    AND moderator_id=public.nova_rls_uid() AND target_type::text='story'
    AND target_id::text=NULLIF(current_setting('nova.fixture_story_id',true),'')
    AND action IN ('hide_story','restore_story')
    AND action::text=NULLIF(current_setting('nova.fixture_story_action_type',true),'')
    AND public.nova_rls_actor_active()
    AND public.nova_rls_actor_has_role(ARRAY['moderator','admin']));

CREATE OR REPLACE FUNCTION public.nova_rls_actor_active()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT EXISTS (SELECT 1 FROM public.users u WHERE u.id=public.nova_rls_uid()
    AND u.auth_subject=public.nova_rls_subject() AND u.status::text='active')
$$;
CREATE OR REPLACE FUNCTION public.nova_rls_actor_has_role(allowed text[])
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT EXISTS (SELECT 1 FROM public.users u WHERE u.id=public.nova_rls_uid()
    AND u.auth_subject=public.nova_rls_subject() AND u.status::text='active'
    AND u.role::text=NULLIF(pg_catalog.btrim(pg_catalog.current_setting('app.user_role',true)),'')
    AND u.role::text=ANY(allowed))
$$;
CREATE OR REPLACE FUNCTION public.nova_rls_own_media_revocation_pending(target uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
  SELECT pg_catalog.pg_has_role(session_user,'nova_fastify_runtime','SET')
    AND public.nova_rls_actor_active()
    AND public.nova_rls_actor_has_role(ARRAY['reader','moderator','support','security','admin'])
    AND EXISTS (
    SELECT 1 FROM public.media_assets m JOIN public.media_key_revocations r ON r.media_id=m.id
    WHERE m.id=target AND m.owner_id=public.nova_rls_uid())
$$;
CREATE OR REPLACE FUNCTION public.nova_rls_valid_moderation_action(p_action_id uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v_action record;
BEGIN
  IF p_action_id IS NULL THEN RETURN false; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_action_predicate_id',p_action_id::text,true);
  SELECT id,action,target_type,target_id INTO v_action FROM public.moderation_actions WHERE id=p_action_id;
  IF NOT FOUND THEN RETURN false; END IF;
  IF v_action.action='hide_story' AND v_action.target_type::text='story' THEN
    PERFORM pg_catalog.set_config('nova.fixture_action_story_id',v_action.target_id::text,true);
    RETURN EXISTS (SELECT 1 FROM public.stories s WHERE s.id=v_action.target_id
      AND s.status::text='removed' AND s.visibility::text='private' AND s.deleted_at IS NULL);
  END IF;
  RETURN false;
END $$;
CREATE OR REPLACE FUNCTION public.nova_rls_valid_media_revocation(p_media_id uuid,p_source_key text,p_action_id uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v_action record; v_media record; v_related boolean; v_ext text;
BEGIN
  IF p_media_id IS NULL OR p_action_id IS NULL OR p_source_key IS NULL THEN RETURN false; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_media_action_id',p_action_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_media_id',p_media_id::text,true);
  SELECT id,action,target_type,target_id INTO v_action FROM public.moderation_actions WHERE id=p_action_id;
  IF NOT FOUND OR v_action.action<>'hide_story' OR v_action.target_type::text<>'story' THEN RETURN false; END IF;
  SELECT id,owner_id,purpose,status,mime_type INTO v_media FROM public.media_assets WHERE id=p_media_id;
  IF NOT FOUND OR v_media.purpose<>'cover' OR v_media.status::text<>'ready' THEN RETURN false; END IF;
  v_ext:=CASE v_media.mime_type WHEN 'image/jpeg' THEN 'jpg' WHEN 'image/png' THEN 'png' WHEN 'image/webp' THEN 'webp' END;
  IF p_source_key IS DISTINCT FROM 'ready/'||v_media.owner_id::text||'/'||v_media.id::text||'.'||v_ext THEN RETURN false; END IF;
  IF v_action.action='hide_story' AND v_action.target_type::text='story' THEN
    PERFORM pg_catalog.set_config('nova.fixture_media_story_id',v_action.target_id::text,true);
    SELECT EXISTS (SELECT 1 FROM public.stories s WHERE s.id=v_action.target_id
      AND s.cover_media_id=v_media.id AND s.author_id=v_media.owner_id
      AND s.status::text='removed' AND s.visibility::text='private' AND s.deleted_at IS NULL) INTO v_related;
  ELSE
    RETURN false;
  END IF;
  RETURN v_related;
END $$;
CREATE OR REPLACE FUNCTION public.nova_rls_valid_report_target(p_target_type public.report_target_type,p_target_id uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF p_target_type IS NULL OR p_target_id IS NULL THEN RETURN false; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_reports_target_type',p_target_type::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_reports_target_id',p_target_id::text,true);
  IF p_target_type::text<>'story' THEN RETURN false; END IF;
  RETURN EXISTS (SELECT 1 FROM public.moderation_actions a JOIN public.stories s ON s.id=a.target_id
    WHERE a.target_type=p_target_type AND a.target_id=p_target_id AND a.action='hide_story'
      AND s.status::text='removed' AND s.visibility::text='private' AND s.deleted_at IS NULL);
END $$;
CREATE OR REPLACE FUNCTION public.nova_rls_target_has_pending_revocation(p_target_type public.report_target_type,p_target_id uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF p_target_type IS NULL OR p_target_id IS NULL THEN RETURN false; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_reports_target_type',p_target_type::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_reports_target_id',p_target_id::text,true);
  RETURN EXISTS (SELECT 1 FROM public.media_key_revocations r
    JOIN public.moderation_actions a ON a.id=r.moderation_action_id
    WHERE a.target_type=p_target_type AND a.target_id=p_target_id
      AND public.nova_rls_valid_media_revocation(r.id,r.media_id,r.source_key,r.moderation_action_id));
END $$;
CREATE OR REPLACE FUNCTION public.nova_rls_target_removal_resolved(p_target_type public.report_target_type,p_target_id uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF p_target_type IS NULL OR p_target_id IS NULL THEN RETURN false; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_reports_target_type',p_target_type::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_reports_target_id',p_target_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_reports_story_id',p_target_id::text,true);
  RETURN (
    EXISTS (SELECT 1 FROM public.moderation_actions a
      JOIN nova_security_fixture.media_purge_attestations att ON att.moderation_action_id=a.id
      JOIN nova_security_fixture.media_removal_authoritative_outcomes outcome
        ON outcome.revocation_id=att.revocation_id AND outcome.moderation_action_id=a.id
      WHERE a.target_type=p_target_type AND a.target_id=p_target_id AND a.action='hide_story'
        AND a.metadata->>'removalStatus'='verified'
        AND att.attested_by='nova_media_purge_attester'
        AND outcome.outcome='media_removed_and_cache_purged'
        AND outcome.confirmed_by='nova_media_removal_authority'
        AND outcome.purge_scope='storage_object_and_all_cache_variants')
    AND NOT EXISTS (SELECT 1 FROM public.media_key_revocations r
      JOIN public.moderation_actions a ON a.id=r.moderation_action_id
      WHERE a.target_type=p_target_type AND a.target_id=p_target_id)
  ) OR EXISTS (
    SELECT 1 FROM public.moderation_actions a
      JOIN public.media_no_media_required n ON n.action_id=a.id
      JOIN public.stories s ON s.id=a.target_id
    WHERE a.target_type=p_target_type AND a.target_id=p_target_id AND a.action='hide_story'
      AND a.metadata->>'removalStatus'='no_media_required'
      AND n.result='no_media_required' AND s.cover_media_id IS NULL
      AND s.status::text='removed' AND s.visibility::text='private' AND s.deleted_at IS NULL);
END $$;

CREATE OR REPLACE FUNCTION public.nova_stories_avatar_reference_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.avatar_media_id IS NOT NULL THEN
    PERFORM pg_catalog.set_config('nova.fixture_reference_media_id',NEW.avatar_media_id::text,true);
    IF NOT EXISTS (SELECT 1 FROM public.media_assets m WHERE m.id=NEW.avatar_media_id
      AND m.owner_id=NEW.id AND m.purpose='avatar' AND m.status::text='ready'
      AND NOT EXISTS (SELECT 1 FROM public.media_key_revocations r WHERE r.media_id=m.id)) THEN
      RAISE EXCEPTION 'invalid avatar media reference' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION public.nova_stories_cover_reference_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.cover_media_id IS NOT NULL THEN
    PERFORM pg_catalog.set_config('nova.fixture_reference_media_id',NEW.cover_media_id::text,true);
    IF NOT EXISTS (SELECT 1 FROM public.media_assets m WHERE m.id=NEW.cover_media_id
      AND m.owner_id=NEW.author_id AND m.purpose='cover' AND m.status::text='ready'
      AND NOT EXISTS (SELECT 1 FROM public.media_key_revocations r WHERE r.media_id=m.id)) THEN
      RAISE EXCEPTION 'invalid story cover media reference' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION public.nova_feedback_screenshot_reference_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.screenshot_media_id IS NOT NULL THEN
    PERFORM pg_catalog.set_config('nova.fixture_reference_media_id',NEW.screenshot_media_id::text,true);
    IF NOT EXISTS (SELECT 1 FROM public.media_assets m WHERE m.id=NEW.screenshot_media_id
      AND m.owner_id=NEW.reporter_id AND m.purpose='feedback_screenshot' AND m.status::text='ready') THEN
      RAISE EXCEPTION 'invalid feedback screenshot reference' USING ERRCODE='23514';
    END IF;
  END IF;
  IF NEW.screenshot_media_id IS NOT NULL AND NEW.expires_at<=pg_catalog.now()
     AND (TG_OP='INSERT' OR NEW.screenshot_media_id IS DISTINCT FROM OLD.screenshot_media_id) THEN
    RAISE EXCEPTION 'expired feedback cannot attach a screenshot' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION public.nova_revocation_worker_update_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE v_delay interval;
BEGIN
  IF current_user='nova_media_purge_verifier' AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'purge verifier may lock but not mutate retry state' USING ERRCODE='42501';
  END IF;
  IF current_user='nova_media_revocation_worker' AND (
    OLD.retry_after>pg_catalog.statement_timestamp() OR OLD.escalated_at IS NOT NULL OR OLD.attempt_count>=5
    OR NEW.attempt_count<>OLD.attempt_count+1
    OR (to_jsonb(NEW)-ARRAY['attempt_count','retry_after','escalated_at']) IS DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['attempt_count','retry_after','escalated_at'])
  ) THEN RAISE EXCEPTION 'revocation retry transition denied' USING ERRCODE='42501'; END IF;
  IF current_user='nova_media_revocation_worker' THEN
    v_delay:=CASE NEW.attempt_count WHEN 1 THEN interval '30 seconds' WHEN 2 THEN interval '2 minutes'
      WHEN 3 THEN interval '10 minutes' WHEN 4 THEN interval '30 minutes' WHEN 5 THEN interval '2 hours' END;
    IF v_delay IS NULL OR NEW.retry_after IS DISTINCT FROM pg_catalog.statement_timestamp()+v_delay
       OR (NEW.attempt_count<5 AND NEW.escalated_at IS NOT NULL)
       OR (NEW.attempt_count=5 AND NEW.escalated_at IS DISTINCT FROM pg_catalog.statement_timestamp()) THEN
      RAISE EXCEPTION 'revocation retry schedule/escalation denied' USING ERRCODE='42501';
    END IF;
  END IF;
  RETURN NEW;
END $$;
DROP POLICY media_revocations_worker_update ON public.media_key_revocations;
CREATE POLICY media_revocations_worker_update ON public.media_key_revocations FOR UPDATE TO nova_media_revocation_worker
  USING (current_user='nova_media_revocation_worker' AND retry_after<=pg_catalog.statement_timestamp()
    AND attempt_count<5 AND escalated_at IS NULL
    AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id))
  WITH CHECK (current_user='nova_media_revocation_worker' AND attempt_count BETWEEN 1 AND 5
    AND ((attempt_count<5 AND escalated_at IS NULL) OR (attempt_count=5 AND escalated_at IS NOT NULL))
    AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id));
REVOKE DELETE ON public.media_key_revocations FROM nova_media_revocation_worker;
DROP POLICY media_revocations_worker_read ON public.media_key_revocations;
CREATE POLICY media_revocations_worker_read ON public.media_key_revocations FOR SELECT TO nova_media_revocation_worker
  USING (current_user='nova_media_revocation_worker' AND attempt_count BETWEEN 0 AND 5
    AND public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id));
DROP POLICY IF EXISTS media_revocations_staff_read ON public.media_key_revocations;
REVOKE SELECT (id,media_id,moderation_action_id) ON public.media_key_revocations FROM nova_fastify_runtime;

CREATE OR REPLACE FUNCTION public.nova_stories_update_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE is_owner boolean; action_type text;
BEGIN
  IF current_user='nova_story_moderation_manager' THEN
    action_type:=NULLIF(pg_catalog.current_setting('nova.fixture_story_action_type',true),'');
    IF NOT public.nova_rls_actor_active()
       OR NOT public.nova_rls_actor_has_role(ARRAY['moderator','admin'])
       OR NOT EXISTS (SELECT 1 FROM public.moderation_actions a
         WHERE a.id::text=NULLIF(pg_catalog.current_setting('nova.fixture_story_action_id',true),'')
           AND a.moderator_id=public.nova_rls_uid() AND a.target_type::text='story'
           AND a.target_id=OLD.id AND a.action=action_type) THEN
      RAISE EXCEPTION 'moderation transition requires a linked allowlisted action' USING ERRCODE='42501';
    END IF;
    IF action_type='hide_story' THEN
      IF OLD.status::text NOT IN ('draft','published') OR OLD.deleted_at IS NOT NULL
         OR NEW.status::text<>'removed' OR NEW.visibility::text<>'private'
         OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at OR NEW.published_at IS DISTINCT FROM OLD.published_at
         OR NEW.comments_open OR NEW.version<>OLD.version+1
         OR (to_jsonb(NEW)-ARRAY['status','visibility','comments_open','version','updated_at']) IS DISTINCT FROM
            (to_jsonb(OLD)-ARRAY['status','visibility','comments_open','version','updated_at']) THEN
        RAISE EXCEPTION 'invalid atomic story hide' USING ERRCODE='42501';
      END IF;
    ELSIF action_type='restore_story' THEN
      IF OLD.status::text<>'removed' OR OLD.deleted_at IS NOT NULL
         OR NEW.status::text NOT IN ('draft','published') OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at
         OR (NEW.status::text='draft' AND (NEW.visibility::text<>'private' OR NEW.published_at IS NOT NULL))
         OR (NEW.status::text='published' AND (NEW.visibility::text<>'public' OR NEW.published_at IS NULL))
         OR NEW.version<>OLD.version+1
         OR (to_jsonb(NEW)-ARRAY['status','visibility','published_at','comments_open','version','updated_at']) IS DISTINCT FROM
            (to_jsonb(OLD)-ARRAY['status','visibility','published_at','comments_open','version','updated_at']) THEN
        RAISE EXCEPTION 'invalid atomic story restore' USING ERRCODE='42501';
      END IF;
    ELSE
      RAISE EXCEPTION 'unsupported moderation action type' USING ERRCODE='42501';
    END IF;
    RETURN NEW;
  END IF;
  IF current_user='nova_story_lifecycle_manager' THEN RETURN NEW; END IF;
  IF current_user<>'nova_fastify_runtime' THEN RETURN NEW; END IF;
  is_owner:=OLD.author_id=public.nova_rls_uid() AND public.nova_rls_actor_active();
  IF is_owner THEN
    IF (NEW.status,NEW.visibility,NEW.published_at,NEW.deleted_at) IS DISTINCT FROM
       (OLD.status,OLD.visibility,OLD.published_at,OLD.deleted_at) THEN
      RAISE EXCEPTION 'story lifecycle transition requires the controlled path' USING ERRCODE='42501';
    END IF;
    IF (to_jsonb(NEW)-ARRAY['title','summary','body','cover_media_id','comments_open','version','updated_at']) IS DISTINCT FROM
       (to_jsonb(OLD)-ARRAY['title','summary','body','cover_media_id','comments_open','version','updated_at']) THEN
      RAISE EXCEPTION 'story owner update denied' USING ERRCODE='42501';
    END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'cross-owner story update requires an atomic moderation procedure' USING ERRCODE='42501';
END $$;
CREATE OR REPLACE FUNCTION public.nova_moderate_hide_story(p_story_id uuid,p_reason text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v_story record; v_action_id uuid;
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'nova_fastify_runtime','SET')
     OR p_story_id IS NULL OR pg_catalog.length(pg_catalog.btrim(COALESCE(p_reason,''))) NOT BETWEEN 1 AND 1000
     OR NOT public.nova_rls_actor_active() OR NOT public.nova_rls_actor_has_role(ARRAY['moderator','admin']) THEN
    RAISE EXCEPTION 'moderation hide denied' USING ERRCODE='42501';
  END IF;
  v_action_id:=pg_catalog.gen_random_uuid();
  PERFORM pg_catalog.set_config('nova.fixture_story_id',p_story_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_story_action_id',v_action_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_story_action_type','hide_story',true);
  SELECT id,author_id,status,visibility,published_at,deleted_at,cover_media_id,comments_open
    INTO v_story FROM public.stories WHERE id=p_story_id FOR UPDATE;
  IF NOT FOUND OR v_story.status::text NOT IN ('draft','published') OR v_story.deleted_at IS NOT NULL THEN
    RAISE EXCEPTION 'moderation hide denied' USING ERRCODE='42501';
  END IF;
  INSERT INTO public.moderation_actions(id,moderator_id,target_type,target_id,action,reason,metadata)
    VALUES(v_action_id,public.nova_rls_uid(),'story',p_story_id,'hide_story',p_reason,
      pg_catalog.jsonb_build_object(
        'priorStatus',v_story.status::text,
        'priorVisibility',v_story.visibility::text,
        'priorPublishedAt',v_story.published_at,
        'priorCommentsOpen',v_story.comments_open,
        'removalStatus',CASE WHEN v_story.cover_media_id IS NULL THEN 'no_media_required' ELSE 'pending' END));
  UPDATE public.stories SET status='removed',visibility='private',comments_open=false,
    version=version+1,updated_at=pg_catalog.now() WHERE id=p_story_id;
  IF v_story.cover_media_id IS NULL THEN
    INSERT INTO public.media_no_media_required(action_id,target_story_id,result,recorded_by,recorded_at)
      VALUES(v_action_id,p_story_id,'no_media_required',current_user,pg_catalog.statement_timestamp());
  END IF;
  RETURN v_action_id;
END $$;

DROP FUNCTION IF EXISTS public.nova_moderate_restore_story(uuid,text,text);
CREATE OR REPLACE FUNCTION public.nova_moderate_restore_story(
  p_story_id uuid,p_expected_hide_action_id uuid,p_reason text
)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
  v_story record;
  v_action_id uuid;
  v_hide_action_id uuid;
  v_prior_status text;
  v_prior_visibility public.story_visibility;
  v_prior_published_at timestamptz;
  v_prior_comments_open boolean;
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'nova_fastify_runtime','SET')
     OR p_story_id IS NULL OR p_expected_hide_action_id IS NULL
     OR pg_catalog.length(pg_catalog.btrim(COALESCE(p_reason,''))) NOT BETWEEN 1 AND 1000
     OR NOT public.nova_rls_actor_active() OR NOT public.nova_rls_actor_has_role(ARRAY['moderator','admin']) THEN
    RAISE EXCEPTION 'moderation restore denied' USING ERRCODE='42501';
  END IF;
  v_action_id:=pg_catalog.gen_random_uuid();
  PERFORM pg_catalog.set_config('nova.fixture_story_id',p_story_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_story_action_id',v_action_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_story_action_type','restore_story',true);
  SELECT id,author_id,status,visibility,deleted_at,title,body INTO v_story
    FROM public.stories WHERE id=p_story_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'stale story restore' USING ERRCODE='40001'; END IF;

  -- The Story lock serializes concurrent hide/restore calls; only then read the latest hide audit.
  SELECT audit_action.id,audit_action.metadata->>'priorStatus',
         (audit_action.metadata->>'priorVisibility')::public.story_visibility,
         (audit_action.metadata->>'priorPublishedAt')::timestamptz,
         (audit_action.metadata->>'priorCommentsOpen')::boolean
    INTO v_hide_action_id,v_prior_status,v_prior_visibility,v_prior_published_at,v_prior_comments_open
    FROM public.moderation_actions audit_action
    WHERE audit_action.target_type='story' AND audit_action.target_id=p_story_id
      AND audit_action.action='hide_story'
    ORDER BY audit_action.created_at DESC,audit_action.id DESC LIMIT 1;
  IF NOT FOUND OR v_hide_action_id IS DISTINCT FROM p_expected_hide_action_id
     OR v_story.status::text<>'removed' OR v_story.deleted_at IS NOT NULL
     OR v_prior_status IS NULL OR v_prior_status NOT IN ('draft','published')
     OR v_prior_visibility IS NULL OR v_prior_comments_open IS NULL
     OR public.nova_rls_target_has_pending_revocation('story',p_story_id)
     OR (v_prior_status='published' AND (pg_catalog.btrim(v_story.title)='' OR pg_catalog.btrim(v_story.body)='')) THEN
    RAISE EXCEPTION 'stale story restore' USING ERRCODE='40001';
  END IF;

  INSERT INTO public.moderation_actions(id,moderator_id,target_type,target_id,action,reason,metadata)
    VALUES(v_action_id,public.nova_rls_uid(),'story',p_story_id,'restore_story',p_reason,
      pg_catalog.jsonb_build_object('restoreStatus',v_prior_status,
        'restoredVisibility',v_prior_visibility::text,'restoredPublishedAt',v_prior_published_at,
        'restoredCommentsOpen',v_prior_comments_open,'restoreFromHideActionId',v_hide_action_id));
  UPDATE public.stories SET status=v_prior_status::public.story_status,
    visibility=v_prior_visibility,published_at=v_prior_published_at,
    comments_open=v_prior_comments_open,version=version+1,updated_at=pg_catalog.now()
    WHERE id=p_story_id;
  RETURN v_action_id;
END $$;

CREATE OR REPLACE FUNCTION public.nova_transition_story(target uuid,transition text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE current_story record;
BEGIN
  IF transition NOT IN ('publish','unpublish','soft_delete') THEN RAISE EXCEPTION 'unsupported story transition' USING ERRCODE='22023'; END IF;
  IF NOT public.nova_rls_actor_active() THEN RAISE EXCEPTION 'story transition denied' USING ERRCODE='42501'; END IF;
  SELECT id,status,deleted_at,title,body,version INTO current_story FROM public.stories
    WHERE id=target AND author_id=public.nova_rls_uid() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'story transition denied' USING ERRCODE='42501'; END IF;
  IF transition='publish' THEN
    IF current_story.status::text<>'draft' OR current_story.deleted_at IS NOT NULL
       OR pg_catalog.btrim(current_story.title)='' OR pg_catalog.btrim(current_story.body)='' THEN
      RAISE EXCEPTION 'invalid publish transition' USING ERRCODE='42501';
    END IF;
    UPDATE public.stories SET status='published',visibility='public',published_at=pg_catalog.now(),
      comments_open=true,version=version+1,updated_at=pg_catalog.now() WHERE id=target;
  ELSIF transition='unpublish' THEN
    IF current_story.status::text<>'published' OR current_story.deleted_at IS NOT NULL THEN RAISE EXCEPTION 'invalid unpublish transition' USING ERRCODE='42501'; END IF;
    UPDATE public.stories SET status='draft',visibility='private',published_at=NULL,comments_open=false,
      version=version+1,updated_at=pg_catalog.now() WHERE id=target;
  ELSE
    IF current_story.status::text='removed' OR current_story.deleted_at IS NOT NULL THEN RAISE EXCEPTION 'invalid soft-delete transition' USING ERRCODE='42501'; END IF;
    UPDATE public.stories SET status='removed',visibility='private',deleted_at=pg_catalog.now(),comments_open=false,
      version=version+1,updated_at=pg_catalog.now() WHERE id=target;
  END IF;
  RETURN true;
END $$;

DROP FUNCTION IF EXISTS public.nova_complete_media_upload(uuid,bigint,text,bigint);
DROP FUNCTION IF EXISTS public.nova_complete_media_upload(uuid,bigint,text,boolean);
DROP FUNCTION IF EXISTS public.nova_complete_media_upload(uuid,bigint,text);
DROP FUNCTION IF EXISTS public.nova_record_media_upload_verification(uuid,bigint,text,text);

CREATE FUNCTION public.nova_begin_media_upload(target uuid)
RETURNS TABLE(upload_nonce uuid,object_key text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE item record; extension text; v_nonce uuid; v_key text;
BEGIN
  IF target IS NULL OR NOT public.nova_rls_actor_active() THEN RAISE EXCEPTION 'media upload begin denied' USING ERRCODE='42501'; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_upload_media_id',target::text,true);
  SELECT id,owner_id,purpose,status,mime_type INTO item FROM public.media_assets
    WHERE id=target AND owner_id=public.nova_rls_uid() FOR UPDATE;
  IF NOT FOUND OR item.status::text<>'pending' THEN RAISE EXCEPTION 'media upload begin denied' USING ERRCODE='42501'; END IF;
  extension:=CASE item.mime_type WHEN 'image/jpeg' THEN 'jpg' WHEN 'image/png' THEN 'png' WHEN 'image/webp' THEN 'webp' END;
  v_nonce:=pg_catalog.gen_random_uuid();
  v_key:='pending/'||item.owner_id::text||'/'||item.id::text||'/'||v_nonce::text||'.'||extension;
  DELETE FROM nova_security_fixture.media_upload_verifications WHERE media_id=target;
  UPDATE public.media_assets SET status='processing',upload_nonce=v_nonce,object_key=v_key,updated_at=pg_catalog.now()
    WHERE id=target;
  RETURN QUERY SELECT v_nonce,v_key;
END $$;

CREATE FUNCTION public.nova_cancel_media_upload(target uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE item record;
BEGIN
  IF target IS NULL OR NOT public.nova_rls_actor_active() THEN RAISE EXCEPTION 'media upload cancel denied' USING ERRCODE='42501'; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_upload_media_id',target::text,true);
  SELECT id,status INTO item FROM public.media_assets
    WHERE id=target AND owner_id=public.nova_rls_uid() FOR UPDATE;
  IF NOT FOUND OR item.status::text<>'processing' THEN RAISE EXCEPTION 'media upload cancel denied' USING ERRCODE='42501'; END IF;
  DELETE FROM nova_security_fixture.media_upload_verifications WHERE media_id=target;
  UPDATE public.media_assets SET status='pending',updated_at=pg_catalog.now() WHERE id=target;
  RETURN true;
END $$;

CREATE FUNCTION public.nova_record_media_upload_verification(p_media_id uuid,p_upload_nonce uuid,
  p_storage_object_version text,p_measured_size bigint,p_checksum_sha256 text,p_audit_ref text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE item record; max_bytes bigint; extension text;
BEGIN
  IF p_media_id IS NULL OR p_upload_nonce IS NULL OR p_storage_object_version IS NULL
     OR pg_catalog.btrim(p_storage_object_version)='' OR pg_catalog.length(p_storage_object_version)>300
     OR p_measured_size<1 OR p_checksum_sha256 !~ '^[0-9a-f]{64}$'
     OR p_audit_ref IS NULL OR pg_catalog.btrim(p_audit_ref)='' OR pg_catalog.length(p_audit_ref)>500 THEN
    RAISE EXCEPTION 'trusted upload verification denied' USING ERRCODE='42501';
  END IF;
  PERFORM pg_catalog.set_config('nova.fixture_upload_media_id',p_media_id::text,true);
  SELECT id,owner_id,purpose,status,object_key,mime_type,upload_nonce INTO item FROM public.media_assets
    WHERE id=p_media_id FOR UPDATE;
  extension:=CASE item.mime_type WHEN 'image/jpeg' THEN 'jpg' WHEN 'image/png' THEN 'png' WHEN 'image/webp' THEN 'webp' END;
  IF NOT FOUND OR item.status::text<>'processing' OR item.upload_nonce IS DISTINCT FROM p_upload_nonce
     OR item.object_key IS DISTINCT FROM ('pending/'||item.owner_id::text||'/'||item.id::text||'/'||item.upload_nonce::text||'.'||extension) THEN
    RAISE EXCEPTION 'trusted upload verification denied' USING ERRCODE='42501';
  END IF;
  max_bytes:=CASE item.purpose WHEN 'cover' THEN 10485760 ELSE 5242880 END;
  IF p_measured_size>max_bytes THEN RAISE EXCEPTION 'verified upload exceeds server limit' USING ERRCODE='22023'; END IF;
  INSERT INTO nova_security_fixture.media_upload_verifications
    (media_id,owner_id,upload_nonce,source_key,storage_object_version,measured_size,checksum_sha256,audit_ref,verified_by,verified_at)
  VALUES(item.id,item.owner_id,item.upload_nonce,item.object_key,p_storage_object_version,p_measured_size,
    p_checksum_sha256,p_audit_ref,current_user,pg_catalog.statement_timestamp());
  RETURN true;
END $$;

CREATE OR REPLACE FUNCTION public.nova_complete_media_upload(target uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE item record; proof record; extension text; ready_key text; max_bytes bigint;
BEGIN
  IF target IS NULL OR NOT public.nova_rls_actor_active() THEN RAISE EXCEPTION 'media completion denied' USING ERRCODE='42501'; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_upload_media_id',target::text,true);
  SELECT id,owner_id,purpose,status,object_key,mime_type,upload_nonce INTO item FROM public.media_assets
    WHERE id=target AND owner_id=public.nova_rls_uid() FOR UPDATE;
  extension:=CASE item.mime_type WHEN 'image/jpeg' THEN 'jpg' WHEN 'image/png' THEN 'png' WHEN 'image/webp' THEN 'webp' END;
  IF NOT FOUND OR item.status::text<>'processing' OR item.object_key IS DISTINCT FROM
      ('pending/'||item.owner_id::text||'/'||item.id::text||'/'||item.upload_nonce::text||'.'||extension) THEN
    RAISE EXCEPTION 'media completion denied' USING ERRCODE='42501';
  END IF;
  SELECT media_id,owner_id,upload_nonce,source_key,storage_object_version,measured_size,checksum_sha256,audit_ref,verified_by
    INTO proof FROM nova_security_fixture.media_upload_verifications WHERE media_id=target;
  IF NOT FOUND OR proof.owner_id IS DISTINCT FROM item.owner_id OR proof.upload_nonce IS DISTINCT FROM item.upload_nonce
     OR proof.source_key IS DISTINCT FROM item.object_key OR proof.storage_object_version IS NULL
     OR proof.verified_by<>'nova_media_upload_verifier' OR proof.audit_ref IS NULL OR pg_catalog.btrim(proof.audit_ref)='' THEN
    RAISE EXCEPTION 'media completion requires current trusted storage verification' USING ERRCODE='42501';
  END IF;
  max_bytes:=CASE item.purpose WHEN 'cover' THEN 10485760 ELSE 5242880 END;
  IF proof.measured_size>max_bytes THEN RAISE EXCEPTION 'media completion exceeds server limit' USING ERRCODE='22023'; END IF;
  ready_key:='ready/'||item.owner_id::text||'/'||item.id::text||'.'||extension;
  UPDATE public.media_assets SET object_key=ready_key,size_bytes=proof.measured_size,checksum=proof.checksum_sha256,
    status='ready',ready_at=pg_catalog.now(),updated_at=pg_catalog.now() WHERE id=target;
  RETURN true;
END $$;

CREATE OR REPLACE FUNCTION public.nova_media_update_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE owner_actor boolean;
BEGIN
  IF current_user='nova_revocation_enqueuer_owner' THEN
    IF OLD.status::text<>'ready' OR OLD.purpose<>'cover' OR NEW.status IS DISTINCT FROM OLD.status
       OR NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.purpose IS DISTINCT FROM OLD.purpose
       OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes OR NEW.checksum IS DISTINCT FROM OLD.checksum
       OR NEW.ready_at IS DISTINCT FROM OLD.ready_at OR NEW.mime_type IS DISTINCT FROM OLD.mime_type
       OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.upload_nonce IS DISTINCT FROM OLD.upload_nonce
       OR (NEW.object_key IS NOT DISTINCT FROM OLD.object_key AND NEW.updated_at IS NOT DISTINCT FROM OLD.updated_at) THEN
      RAISE EXCEPTION 'media revocation rotation denied' USING ERRCODE='42501';
    END IF;
    RETURN NEW;
  END IF;
  IF current_user='nova_media_upload_verifier' THEN
    RAISE EXCEPTION 'upload verifier may lock but cannot modify media state' USING ERRCODE='42501';
  END IF;
  IF current_user NOT IN ('nova_fastify_runtime','nova_media_lifecycle_manager') THEN RETURN NEW; END IF;
  IF current_user='nova_media_lifecycle_manager' THEN
    IF OLD.status::text='pending' AND NEW.status::text='processing' THEN
      IF NEW.upload_nonce IS NOT DISTINCT FROM OLD.upload_nonce
         OR NEW.object_key IS DISTINCT FROM ('pending/'||OLD.owner_id::text||'/'||OLD.id::text||'/'||NEW.upload_nonce::text||'.'||
           (CASE OLD.mime_type WHEN 'image/jpeg' THEN 'jpg' WHEN 'image/png' THEN 'png' WHEN 'image/webp' THEN 'webp' END))
         OR (to_jsonb(NEW)-ARRAY['status','upload_nonce','object_key','updated_at']) IS DISTINCT FROM
            (to_jsonb(OLD)-ARRAY['status','upload_nonce','object_key','updated_at']) THEN
        RAISE EXCEPTION 'invalid nonce-bound media upload start' USING ERRCODE='42501';
      END IF;
      RETURN NEW;
    ELSIF OLD.status::text='processing' AND NEW.status::text='pending' THEN
      IF NEW.upload_nonce IS DISTINCT FROM OLD.upload_nonce OR NEW.object_key IS DISTINCT FROM OLD.object_key
         OR (to_jsonb(NEW)-ARRAY['status','updated_at']) IS DISTINCT FROM
            (to_jsonb(OLD)-ARRAY['status','updated_at']) THEN
        RAISE EXCEPTION 'invalid media upload cancellation' USING ERRCODE='42501';
      END IF;
      RETURN NEW;
    ELSIF OLD.status::text='processing' AND NEW.status::text='ready' THEN
      IF NEW.upload_nonce IS DISTINCT FROM OLD.upload_nonce
         OR NEW.object_key IS DISTINCT FROM ('ready/'||OLD.owner_id::text||'/'||OLD.id::text||'.'||
           (CASE OLD.mime_type WHEN 'image/jpeg' THEN 'jpg' WHEN 'image/png' THEN 'png' WHEN 'image/webp' THEN 'webp' END))
         OR NEW.size_bytes<1 OR NEW.checksum !~ '^[0-9a-f]{64}$' OR NEW.ready_at IS NULL
         OR (to_jsonb(NEW)-ARRAY['status','object_key','size_bytes','checksum','ready_at','updated_at']) IS DISTINCT FROM
            (to_jsonb(OLD)-ARRAY['status','object_key','size_bytes','checksum','ready_at','updated_at']) THEN
        RAISE EXCEPTION 'invalid media completion transition' USING ERRCODE='42501';
      END IF;
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'unsupported lifecycle manager media transition' USING ERRCODE='42501';
  END IF;
  owner_actor:=OLD.owner_id=public.nova_rls_uid() AND public.nova_rls_actor_active();
  IF owner_actor THEN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
      RAISE EXCEPTION 'owner must use nonce-bound begin/cancel procedures' USING ERRCODE='42501';
    END IF;
    IF (NEW.owner_id,NEW.purpose,NEW.object_key,NEW.mime_type,NEW.size_bytes,NEW.checksum,NEW.ready_at,NEW.upload_nonce) IS DISTINCT FROM
       (OLD.owner_id,OLD.purpose,OLD.object_key,OLD.mime_type,OLD.size_bytes,OLD.checksum,OLD.ready_at,OLD.upload_nonce) THEN
      RAISE EXCEPTION 'media metadata is immutable to the owner' USING ERRCODE='42501';
    END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'media update denied' USING ERRCODE='42501';
END $$;

DROP FUNCTION public.nova_enqueue_media_key_revocation(uuid,uuid,text,text);
CREATE FUNCTION public.nova_enqueue_media_key_revocation(p_media_id uuid,p_action_id uuid,
  p_expected_source_key text,p_rotated_key text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v_action record; v_media record; v_related boolean; v_ext text; v_prefix text; v_base text; v_rotation text; v_new_id uuid;
BEGIN
  IF NOT pg_catalog.pg_has_role(session_user,'nova_fastify_runtime','SET')
     OR p_media_id IS NULL OR p_action_id IS NULL OR NOT public.nova_rls_actor_active()
     OR NOT public.nova_rls_actor_has_role(ARRAY['moderator']) THEN RAISE EXCEPTION 'media revocation enqueue denied' USING ERRCODE='42501'; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_enqueue_action_id',p_action_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_enqueue_media_id',p_media_id::text,true);
  SELECT id,moderator_id,target_type,target_id,action INTO v_action FROM public.moderation_actions WHERE id=p_action_id;
  IF NOT FOUND OR v_action.moderator_id<>public.nova_rls_uid()
     OR v_action.action<>'hide_story' OR v_action.target_type::text<>'story' THEN
    RAISE EXCEPTION 'media revocation enqueue denied' USING ERRCODE='42501'; END IF;
  PERFORM pg_catalog.set_config('nova.fixture_enqueue_story_id',v_action.target_id::text,true);
  SELECT id,owner_id,purpose,object_key,mime_type,status INTO v_media FROM public.media_assets WHERE id=p_media_id FOR UPDATE;
  IF NOT FOUND OR v_media.purpose<>'cover' OR v_media.status::text<>'ready'
     OR v_media.object_key IS DISTINCT FROM p_expected_source_key THEN RAISE EXCEPTION 'media revocation enqueue denied' USING ERRCODE='42501'; END IF;
  SELECT EXISTS (SELECT 1 FROM public.stories s WHERE s.id=v_action.target_id AND s.cover_media_id=v_media.id
    AND s.author_id=v_media.owner_id AND s.status::text='removed' AND s.visibility::text='private' AND s.deleted_at IS NULL) INTO v_related;
  IF NOT v_related THEN RAISE EXCEPTION 'media revocation enqueue denied' USING ERRCODE='42501'; END IF;
  v_ext:=CASE v_media.mime_type WHEN 'image/jpeg' THEN 'jpg' WHEN 'image/png' THEN 'png' WHEN 'image/webp' THEN 'webp' END;
  v_prefix:='ready/'||v_media.owner_id::text||'/'; v_base:=v_media.id::text||'.'||v_ext;
  IF p_expected_source_key IS DISTINCT FROM v_prefix||v_base OR p_rotated_key NOT LIKE v_prefix||'%-'||v_base THEN
    RAISE EXCEPTION 'media revocation enqueue denied' USING ERRCODE='42501'; END IF;
  v_rotation:=pg_catalog.substr(p_rotated_key,pg_catalog.length(v_prefix)+1,
    pg_catalog.length(p_rotated_key)-pg_catalog.length(v_prefix)-pg_catalog.length(v_base)-1);
  IF v_rotation !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'media revocation enqueue denied' USING ERRCODE='42501'; END IF;
  UPDATE public.media_assets SET object_key=p_rotated_key,updated_at=pg_catalog.now() WHERE id=p_media_id;
  v_new_id:=pg_catalog.gen_random_uuid();
  INSERT INTO public.media_key_revocations(id,media_id,source_key,moderation_action_id)
    VALUES(v_new_id,v_media.id,p_expected_source_key,v_action.id);
  UPDATE public.reports
     SET status='reviewing',removal_pending=true,updated_at=pg_catalog.now(),
         first_response_at=COALESCE(first_response_at,pg_catalog.now()),closed_at=NULL,
         reopen_count=reopen_count+CASE WHEN status::text='closed' THEN 1 ELSE 0 END
   WHERE target_type::text='story' AND target_id=v_action.target_id;
  RETURN v_new_id;
END $$;

CREATE FUNCTION public.nova_record_media_purge_attestation(p_revocation_id uuid,p_storage_object_version text,p_attestation_ref text)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE v_queue record;
BEGIN
  IF current_user<>'nova_media_purge_attester' OR p_revocation_id IS NULL
     OR p_storage_object_version IS NULL OR pg_catalog.btrim(p_storage_object_version)=''
     OR pg_catalog.length(p_storage_object_version)>300 OR p_attestation_ref IS NULL
     OR pg_catalog.btrim(p_attestation_ref)='' OR pg_catalog.length(p_attestation_ref)>500 THEN
    RAISE EXCEPTION 'purge attestation recording denied' USING ERRCODE='42501';
  END IF;
  PERFORM pg_catalog.set_config('nova.fixture_purge_revocation_id',p_revocation_id::text,true);
  SELECT id,media_id,source_key,moderation_action_id INTO v_queue
    FROM public.media_key_revocations WHERE id=p_revocation_id;
  IF NOT FOUND OR NOT public.nova_rls_valid_media_revocation(v_queue.id,v_queue.media_id,v_queue.source_key,v_queue.moderation_action_id) THEN
    RAISE EXCEPTION 'purge attestation requires a valid queue row' USING ERRCODE='42501';
  END IF;
  PERFORM pg_catalog.set_config('nova.fixture_purge_media_id',v_queue.media_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_purge_action_id',v_queue.moderation_action_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_purge_source_key',v_queue.source_key,true);
  INSERT INTO nova_security_fixture.media_purge_attestations
    (revocation_id,media_id,moderation_action_id,source_key,storage_object_version,attestation_ref,attested_by,attested_at)
  VALUES(v_queue.id,v_queue.media_id,v_queue.moderation_action_id,v_queue.source_key,
    p_storage_object_version,p_attestation_ref,current_user,pg_catalog.statement_timestamp());
  RETURN true;
END $$;

DROP FUNCTION IF EXISTS public.nova_record_media_removal_authority(uuid,text,text);
CREATE FUNCTION public.nova_finalize_media_key_revocation(
  p_revocation_id uuid,p_storage_object_version text,p_authority_reference text,p_purge_scope text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v_queue record; v_attestation record; affected integer;
BEGIN
  IF p_revocation_id IS NULL OR p_storage_object_version IS NULL
     OR pg_catalog.btrim(p_storage_object_version)='' OR pg_catalog.length(p_storage_object_version)>300
     OR p_authority_reference IS NULL OR pg_catalog.btrim(p_authority_reference)=''
     OR pg_catalog.length(p_authority_reference)>500
     OR p_purge_scope IS DISTINCT FROM 'storage_object_and_all_cache_variants' THEN
    RAISE EXCEPTION 'authoritative removal evidence or required purge scope is invalid' USING ERRCODE='42501';
  END IF;
  PERFORM pg_catalog.set_config('nova.fixture_purge_revocation_id',p_revocation_id::text,true);
  SELECT id,media_id,source_key,moderation_action_id,attempt_count,retry_after,escalated_at
    INTO v_queue FROM public.media_key_revocations WHERE id=p_revocation_id FOR UPDATE;
  IF NOT FOUND OR NOT ((v_queue.retry_after<=pg_catalog.statement_timestamp()
       AND v_queue.attempt_count<5 AND v_queue.escalated_at IS NULL)
       OR v_queue.escalated_at IS NOT NULL)
     OR NOT public.nova_rls_valid_media_revocation(v_queue.id,v_queue.media_id,v_queue.source_key,v_queue.moderation_action_id) THEN
    RAISE EXCEPTION 'purge finalization denied' USING ERRCODE='42501';
  END IF;
  PERFORM pg_catalog.set_config('nova.fixture_purge_action_id',v_queue.moderation_action_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_purge_media_id',v_queue.media_id::text,true);
  PERFORM pg_catalog.set_config('nova.fixture_purge_source_key',v_queue.source_key,true);
  SELECT revocation_id,media_id,moderation_action_id,source_key,storage_object_version,attested_by
    INTO v_attestation FROM nova_security_fixture.media_purge_attestations WHERE revocation_id=v_queue.id;
  IF NOT FOUND OR v_attestation.attested_by<>'nova_media_purge_attester'
     OR (v_attestation.revocation_id,v_attestation.media_id,v_attestation.moderation_action_id,
         v_attestation.source_key,v_attestation.storage_object_version)
       IS DISTINCT FROM (v_queue.id,v_queue.media_id,v_queue.moderation_action_id,
         v_queue.source_key,p_storage_object_version) THEN
    RAISE EXCEPTION 'authority requires attestation for this exact object key and immutable version' USING ERRCODE='42501';
  END IF;
  INSERT INTO nova_security_fixture.media_removal_authoritative_outcomes
    (revocation_id,media_id,moderation_action_id,source_key,storage_object_version,
     authority_reference,purge_scope,outcome,confirmed_by,confirmed_at)
  VALUES(v_queue.id,v_queue.media_id,v_queue.moderation_action_id,v_queue.source_key,
    p_storage_object_version,p_authority_reference,p_purge_scope,
    'media_removed_and_cache_purged','nova_media_removal_authority',pg_catalog.statement_timestamp());
  DELETE FROM public.media_key_revocations WHERE id=v_queue.id;
  GET DIAGNOSTICS affected=ROW_COUNT;
  IF affected<>1 THEN RAISE EXCEPTION 'authoritatively resolved queue row was not removed' USING ERRCODE='42501'; END IF;
  IF NOT EXISTS (SELECT 1 FROM public.media_key_revocations WHERE moderation_action_id=v_queue.moderation_action_id) THEN
    UPDATE public.moderation_actions
      SET metadata=metadata||pg_catalog.jsonb_build_object('removalStatus','verified',
        'removalVerifiedAt',pg_catalog.statement_timestamp())
      WHERE id=v_queue.moderation_action_id AND action='hide_story' AND metadata->>'removalStatus'='pending';
    GET DIAGNOSTICS affected=ROW_COUNT;
    IF affected<>1 THEN RAISE EXCEPTION 'authoritative moderation transition denied' USING ERRCODE='42501'; END IF;
  END IF;
  RETURN true;
END $$;

DROP POLICY reports_worker_update_removal_only ON public.reports;
CREATE POLICY reports_worker_update_removal_only ON public.reports FOR UPDATE TO nova_reports_worker
  USING (current_user='nova_reports_worker' AND removal_pending
    AND public.nova_rls_valid_report_target(target_type,target_id))
  WITH CHECK (current_user='nova_reports_worker' AND status::text='actioned'
    AND removal_pending=false AND public.nova_rls_target_removal_resolved(target_type,target_id));

-- Temporary CREATE is only needed to transfer fixture SECURITY DEFINER ownership; revoke it below.
GRANT CREATE ON SCHEMA public TO nova_media_upload_verifier,nova_media_purge_verifier;
ALTER FUNCTION public.nova_rls_actor_active() OWNER TO nova_actor_predicate_owner;
ALTER FUNCTION public.nova_rls_actor_has_role(text[]) OWNER TO nova_actor_predicate_owner;
ALTER FUNCTION public.nova_rls_own_media_revocation_pending(uuid) OWNER TO nova_media_state_predicate_owner;
ALTER FUNCTION public.nova_rls_valid_moderation_action(uuid) OWNER TO nova_action_predicate_owner;
ALTER FUNCTION public.nova_rls_valid_media_revocation(uuid,text,uuid) OWNER TO nova_media_predicate_owner;
ALTER FUNCTION public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid) OWNER TO nova_media_predicate_owner;
ALTER FUNCTION public.nova_rls_valid_report_target(public.report_target_type,uuid) OWNER TO nova_reports_predicate_owner;
ALTER FUNCTION public.nova_rls_target_has_pending_revocation(public.report_target_type,uuid) OWNER TO nova_reports_predicate_owner;
ALTER FUNCTION public.nova_rls_target_removal_resolved(public.report_target_type,uuid) OWNER TO nova_reports_predicate_owner;
ALTER FUNCTION public.nova_transition_story(uuid,text) OWNER TO nova_story_lifecycle_manager;
ALTER FUNCTION public.nova_stories_avatar_reference_guard() OWNER TO nova_media_reference_guard_owner;
ALTER FUNCTION public.nova_stories_cover_reference_guard() OWNER TO nova_media_reference_guard_owner;
ALTER FUNCTION public.nova_feedback_screenshot_reference_guard() OWNER TO nova_media_reference_guard_owner;
ALTER FUNCTION public.nova_begin_media_upload(uuid) OWNER TO nova_media_lifecycle_manager;
ALTER FUNCTION public.nova_cancel_media_upload(uuid) OWNER TO nova_media_lifecycle_manager;
ALTER FUNCTION public.nova_record_media_upload_verification(uuid,uuid,text,bigint,text,text) OWNER TO nova_media_upload_verifier;
ALTER FUNCTION public.nova_complete_media_upload(uuid) OWNER TO nova_media_lifecycle_manager;
ALTER FUNCTION public.nova_enqueue_media_key_revocation(uuid,uuid,text,text) OWNER TO nova_revocation_enqueuer_owner;
ALTER FUNCTION public.nova_moderate_hide_story(uuid,text) OWNER TO nova_story_moderation_manager;
ALTER FUNCTION public.nova_moderate_restore_story(uuid,uuid,text) OWNER TO nova_story_moderation_manager;
ALTER FUNCTION public.nova_rate_limit_record(text,timestamptz) OWNER TO nova_rate_limit_counter_owner;
ALTER FUNCTION public.nova_finalize_media_key_revocation(uuid,text,text,text) OWNER TO nova_media_purge_verifier;

REVOKE ALL ON FUNCTION public.nova_rls_actor_active(),public.nova_rls_actor_has_role(text[]),
  public.nova_rls_own_media_revocation_pending(uuid),public.nova_rls_valid_moderation_action(uuid),
  public.nova_rls_valid_media_revocation(uuid,text,uuid),public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid),
  public.nova_rls_valid_report_target(public.report_target_type,uuid),
  public.nova_rls_target_has_pending_revocation(public.report_target_type,uuid),
  public.nova_rls_target_removal_resolved(public.report_target_type,uuid),
  public.nova_transition_story(uuid,text),public.nova_stories_avatar_reference_guard(),
  public.nova_stories_cover_reference_guard(),public.nova_feedback_screenshot_reference_guard(),
  public.nova_begin_media_upload(uuid),public.nova_cancel_media_upload(uuid),
  public.nova_record_media_upload_verification(uuid,uuid,text,bigint,text,text),public.nova_complete_media_upload(uuid),
  public.nova_enqueue_media_key_revocation(uuid,uuid,text,text),public.nova_moderate_hide_story(uuid,text),
  public.nova_moderate_restore_story(uuid,uuid,text),public.nova_rate_limit_record(text,timestamptz),public.nova_record_media_purge_attestation(uuid,text,text),
  public.nova_finalize_media_key_revocation(uuid,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.nova_rls_valid_media_revocation(uuid,text,uuid) FROM nova_fastify_runtime,
  nova_media_revocation_worker,nova_reports_worker,nova_reports_predicate_owner,nova_media_purge_verifier;
REVOKE ALL ON FUNCTION public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid) FROM nova_fastify_runtime,
  nova_tag_catalog_writer,nova_rate_limiter_runtime,nova_feedback_cleanup,nova_security_reports_cleanup,nova_audit_cleanup;
GRANT EXECUTE ON FUNCTION public.nova_rls_uid(),public.nova_rls_subject() TO nova_actor_predicate_owner,
  nova_media_state_predicate_owner,nova_revocation_enqueuer_owner,nova_story_moderation_manager,
  nova_story_lifecycle_manager,nova_media_lifecycle_manager;
GRANT EXECUTE ON FUNCTION public.nova_rls_actor_active() TO nova_fastify_runtime,nova_media_state_predicate_owner,
  nova_revocation_enqueuer_owner,nova_story_moderation_manager,nova_story_lifecycle_manager,nova_media_lifecycle_manager;
GRANT EXECUTE ON FUNCTION public.nova_rls_actor_has_role(text[]) TO nova_fastify_runtime,nova_media_state_predicate_owner,
  nova_revocation_enqueuer_owner,nova_story_moderation_manager,nova_story_lifecycle_manager,nova_media_lifecycle_manager;
GRANT EXECUTE ON FUNCTION public.nova_rls_own_media_revocation_pending(uuid) TO nova_fastify_runtime;
REVOKE ALL ON FUNCTION public.nova_rls_valid_moderation_action(uuid) FROM nova_media_revocation_worker,
  nova_reports_worker,nova_media_predicate_owner,nova_reports_predicate_owner;
GRANT EXECUTE ON FUNCTION public.nova_rls_valid_moderation_action(uuid) TO nova_revocation_enqueuer_owner;
GRANT EXECUTE ON FUNCTION public.nova_rls_valid_media_revocation(uuid,text,uuid) TO nova_revocation_enqueuer_owner;
GRANT EXECUTE ON FUNCTION public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)
  TO nova_media_revocation_worker,nova_media_predicate_owner,nova_reports_predicate_owner,
     nova_media_purge_verifier,nova_media_purge_attester,nova_media_removal_authority;
GRANT EXECUTE ON FUNCTION public.nova_rls_valid_report_target(public.report_target_type,uuid),
  public.nova_rls_target_has_pending_revocation(public.report_target_type,uuid),
  public.nova_rls_target_removal_resolved(public.report_target_type,uuid) TO nova_reports_worker;
GRANT EXECUTE ON FUNCTION public.nova_transition_story(uuid,text),public.nova_enqueue_media_key_revocation(uuid,uuid,text,text),
  public.nova_moderate_hide_story(uuid,text),public.nova_moderate_restore_story(uuid,uuid,text) TO nova_fastify_runtime;
GRANT EXECUTE ON FUNCTION public.nova_begin_media_upload(uuid),public.nova_cancel_media_upload(uuid),
  public.nova_complete_media_upload(uuid) TO nova_fastify_runtime;
GRANT EXECUTE ON FUNCTION public.nova_record_media_upload_verification(uuid,uuid,text,bigint,text,text)
  TO nova_media_upload_gateway;
GRANT EXECUTE ON FUNCTION public.nova_rls_target_has_pending_revocation(public.report_target_type,uuid)
  TO nova_story_moderation_manager;
GRANT EXECUTE ON FUNCTION public.nova_record_media_purge_attestation(uuid,text,text) TO nova_media_purge_attester;
GRANT EXECUTE ON FUNCTION public.nova_finalize_media_key_revocation(uuid,text,text,text) TO nova_media_removal_authority;
REVOKE CREATE ON SCHEMA public FROM nova_story_lifecycle_manager,nova_media_lifecycle_manager,
  nova_actor_predicate_owner,nova_media_state_predicate_owner,nova_action_predicate_owner,
  nova_media_predicate_owner,nova_reports_predicate_owner,nova_media_reference_guard_owner,
  nova_revocation_enqueuer_owner,nova_story_moderation_manager,nova_media_upload_verifier,nova_media_purge_verifier;

COMMIT;
