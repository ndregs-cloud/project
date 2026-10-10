-- Validation only for the moderation outbox integration test.
-- DISPOSABLE LOCAL POSTGRESQL 17 DATABASE ONLY; run after migrations 001-003,
-- rls-policy-prototype.sql, and rls-fastify-e2e.sql. This file grants nothing,
-- creates no login roles, and seeds no rows. It cannot be used as a permissive
-- substitute for the disposable RLS fixture.
-- psql variables: runtime_login, limiter_login, worker_login.

SELECT pg_catalog.format($validator$
DO $check$
DECLARE
  wrapper_name text;
  expected_role text;
  target_role text;
  relation_name text;
BEGIN
  IF NOT COALESCE((SELECT relrowsecurity AND relforcerowsecurity FROM pg_catalog.pg_class
      WHERE oid='public.users'::regclass),false)
     OR NOT COALESCE((SELECT relrowsecurity AND relforcerowsecurity FROM pg_catalog.pg_class
      WHERE oid='public.comments'::regclass),false)
     OR NOT COALESCE((SELECT relrowsecurity AND relforcerowsecurity FROM pg_catalog.pg_class
      WHERE oid='public.reports'::regclass),false)
     OR NOT COALESCE((SELECT relrowsecurity AND relforcerowsecurity FROM pg_catalog.pg_class
      WHERE oid='public.stories'::regclass),false)
     OR NOT COALESCE((SELECT relrowsecurity AND relforcerowsecurity FROM pg_catalog.pg_class
      WHERE oid='public.rate_limit_buckets'::regclass),false)
     OR NOT COALESCE((SELECT relrowsecurity AND relforcerowsecurity FROM pg_catalog.pg_class
      WHERE oid='public.moderation_actions'::regclass),false)
     OR NOT COALESCE((SELECT relrowsecurity AND relforcerowsecurity FROM pg_catalog.pg_class
      WHERE oid='public.media_key_revocations'::regclass),false) THEN
    RAISE EXCEPTION 'RLS fixture must be enabled and forced on users, comments, reports, stories, rate buckets, moderation actions, and revocation queue';
  END IF;

  FOR wrapper_name,expected_role IN
    SELECT pair.login_name,pair.principal_name FROM (VALUES
      (%L,'nova_fastify_runtime'),(%L,'nova_rate_limiter_runtime'),(%L,'nova_media_revocation_worker')
    ) AS pair(login_name,principal_name)
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=wrapper_name AND rolcanlogin
        AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls
        AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication) THEN
      RAISE EXCEPTION 'login wrapper %% has unsafe login or administrative attributes',wrapper_name;
    END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_auth_members memberships
        WHERE memberships.member=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=wrapper_name)) <> 1 THEN
      RAISE EXCEPTION 'login wrapper %% must have exactly one direct role membership',wrapper_name;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members memberships
        WHERE memberships.member=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=wrapper_name)
          AND memberships.roleid=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=expected_role)
          AND NOT memberships.inherit_option AND memberships.set_option AND NOT memberships.admin_option) THEN
      RAISE EXCEPTION 'login wrapper %% membership options must be INHERIT FALSE, SET TRUE, ADMIN FALSE',wrapper_name;
    END IF;
    IF (SELECT count(*) FROM pg_catalog.pg_auth_members memberships
        WHERE memberships.roleid=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=expected_role)) <> 1
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members memberships
        WHERE memberships.member=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=expected_role)) THEN
      RAISE EXCEPTION 'principal %% must have only its wrapper and no nested membership',expected_role;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members memberships
        WHERE memberships.member=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=wrapper_name)
          AND memberships.admin_option) THEN
      RAISE EXCEPTION 'login wrapper %% must not have ADMIN OPTION on any membership',wrapper_name;
    END IF;
    IF (WITH RECURSIVE membership_closure(roleid) AS (
          SELECT memberships.roleid FROM pg_catalog.pg_auth_members memberships
          WHERE memberships.member=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=wrapper_name)
          UNION
          SELECT memberships.roleid FROM pg_catalog.pg_auth_members memberships
          JOIN membership_closure closure ON memberships.member=closure.roleid
        ) SELECT count(DISTINCT roleid) FROM membership_closure) <> 1 THEN
      RAISE EXCEPTION 'login wrapper %% has an unexpected transitive role membership',wrapper_name;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members memberships
        WHERE memberships.roleid=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=wrapper_name))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_roles candidate
        WHERE candidate.oid<>(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=wrapper_name)
          AND NOT candidate.rolsuper
          AND pg_catalog.pg_has_role(candidate.oid,wrapper_name,'SET')) THEN
      RAISE EXCEPTION 'login wrapper %% has an incoming direct or nested SET ROLE path',wrapper_name;
    END IF;
    IF NOT pg_catalog.pg_has_role(wrapper_name,expected_role,'SET') THEN
      RAISE EXCEPTION 'login wrapper %% cannot SET ROLE to its expected principal %%',wrapper_name,expected_role;
    END IF;
    FOREACH target_role IN ARRAY ARRAY['nova_fastify_runtime','nova_rate_limiter_runtime','nova_media_revocation_worker'] LOOP
      IF target_role <> expected_role AND pg_catalog.pg_has_role(wrapper_name,target_role,'SET') THEN
        RAISE EXCEPTION 'login wrapper %% can SET ROLE to an unrelated principal %%',wrapper_name,target_role;
      END IF;
    END LOOP;

    FOR relation_name IN
      SELECT pg_catalog.format('public.%%I',tablename)
      FROM pg_catalog.pg_tables WHERE schemaname='public'
    LOOP
      IF has_table_privilege(wrapper_name,relation_name,'INSERT')
         OR has_table_privilege(wrapper_name,relation_name,'UPDATE')
         OR has_table_privilege(wrapper_name,relation_name,'DELETE') THEN
        RAISE EXCEPTION 'login wrapper %% has direct/inherited broad DML on %%',wrapper_name,relation_name;
      END IF;
    END LOOP;
    IF has_column_privilege(wrapper_name,'public.stories','status','UPDATE')
       OR has_column_privilege(wrapper_name,'public.moderation_actions','reason','INSERT')
       OR has_column_privilege(wrapper_name,'public.media_key_revocations','media_id','INSERT') THEN
      RAISE EXCEPTION 'login wrapper %% has effective column-level DML',wrapper_name;
    END IF;
    IF has_table_privilege(wrapper_name,'public.users','INSERT')
       OR has_any_column_privilege(wrapper_name,'public.users','INSERT')
       OR has_column_privilege(wrapper_name,'public.users','auth_subject','SELECT')
       OR has_column_privilege(wrapper_name,'public.users','auth_subject','INSERT')
       OR has_function_privilege(wrapper_name,'public.nova_auth_bootstrap_identity(text)','EXECUTE') THEN
      RAISE EXCEPTION 'login wrapper %% has direct identity-helper or users/auth_subject privileges',wrapper_name;
    END IF;
    IF has_schema_privilege(wrapper_name,'public','USAGE')
       OR has_schema_privilege(wrapper_name,'public','CREATE') THEN
      RAISE EXCEPTION 'login wrapper %% has unexpected public schema privileges',wrapper_name;
    END IF;
  END LOOP;

  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname IN ('nova_fastify_runtime','nova_rate_limiter_runtime','nova_media_revocation_worker')
        AND (rolcanlogin OR rolinherit OR rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members memberships
        JOIN pg_catalog.pg_roles principal ON principal.oid=memberships.member
        WHERE principal.rolname IN ('nova_fastify_runtime','nova_rate_limiter_runtime','nova_media_revocation_worker')) THEN
    RAISE EXCEPTION 'effective runtime roles must be NOLOGIN, NOINHERIT, non-superuser, non-BYPASSRLS, and have empty membership closure';
  END IF;
  IF pg_catalog.pg_has_role('nova_fastify_runtime','nova_rate_limiter_runtime','SET')
     OR pg_catalog.pg_has_role('nova_fastify_runtime','nova_media_revocation_worker','SET')
     OR pg_catalog.pg_has_role('nova_rate_limiter_runtime','nova_fastify_runtime','SET')
     OR pg_catalog.pg_has_role('nova_rate_limiter_runtime','nova_media_revocation_worker','SET')
     OR pg_catalog.pg_has_role('nova_media_revocation_worker','nova_fastify_runtime','SET')
     OR pg_catalog.pg_has_role('nova_media_revocation_worker','nova_rate_limiter_runtime','SET') THEN
    RAISE EXCEPTION 'runtime, limiter, and worker principals must not be able to SET ROLE to one another';
  END IF;
  IF NOT has_schema_privilege('nova_fastify_runtime','public','USAGE')
     OR NOT has_schema_privilege('nova_rate_limiter_runtime','public','USAGE')
     OR NOT has_schema_privilege('nova_media_revocation_worker','public','USAGE')
     OR has_schema_privilege('nova_fastify_runtime','public','CREATE')
     OR has_schema_privilege('nova_rate_limiter_runtime','public','CREATE')
     OR has_schema_privilege('nova_media_revocation_worker','public','CREATE') THEN
    RAISE EXCEPTION 'effective runtime roles must have public USAGE but no public CREATE';
  END IF;
  IF EXISTS (
      SELECT 1 FROM pg_catalog.pg_namespace ns
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(ns.nspacl,pg_catalog.acldefault('n',ns.nspowner))
      ) acl
      WHERE ns.nspname='public' AND acl.grantee=0 AND acl.privilege_type IN ('USAGE','CREATE')) THEN
    RAISE EXCEPTION 'PUBLIC has unexpected USAGE/CREATE on the public schema';
  END IF;

  IF has_table_privilege('nova_fastify_runtime','public.moderation_actions','INSERT')
     OR has_table_privilege('nova_fastify_runtime','public.media_key_revocations','INSERT')
     OR has_table_privilege('nova_media_revocation_worker','public.media_key_revocations','DELETE')
     OR has_table_privilege('nova_media_revocation_worker','public.moderation_actions','UPDATE') THEN
    RAISE EXCEPTION 'effective least-privilege assertions failed';
  END IF;
  IF has_table_privilege('nova_fastify_runtime','public.users','INSERT')
     OR has_any_column_privilege('nova_fastify_runtime','public.users','INSERT')
     OR has_column_privilege('nova_fastify_runtime','public.users','auth_subject','SELECT')
     OR has_column_privilege('nova_fastify_runtime','public.users','auth_subject','INSERT')
     OR NOT has_function_privilege('nova_fastify_runtime','public.nova_auth_bootstrap_identity(text)','EXECUTE')
     OR has_function_privilege('nova_rate_limiter_runtime','public.nova_auth_bootstrap_identity(text)','EXECUTE')
     OR has_function_privilege('nova_media_revocation_worker','public.nova_auth_bootstrap_identity(text)','EXECUTE') THEN
    RAISE EXCEPTION 'identity helper EXECUTE/direct users privilege contract failed';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_proc helper
      JOIN pg_catalog.pg_roles helper_owner ON helper_owner.oid=helper.proowner
      WHERE helper.oid='public.nova_auth_bootstrap_identity(text)'::regprocedure
        AND helper.prosecdef AND helper.proconfig @> ARRAY['search_path=pg_catalog']
        AND NOT helper_owner.rolcanlogin AND NOT helper_owner.rolinherit
        AND NOT helper_owner.rolsuper AND NOT helper_owner.rolbypassrls
        AND NOT helper_owner.rolcreaterole AND NOT helper_owner.rolcreatedb AND NOT helper_owner.rolreplication
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members memberships WHERE memberships.member=helper_owner.oid)
        AND NOT EXISTS (
          SELECT 1 FROM pg_catalog.aclexplode(
            COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))
          ) helper_acl WHERE helper_acl.grantee=0 AND helper_acl.privilege_type='EXECUTE'
        )) THEN
    RAISE EXCEPTION 'identity helper SECURITY DEFINER owner/search_path/ACL contract failed';
  END IF;
  IF NOT has_function_privilege('nova_fastify_runtime','public.nova_moderate_hide_story(uuid,text)','EXECUTE')
     OR NOT has_function_privilege('nova_fastify_runtime','public.nova_enqueue_media_key_revocation(uuid,uuid,text,text)','EXECUTE') THEN
    RAISE EXCEPTION 'runtime lacks the approved atomic moderation/enqueue procedure contract';
  END IF;
  IF NOT has_column_privilege('nova_media_revocation_worker','public.media_key_revocations','id','SELECT')
     OR NOT has_column_privilege('nova_media_revocation_worker','public.media_key_revocations','media_id','SELECT')
     OR NOT has_column_privilege('nova_media_revocation_worker','public.media_key_revocations','source_key','SELECT')
     OR NOT has_column_privilege('nova_media_revocation_worker','public.media_key_revocations','moderation_action_id','SELECT')
     OR NOT has_column_privilege('nova_media_revocation_worker','public.media_key_revocations','attempt_count','SELECT')
     OR NOT has_column_privilege('nova_media_revocation_worker','public.media_key_revocations','retry_after','SELECT')
     OR NOT has_column_privilege('nova_media_revocation_worker','public.media_key_revocations','created_at','SELECT')
     OR NOT has_column_privilege('nova_media_revocation_worker','public.media_key_revocations','escalated_at','SELECT')
     OR NOT has_column_privilege('nova_media_revocation_worker','public.media_key_revocations','attempt_count','UPDATE')
     OR NOT has_column_privilege('nova_media_revocation_worker','public.media_key_revocations','retry_after','UPDATE')
     OR NOT has_column_privilege('nova_media_revocation_worker','public.media_key_revocations','escalated_at','UPDATE')
     OR has_table_privilege('nova_media_revocation_worker','public.media_key_revocations','UPDATE')
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute queue_column
       WHERE queue_column.attrelid='public.media_key_revocations'::regclass
         AND queue_column.attnum>0 AND NOT queue_column.attisdropped
         AND queue_column.attname NOT IN ('attempt_count','retry_after','escalated_at')
         AND has_column_privilege('nova_media_revocation_worker','public.media_key_revocations',queue_column.attname,'UPDATE')) THEN
    RAISE EXCEPTION 'worker lacks one or more required queue column privileges';
  END IF;
  IF has_table_privilege('nova_rate_limiter_runtime','public.rate_limit_buckets','SELECT')
     OR has_table_privilege('nova_rate_limiter_runtime','public.rate_limit_buckets','INSERT')
     OR has_table_privilege('nova_rate_limiter_runtime','public.rate_limit_buckets','UPDATE')
     OR has_table_privilege('nova_rate_limiter_runtime','public.rate_limit_buckets','DELETE')
     OR NOT has_function_privilege('nova_rate_limiter_runtime','public.nova_rate_limit_record(text,timestamptz)','EXECUTE') THEN
    RAISE EXCEPTION 'limiter must have counter EXECUTE only and no rate bucket table access';
  END IF;
  IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_roles owner ON owner.oid=p.proowner
      WHERE p.oid='public.nova_rate_limit_record(text,timestamptz)'::regprocedure
        AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog']
        AND owner.rolname='nova_rate_limit_counter_owner' AND NOT owner.rolcanlogin
        AND NOT owner.rolinherit AND NOT owner.rolsuper AND NOT owner.rolbypassrls)
     OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_proc p
      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
      WHERE p.oid='public.nova_rate_limit_record(text,timestamptz)'::regprocedure
        AND acl.grantee=0 AND acl.privilege_type='EXECUTE') THEN
    RAISE EXCEPTION 'rate counter SECURITY DEFINER ownership/ACL is not bounded';
  END IF;
END
$check$;

DO $definer_contract$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc helper
    JOIN pg_catalog.pg_roles owner ON owner.oid=helper.proowner
    JOIN pg_catalog.pg_roles runtime ON runtime.rolname='nova_fastify_runtime'
    WHERE helper.oid='public.nova_auth_bootstrap_identity(text)'::regprocedure
      AND helper.prosecdef AND helper.proconfig @> ARRAY['search_path=pg_catalog']
      AND owner.rolname='nova_auth_identity_owner' AND NOT owner.rolcanlogin AND NOT owner.rolinherit
      AND NOT owner.rolsuper AND NOT owner.rolbypassrls AND NOT owner.rolcreaterole
      AND NOT owner.rolcreatedb AND NOT owner.rolreplication
      AND pg_catalog.has_schema_privilege(owner.oid,'public','USAGE')
      AND NOT pg_catalog.has_schema_privilege(owner.oid,'public','CREATE')
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
        WHERE m.member=owner.oid OR m.roleid=owner.oid)
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class rel
        WHERE rel.relnamespace='public'::regnamespace AND rel.relkind IN ('r','p','v','m','f')
          AND (pg_catalog.has_table_privilege(owner.oid,rel.oid,'SELECT')
            OR pg_catalog.has_table_privilege(owner.oid,rel.oid,'INSERT')
            OR pg_catalog.has_table_privilege(owner.oid,rel.oid,'UPDATE')
            OR pg_catalog.has_table_privilege(owner.oid,rel.oid,'DELETE')
            OR pg_catalog.has_table_privilege(owner.oid,rel.oid,'TRUNCATE')
            OR pg_catalog.has_table_privilege(owner.oid,rel.oid,'REFERENCES')
            OR pg_catalog.has_table_privilege(owner.oid,rel.oid,'TRIGGER')
            OR (rel.oid='public.users'::regclass AND (
              pg_catalog.has_any_column_privilege(owner.oid,rel.oid,'UPDATE')
              OR pg_catalog.has_any_column_privilege(owner.oid,rel.oid,'REFERENCES')
              OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
                WHERE a.attrelid=rel.oid AND a.attnum>0 AND NOT a.attisdropped
                  AND ((a.attname NOT IN ('id','auth_subject','username','role','status')
                        AND pg_catalog.has_column_privilege(owner.oid,rel.oid,a.attname,'SELECT'))
                    OR (a.attname NOT IN ('auth_subject','username','username_normalized')
                        AND pg_catalog.has_column_privilege(owner.oid,rel.oid,a.attname,'INSERT')))
              )
            ))
            OR (rel.oid<>'public.users'::regclass AND (
              pg_catalog.has_any_column_privilege(owner.oid,rel.oid,'SELECT')
              OR pg_catalog.has_any_column_privilege(owner.oid,rel.oid,'INSERT')
              OR pg_catalog.has_any_column_privilege(owner.oid,rel.oid,'UPDATE')
              OR pg_catalog.has_any_column_privilege(owner.oid,rel.oid,'REFERENCES')
            )))
      )
      AND pg_catalog.has_column_privilege(owner.oid,'public.users','id','SELECT')
      AND pg_catalog.has_column_privilege(owner.oid,'public.users','auth_subject','SELECT')
      AND pg_catalog.has_column_privilege(owner.oid,'public.users','username','SELECT')
      AND pg_catalog.has_column_privilege(owner.oid,'public.users','role','SELECT')
      AND pg_catalog.has_column_privilege(owner.oid,'public.users','status','SELECT')
      AND pg_catalog.has_column_privilege(owner.oid,'public.users','auth_subject','INSERT')
      AND pg_catalog.has_column_privilege(owner.oid,'public.users','username','INSERT')
      AND pg_catalog.has_column_privilege(owner.oid,'public.users','username_normalized','INSERT')
      AND EXISTS (SELECT 1 FROM pg_catalog.aclexplode(
        COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
        WHERE acl.grantee=runtime.oid AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(
        COALESCE(helper.proacl,pg_catalog.acldefault('f',helper.proowner))) acl
        WHERE acl.privilege_type='EXECUTE'
          AND (acl.grantee NOT IN (helper.proowner,runtime.oid) OR acl.is_grantable))
  ) THEN
    RAISE EXCEPTION 'identity helper owner, grants, membership, or EXECUTE ACL is not bounded';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc counter
    JOIN pg_catalog.pg_roles owner ON owner.oid=counter.proowner
    JOIN pg_catalog.pg_roles limiter ON limiter.rolname='nova_rate_limiter_runtime'
    WHERE counter.oid='public.nova_rate_limit_record(text,timestamptz)'::regprocedure
      AND counter.prosecdef AND counter.proconfig @> ARRAY['search_path=pg_catalog']
      AND owner.rolname='nova_rate_limit_counter_owner' AND NOT owner.rolcanlogin AND NOT owner.rolinherit
      AND NOT owner.rolsuper AND NOT owner.rolbypassrls AND NOT owner.rolcreaterole
      AND NOT owner.rolcreatedb AND NOT owner.rolreplication
      AND pg_catalog.has_schema_privilege(owner.oid,'public','USAGE')
      AND NOT pg_catalog.has_schema_privilege(owner.oid,'public','CREATE')
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
        WHERE m.member=owner.oid OR m.roleid=owner.oid)
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class rel
        WHERE rel.relnamespace='public'::regnamespace AND rel.relkind IN ('r','p','v','m','f')
          AND (pg_catalog.has_table_privilege(owner.oid,rel.oid,'SELECT')
            OR pg_catalog.has_table_privilege(owner.oid,rel.oid,'INSERT')
            OR pg_catalog.has_table_privilege(owner.oid,rel.oid,'UPDATE')
            OR pg_catalog.has_table_privilege(owner.oid,rel.oid,'DELETE')
            OR pg_catalog.has_table_privilege(owner.oid,rel.oid,'TRUNCATE')
            OR pg_catalog.has_table_privilege(owner.oid,rel.oid,'REFERENCES')
            OR pg_catalog.has_table_privilege(owner.oid,rel.oid,'TRIGGER')
            OR (rel.oid='public.rate_limit_buckets'::regclass AND (
              pg_catalog.has_any_column_privilege(owner.oid,rel.oid,'REFERENCES')
              OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
                WHERE a.attrelid=rel.oid AND a.attnum>0 AND NOT a.attisdropped
                  AND ((a.attname NOT IN ('bucket_key','window_start','hits')
                        AND (pg_catalog.has_column_privilege(owner.oid,rel.oid,a.attname,'SELECT')
                          OR pg_catalog.has_column_privilege(owner.oid,rel.oid,a.attname,'INSERT')))
                    OR (a.attname NOT IN ('window_start','hits')
                        AND pg_catalog.has_column_privilege(owner.oid,rel.oid,a.attname,'UPDATE')))
              )
            ))
            OR (rel.oid<>'public.rate_limit_buckets'::regclass AND (
              pg_catalog.has_any_column_privilege(owner.oid,rel.oid,'SELECT')
              OR pg_catalog.has_any_column_privilege(owner.oid,rel.oid,'INSERT')
              OR pg_catalog.has_any_column_privilege(owner.oid,rel.oid,'UPDATE')
              OR pg_catalog.has_any_column_privilege(owner.oid,rel.oid,'REFERENCES')
            )))
      )
      AND pg_catalog.has_column_privilege(owner.oid,'public.rate_limit_buckets','bucket_key','SELECT')
      AND pg_catalog.has_column_privilege(owner.oid,'public.rate_limit_buckets','window_start','SELECT')
      AND pg_catalog.has_column_privilege(owner.oid,'public.rate_limit_buckets','hits','SELECT')
      AND pg_catalog.has_column_privilege(owner.oid,'public.rate_limit_buckets','bucket_key','INSERT')
      AND pg_catalog.has_column_privilege(owner.oid,'public.rate_limit_buckets','window_start','INSERT')
      AND pg_catalog.has_column_privilege(owner.oid,'public.rate_limit_buckets','hits','INSERT')
      AND pg_catalog.has_column_privilege(owner.oid,'public.rate_limit_buckets','window_start','UPDATE')
      AND pg_catalog.has_column_privilege(owner.oid,'public.rate_limit_buckets','hits','UPDATE')
      AND NOT pg_catalog.has_column_privilege(owner.oid,'public.rate_limit_buckets','bucket_key','UPDATE')
      AND EXISTS (SELECT 1 FROM pg_catalog.aclexplode(
        COALESCE(counter.proacl,pg_catalog.acldefault('f',counter.proowner))) acl
        WHERE acl.grantee=limiter.oid AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable)
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(
        COALESCE(counter.proacl,pg_catalog.acldefault('f',counter.proowner))) acl
        WHERE acl.privilege_type='EXECUTE'
          AND (acl.grantee NOT IN (counter.proowner,limiter.oid) OR acl.is_grantable))
  ) THEN
    RAISE EXCEPTION 'rate counter owner, grants, membership, or EXECUTE ACL is not bounded';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_auth_members memberships
    JOIN pg_catalog.pg_roles member_role ON member_role.oid=memberships.member
    JOIN pg_catalog.pg_roles granted_role ON granted_role.oid=memberships.roleid
    WHERE member_role.rolname IN ('anon','authenticated','nova_unrelated_acl_probe')
       OR granted_role.rolname IN ('anon','authenticated','nova_unrelated_acl_probe')
  ) THEN
    RAISE EXCEPTION 'ACL probe roles must not have role membership edges';
  END IF;
END
$definer_contract$;
$validator$,
  :'runtime_login', :'limiter_login', :'worker_login') AS moderation_outbox_rls_validation \gexec
