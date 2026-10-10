-- NOVA PG17 prototype negative/positive probes — DISPOSABLE LOCAL DATABASE ONLY.
-- Requires migrations 001–003 and rls-policy-prototype.sql to have been applied.
-- Run as a local superuser only on the disposable fixture DB; no remote use.
\set ON_ERROR_STOP on

CREATE TEMP TABLE nova_rls_probe_results(name text PRIMARY KEY, passed boolean NOT NULL);
GRANT INSERT, SELECT ON nova_rls_probe_results TO PUBLIC;
CREATE FUNCTION pg_temp.assert_true(probe_name text, condition boolean)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO nova_rls_probe_results VALUES (probe_name, condition IS TRUE);
  IF condition IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'probe failed: %', probe_name;
  END IF;
END $$;
CREATE FUNCTION pg_temp.assert_denied(probe_name text, statement text, expected_state text DEFAULT '42501')
RETURNS void LANGUAGE plpgsql AS $$
DECLARE got_state text;
BEGIN
  BEGIN
    EXECUTE statement;
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS got_state = RETURNED_SQLSTATE;
    IF got_state = expected_state THEN
      INSERT INTO nova_rls_probe_results VALUES (probe_name, true);
      RETURN;
    END IF;
    RAISE EXCEPTION 'probe % expected SQLSTATE %, got %', probe_name, expected_state, got_state;
  END;
  INSERT INTO nova_rls_probe_results VALUES (probe_name, false);
  RAISE EXCEPTION 'probe unexpectedly succeeded: %', probe_name;
END $$;
CREATE FUNCTION pg_temp.assert_no_effect(probe_name text, statement text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE affected bigint;
BEGIN
  EXECUTE statement;
  GET DIAGNOSTICS affected = ROW_COUNT;
  INSERT INTO nova_rls_probe_results VALUES (probe_name, affected=0);
  IF affected <> 0 THEN RAISE EXCEPTION 'probe unexpectedly affected % rows: %', affected, probe_name; END IF;
END $$;
CREATE FUNCTION pg_temp.atomic_hide_rollback_probe(target_story uuid, reason text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE hide_applied boolean := false; hide_rolled_back boolean := false;
BEGIN
  BEGIN
    PERFORM public.nova_moderate_hide_story(target_story,reason);
    SELECT EXISTS (SELECT 1 FROM public.stories s WHERE s.id=target_story
        AND s.status::text='removed' AND s.visibility::text='private' AND s.deleted_at IS NULL)
       AND EXISTS (SELECT 1 FROM public.moderation_actions a WHERE a.target_type='story'
        AND a.target_id=target_story AND a.action='hide_story') INTO hide_applied;
    IF NOT hide_applied THEN RAISE EXCEPTION 'hide was not fully applied before rollback' USING ERRCODE='P0002'; END IF;
    RAISE EXCEPTION 'force subtransaction rollback after linked hide' USING ERRCODE='P0001';
  EXCEPTION WHEN SQLSTATE 'P0001' THEN
    NULL;
  END;
  SELECT EXISTS (SELECT 1 FROM public.stories s WHERE s.id=target_story
      AND s.status::text='draft' AND s.visibility::text='private')
     AND NOT EXISTS (SELECT 1 FROM public.moderation_actions a WHERE a.target_type='story'
      AND a.target_id=target_story AND a.action='hide_story')
     AND NOT EXISTS (SELECT 1 FROM public.media_no_media_required n
      WHERE n.target_story_id=target_story) INTO hide_rolled_back;
  RETURN hide_applied AND hide_rolled_back;
END $$;

-- Synthetic, disposable-only actors and assets.
INSERT INTO public.users(id,auth_subject,username,username_normalized,role,status) VALUES
 ('10000000-0000-4000-8000-000000000001','fixture-only-owner-subject','fixture_owner','fixture_owner','reader','active'),
 ('10000000-0000-4000-8000-000000000002','fixture-only-other-subject','fixture_other','fixture_other','reader','active'),
 ('10000000-0000-4000-8000-000000000003','fixture-only-moderator-subject','fixture_moderator','fixture_moderator','moderator','active'),
 ('10000000-0000-4000-8000-000000000004','fixture-only-admin-subject','fixture_admin','fixture_admin','admin','active');
INSERT INTO public.media_assets(id,owner_id,purpose,object_key,mime_type,size_bytes,checksum,status,ready_at) VALUES
 ('20000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','avatar','ready/10000000-0000-4000-8000-000000000001/20000000-0000-4000-8000-000000000001.jpg','image/jpeg',128,repeat('a',64),'ready',now()),
 ('20000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000001','cover','ready/10000000-0000-4000-8000-000000000001/20000000-0000-4000-8000-000000000002.jpg','image/jpeg',128,repeat('b',64),'ready',now()),
 ('20000000-0000-4000-8000-000000000003','10000000-0000-4000-8000-000000000002','cover','ready/10000000-0000-4000-8000-000000000002/20000000-0000-4000-8000-000000000003.jpg','image/jpeg',128,repeat('c',64),'ready',now()),
 ('20000000-0000-4000-8000-000000000004','10000000-0000-4000-8000-000000000001','feedback_screenshot','ready/10000000-0000-4000-8000-000000000001/20000000-0000-4000-8000-000000000004.jpg','image/jpeg',128,repeat('d',64),'ready',now()),
 ('20000000-0000-4000-8000-000000000005','10000000-0000-4000-8000-000000000001','cover','pending/10000000-0000-4000-8000-000000000001/20000000-0000-4000-8000-000000000005.jpg','image/jpeg',128,NULL,'pending',NULL),
 ('20000000-0000-4000-8000-000000000006','10000000-0000-4000-8000-000000000001','avatar','pending/10000000-0000-4000-8000-000000000001/20000000-0000-4000-8000-000000000006.jpg','image/jpeg',128,NULL,'pending',NULL),
 ('20000000-0000-4000-8000-000000000007','10000000-0000-4000-8000-000000000001','cover','ready/10000000-0000-4000-8000-000000000001/20000000-0000-4000-8000-000000000007.jpg','image/jpeg',128,repeat('e',64),'ready',now()),
 ('20000000-0000-4000-8000-000000000008','10000000-0000-4000-8000-000000000002','feedback_screenshot','ready/10000000-0000-4000-8000-000000000002/20000000-0000-4000-8000-000000000008.jpg','image/jpeg',128,repeat('f',64),'ready',now());
INSERT INTO public.stories(id,author_id,title,slug,body,status,visibility,published_at,cover_media_id) VALUES
 ('30000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','Lifecycle draft','lifecycle-draft','Synthetic text for local testing.','draft','private',NULL,NULL),
 ('30000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000001','Context draft','context-draft','Synthetic text for local testing.','draft','private',NULL,NULL),
 ('30000000-0000-4000-8000-000000000003','10000000-0000-4000-8000-000000000001','Moderator target','moderator-target','Synthetic text for local testing.','published','public',now(),'20000000-0000-4000-8000-000000000002'),
 ('30000000-0000-4000-8000-000000000004','10000000-0000-4000-8000-000000000001','Hidden story target','hidden-story-target','Synthetic text for local testing.','removed','private',now(),'20000000-0000-4000-8000-000000000007'),
 ('30000000-0000-4000-8000-000000000005','10000000-0000-4000-8000-000000000002','Other owner draft','other-owner-draft','Synthetic text for local testing.','draft','private',NULL,'20000000-0000-4000-8000-000000000003'),
 ('30000000-0000-4000-8000-000000000008','10000000-0000-4000-8000-000000000001','No media target','no-media-target','Synthetic text for local testing.','published','public',now(),NULL),
 ('30000000-0000-4000-8000-000000000009','10000000-0000-4000-8000-000000000001','No media rollback','no-media-rollback','Synthetic text for local testing.','draft','private',NULL,NULL),
 ('30000000-0000-4000-8000-000000000011','10000000-0000-4000-8000-000000000002','Unqueued valid cover target','unqueued-valid-cover-target','Synthetic text for local testing.','published','public',now(),'20000000-0000-4000-8000-000000000003');
INSERT INTO public.moderation_actions(id,moderator_id,target_type,target_id,action,reason,metadata) VALUES
 ('40000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000003','story','30000000-0000-4000-8000-000000000004','hide_story','Fixture moderation action','{"removalStatus":"pending"}'),
 ('40000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000003','story','30000000-0000-4000-8000-000000000004','report_status:closed','Fixture decoy action','{}');
INSERT INTO public.reports(id,reporter_id,target_type,target_id,reason,status,removal_pending) VALUES
 ('50000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000002','story','30000000-0000-4000-8000-000000000004','spam','reviewing',true),
 ('50000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000002','story','30000000-0000-4000-8000-000000000005','other','reviewing',true),
 ('50000000-0000-4000-8000-000000000003','10000000-0000-4000-8000-000000000001','story','30000000-0000-4000-8000-000000000005','other','received',false);
INSERT INTO public.beta_feedback(id,reporter_id,category,summary,screenshot_media_id,expires_at)
VALUES ('60000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','bug','Synthetic expiring feedback','20000000-0000-4000-8000-000000000004',now()+interval '1 day');
COMMIT;

SELECT pg_temp.assert_true('all SECURITY DEFINER owners are narrow NOLOGIN non-bypass roles with fixed search_path',
  NOT EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      JOIN pg_roles r ON r.oid=p.proowner
    WHERE n.nspname='public' AND p.prosecdef
      AND (r.rolsuper OR r.rolbypassrls OR r.rolcanlogin
        OR NOT (COALESCE(p.proconfig,ARRAY[]::text[]) @> ARRAY['search_path=pg_catalog']))
  ));
SELECT pg_temp.assert_true('trusted upload/purge/authority roles are NOLOGIN, non-bypass, and not inherited by API',
  (SELECT count(*)=6 FROM pg_roles WHERE rolname IN
    ('nova_media_upload_gateway','nova_media_upload_verifier','nova_media_purge_gateway',
     'nova_media_purge_verifier','nova_media_purge_attester','nova_media_removal_authority')
     AND rolcanlogin=false AND rolsuper=false AND rolbypassrls=false)
  AND NOT pg_has_role('nova_fastify_runtime','nova_media_upload_gateway','MEMBER')
  AND NOT pg_has_role('nova_fastify_runtime','nova_media_upload_verifier','MEMBER')
  AND NOT pg_has_role('nova_fastify_runtime','nova_media_purge_gateway','MEMBER')
  AND NOT pg_has_role('nova_fastify_runtime','nova_media_purge_verifier','MEMBER')
  AND NOT pg_has_role('nova_fastify_runtime','nova_media_purge_attester','MEMBER')
  AND NOT pg_has_role('nova_fastify_runtime','nova_media_removal_authority','MEMBER'));
SELECT pg_temp.assert_true('upload and purge gateways have no direct or inherited table privileges',
  NOT EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      CROSS JOIN (VALUES ('nova_media_upload_gateway'),('nova_media_purge_gateway'),('nova_media_removal_authority')) g(role_name)
      CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER')) p(privilege)
    WHERE n.nspname IN ('public','nova_security_fixture') AND c.relkind IN ('r','p','v','m','f')
      AND has_table_privilege(g.role_name,c.oid,p.privilege)
  ));
SELECT pg_temp.assert_true('atomic finalizer EXECUTE is backend-authority-only; gateway/runtime cannot call it',
  NOT EXISTS (SELECT 1 FROM pg_proc p
    CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
    WHERE p.oid='public.nova_finalize_media_key_revocation(uuid,text,text,text)'::regprocedure
      AND acl.grantee=0 AND acl.privilege_type='EXECUTE')
  AND has_function_privilege('nova_media_removal_authority','public.nova_finalize_media_key_revocation(uuid,text,text,text)','EXECUTE')
  AND NOT has_function_privilege('nova_media_purge_gateway','public.nova_finalize_media_key_revocation(uuid,text,text,text)','EXECUTE')
  AND NOT has_function_privilege('nova_fastify_runtime','public.nova_finalize_media_key_revocation(uuid,text,text,text)','EXECUTE')
  AND NOT has_function_privilege('nova_media_revocation_worker','public.nova_finalize_media_key_revocation(uuid,text,text,text)','EXECUTE')
  AND NOT has_function_privilege('nova_reports_worker','public.nova_finalize_media_key_revocation(uuid,text,text,text)','EXECUTE')
  AND NOT has_function_privilege('nova_media_purge_attester','public.nova_finalize_media_key_revocation(uuid,text,text,text)','EXECUTE'));
SELECT pg_temp.assert_true('attestation can only be recorded by attester; authority cannot write outcome tables directly',
  has_function_privilege('nova_media_purge_attester','public.nova_record_media_purge_attestation(uuid,text,text)','EXECUTE')
  AND NOT has_function_privilege('nova_media_purge_gateway','public.nova_record_media_purge_attestation(uuid,text,text)','EXECUTE')
  AND to_regprocedure('public.nova_record_media_removal_authority(uuid,text,text)') IS NULL
  AND NOT has_schema_privilege('nova_media_removal_authority','nova_security_fixture','USAGE')
  AND NOT has_table_privilege('nova_media_removal_authority','nova_security_fixture.media_removal_authoritative_outcomes','INSERT')
  AND NOT has_table_privilege('nova_media_removal_authority','public.media_key_revocations','DELETE')
  AND NOT has_table_privilege('nova_media_removal_authority','public.reports','UPDATE'));
SELECT pg_temp.assert_true('upload verification can only be recorded through trusted gateway',
  has_function_privilege('nova_media_upload_gateway','public.nova_record_media_upload_verification(uuid,uuid,text,bigint,text,text)','EXECUTE')
  AND NOT has_function_privilege('nova_fastify_runtime','public.nova_record_media_upload_verification(uuid,uuid,text,bigint,text,text)','EXECUTE')
  AND NOT has_function_privilege('nova_media_purge_gateway','public.nova_record_media_upload_verification(uuid,uuid,text,bigint,text,text)','EXECUTE'));

-- The dedicated local lifecycle helper can only be invoked with verified-context identity;
-- this fixture deliberately does not prove storage bytes, only the DB-side transition.
BEGIN;
SET LOCAL ROLE nova_fastify_runtime;
SELECT set_config('app.user_id','10000000-0000-4000-8000-000000000003',true);
SELECT set_config('app.auth_subject','fixture-only-moderator-subject',true);
SELECT set_config('app.user_role','moderator',true);
SELECT pg_temp.assert_true('linked moderation enqueue succeeds',
  public.nova_enqueue_media_key_revocation(
   '20000000-0000-4000-8000-000000000007','40000000-0000-4000-8000-000000000001',
   'ready/10000000-0000-4000-8000-000000000001/20000000-0000-4000-8000-000000000007.jpg',
   'ready/10000000-0000-4000-8000-000000000001/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa-20000000-0000-4000-8000-000000000007.jpg'
  ) IS NOT NULL);
SELECT pg_temp.assert_denied('unrelated media cannot be linked to action',
  $stmt$SELECT public.nova_enqueue_media_key_revocation(
   '20000000-0000-4000-8000-000000000003','40000000-0000-4000-8000-000000000001',
   'ready/10000000-0000-4000-8000-000000000002/20000000-0000-4000-8000-000000000003.jpg',
   'ready/10000000-0000-4000-8000-000000000002/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb-20000000-0000-4000-8000-000000000003.jpg')$stmt$);
COMMIT;

-- Pool/context tests: context exists only within its transaction; mismatch and forged role fail.
BEGIN;
SET LOCAL ROLE nova_fastify_runtime;
SELECT set_config('app.user_id','10000000-0000-4000-8000-000000000001',true);
SELECT set_config('app.auth_subject','fixture-only-owner-subject',true);
SELECT set_config('app.user_role','reader',true);
SELECT pg_temp.assert_true('owner sees own draft in scoped transaction',
  (SELECT count(*)=1 FROM public.stories WHERE id='30000000-0000-4000-8000-000000000002'));
SELECT pg_temp.assert_true('actor subject and id resolve',public.nova_rls_actor_active());
SELECT pg_temp.assert_true('own revocation helper reveals own pending status only',
  public.nova_rls_own_media_revocation_pending('20000000-0000-4000-8000-000000000007')
  AND NOT public.nova_rls_own_media_revocation_pending('20000000-0000-4000-8000-000000000003'));
COMMIT;
BEGIN;
SET LOCAL ROLE nova_fastify_runtime;
SELECT pg_temp.assert_true('request context is cleared after commit',
  public.nova_rls_uid() IS NULL AND
  (SELECT count(*)=0 FROM public.stories WHERE id='30000000-0000-4000-8000-000000000002'));
COMMIT;
BEGIN;
SET LOCAL ROLE nova_fastify_runtime;
SELECT set_config('app.user_id','10000000-0000-4000-8000-000000000001',true);
SELECT set_config('app.auth_subject','fixture-only-other-subject',true);
SELECT set_config('app.user_role','moderator',true);
SELECT pg_temp.assert_true('subject mismatch and role GUC cannot authorize',
  NOT public.nova_rls_actor_active()
  AND NOT public.nova_rls_actor_has_role(ARRAY['moderator'])
  AND (SELECT count(*)=0 FROM public.stories WHERE id='30000000-0000-4000-8000-000000000002'));
SELECT pg_temp.assert_true('sensitive identity columns are not selectable',
  NOT has_column_privilege('nova_fastify_runtime','public.users','auth_subject','SELECT')
  AND NOT has_column_privilege('nova_fastify_runtime','public.users','role','SELECT'));
SELECT pg_temp.assert_denied('auth_subject direct read denied',
  $stmt$SELECT auth_subject FROM public.users LIMIT 1$stmt$);
SELECT pg_temp.assert_denied('role direct read denied',
  $stmt$SELECT role FROM public.users LIMIT 1$stmt$);
SELECT pg_temp.assert_true('public active-user helper oracle removed',
  to_regprocedure('public.nova_rls_user_active(uuid)') IS NULL);
SELECT pg_temp.assert_true('runtime cannot execute either media/action validity helper',
  NOT has_function_privilege('nova_fastify_runtime','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_fastify_runtime','public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)','EXECUTE'));
SELECT pg_temp.assert_true('cross-media tuple helper is enqueuer-only and queue-bound helper excludes PUBLIC and API roles',
  NOT EXISTS (
    SELECT 1 FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
    WHERE p.oid='public.nova_rls_valid_media_revocation(uuid,text,uuid)'::regprocedure
      AND acl.grantee=0 AND acl.privilege_type='EXECUTE'
  )
  AND NOT EXISTS (
    SELECT 1 FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
    WHERE p.oid='public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)'::regprocedure
      AND acl.grantee=0 AND acl.privilege_type='EXECUTE'
  )
  AND has_function_privilege('nova_revocation_enqueuer_owner','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_media_revocation_worker','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_reports_worker','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_fastify_runtime','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE')
  AND has_function_privilege('nova_media_revocation_worker','public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)','EXECUTE')
  AND has_function_privilege('nova_reports_predicate_owner','public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)','EXECUTE')
  AND has_function_privilege('nova_media_purge_verifier','public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)','EXECUTE')
  AND has_function_privilege('nova_media_purge_attester','public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)','EXECUTE')
  AND has_function_privilege('nova_media_removal_authority','public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_reports_worker','public.nova_rls_valid_media_revocation(uuid,uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_tag_catalog_writer','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_rate_limiter_runtime','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_feedback_cleanup','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_security_reports_cleanup','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_audit_cleanup','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_story_lifecycle_manager','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_media_lifecycle_manager','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_story_moderation_manager','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE')
  AND NOT has_function_privilege('nova_media_upload_verifier','public.nova_rls_valid_media_revocation(uuid,text,uuid)','EXECUTE'));
SELECT pg_temp.assert_denied('runtime cannot probe arbitrary media/action validity using enqueue helper',
  $stmt$SELECT public.nova_rls_valid_media_revocation(
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','ready/arbitrary/key.jpg',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb')$stmt$);
SELECT pg_temp.assert_denied('runtime cannot call queue-bound validity helper with arbitrary identifiers',
  $stmt$SELECT public.nova_rls_valid_media_revocation(
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    'ready/arbitrary/key.jpg','cccccccc-cccc-4ccc-8ccc-cccccccccccc')$stmt$);
RESET ROLE;
SELECT pg_temp.assert_true('old caller-controlled upload limit signature is absent',
  to_regprocedure('public.nova_complete_media_upload(uuid,bigint,text,bigint)') IS NULL
  AND to_regprocedure('public.nova_complete_media_upload(uuid,bigint,text,boolean)') IS NULL
  AND to_regprocedure('public.nova_complete_media_upload(uuid,bigint,text)') IS NULL
  AND has_function_privilege('nova_fastify_runtime','public.nova_complete_media_upload(uuid)','EXECUTE')
  AND to_regprocedure('public.nova_record_media_upload_verification(uuid,bigint,text,text)') IS NULL
  AND NOT has_function_privilege('nova_fastify_runtime','public.nova_record_media_upload_verification(uuid,uuid,text,bigint,text,text)','EXECUTE')
  AND has_function_privilege('nova_media_upload_gateway','public.nova_record_media_upload_verification(uuid,uuid,text,bigint,text,text)','EXECUTE')
  AND has_function_privilege('nova_fastify_runtime','public.nova_begin_media_upload(uuid)','EXECUTE')
  AND has_function_privilege('nova_fastify_runtime','public.nova_cancel_media_upload(uuid)','EXECUTE')
  AND (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
       WHERE oid='nova_security_fixture.media_upload_verifications'::regclass)
  AND NOT has_table_privilege('nova_fastify_runtime','nova_security_fixture.media_upload_verifications','SELECT')
  AND NOT has_table_privilege('nova_media_upload_gateway','nova_security_fixture.media_upload_verifications','INSERT')
  AND NOT has_table_privilege('nova_media_upload_gateway','public.media_assets','SELECT'));
SET LOCAL ROLE nova_fastify_runtime;
SELECT pg_temp.assert_true('API runtime has no rate bucket grant',
  NOT has_table_privilege('nova_fastify_runtime','public.rate_limit_buckets','INSERT')
  AND NOT has_table_privilege('nova_fastify_runtime','public.rate_limit_buckets','SELECT'));
SELECT pg_temp.assert_denied('runtime rate bucket write denied',
  $stmt$INSERT INTO public.rate_limit_buckets(bucket_key,window_start,hits) VALUES(repeat('a',64),now(),1)$stmt$);
SELECT pg_temp.assert_denied('bootstrap user INSERT denied without narrow path',
  $stmt$INSERT INTO public.users(auth_subject,username,username_normalized) VALUES('fixture-new-subject','fixture_new','fixture_new')$stmt$);
COMMIT;

-- Dedicated rate-limiter role can use hashed keys while API runtime cannot.
BEGIN;
SET LOCAL ROLE nova_rate_limiter_runtime;
INSERT INTO public.rate_limit_buckets(bucket_key,window_start,hits) VALUES(repeat('a',64),now(),1)
ON CONFLICT(bucket_key) DO UPDATE SET hits=rate_limit_buckets.hits+1 RETURNING hits;
SELECT pg_temp.assert_true('dedicated limiter principal can write bucket',
  (SELECT count(*)=1 FROM public.rate_limit_buckets WHERE bucket_key=repeat('a',64)));
COMMIT;

-- Story owner lifecycle and direct DML attempts.
BEGIN;
SET LOCAL ROLE nova_fastify_runtime;
SELECT set_config('app.user_id','10000000-0000-4000-8000-000000000001',true);
SELECT set_config('app.auth_subject','fixture-only-owner-subject',true);
SELECT set_config('app.user_role','reader',true);
SELECT pg_temp.assert_denied('owner direct publish state denied',
  $stmt$UPDATE public.stories SET status='published',visibility='public',published_at=now() WHERE id='30000000-0000-4000-8000-000000000001'$stmt$);
SELECT pg_temp.assert_denied('owner direct deleted/removed state denied',
  $stmt$UPDATE public.stories SET status='removed',visibility='private',deleted_at=now() WHERE id='30000000-0000-4000-8000-000000000001'$stmt$);
SELECT pg_temp.assert_true('owner publish controlled transition succeeds',
  public.nova_transition_story('30000000-0000-4000-8000-000000000001','publish'));
SELECT pg_temp.assert_true('controlled publish sets consistent state',
  (SELECT status::text='published' AND visibility::text='public' AND published_at IS NOT NULL
   FROM public.stories WHERE id='30000000-0000-4000-8000-000000000001'));
SELECT pg_temp.assert_denied('owner direct unpublish DML denied',
  $stmt$UPDATE public.stories SET status='draft',visibility='private',published_at=NULL WHERE id='30000000-0000-4000-8000-000000000001'$stmt$);
SELECT pg_temp.assert_true('owner unpublish controlled transition succeeds',
  public.nova_transition_story('30000000-0000-4000-8000-000000000001','unpublish'));
SELECT pg_temp.assert_true('owner soft-delete controlled transition succeeds',
  public.nova_transition_story('30000000-0000-4000-8000-000000000001','soft_delete'));
COMMIT;

-- Nonce-bound uploads: direct DML is denied; attempts use unique keys, verified versions and server limits.
GRANT UPDATE(object_key,size_bytes,checksum,ready_at,upload_nonce) ON public.media_assets TO nova_fastify_runtime;
BEGIN;
SET LOCAL ROLE nova_fastify_runtime;
SELECT set_config('app.user_id','10000000-0000-4000-8000-000000000001',true);
SELECT set_config('app.auth_subject','fixture-only-owner-subject',true);
SELECT set_config('app.user_role','reader',true);
SELECT pg_temp.assert_denied('owner cannot fake ready status',
  $stmt$UPDATE public.media_assets SET status='ready' WHERE id='20000000-0000-4000-8000-000000000006'$stmt$);
SELECT pg_temp.assert_denied('owner cannot swap upload object key',
  $stmt$UPDATE public.media_assets SET object_key='ready/10000000-0000-4000-8000-000000000001/forged.jpg' WHERE id='20000000-0000-4000-8000-000000000006'$stmt$);
SELECT pg_temp.assert_denied('owner cannot forge media size/checksum/readiness',
  $stmt$UPDATE public.media_assets SET size_bytes=1,checksum=repeat('0',64),ready_at=now() WHERE id='20000000-0000-4000-8000-000000000006'$stmt$);
SELECT pg_temp.assert_denied('owner cannot insert media with another owner key',
  $stmt$INSERT INTO public.media_assets(id,owner_id,purpose,object_key,mime_type,size_bytes) VALUES('20000000-0000-4000-8000-000000000009','10000000-0000-4000-8000-000000000001','avatar','pending/10000000-0000-4000-8000-000000000002/20000000-0000-4000-8000-000000000009.jpg','image/jpeg',64)$stmt$);
INSERT INTO public.media_assets(id,owner_id,purpose,object_key,mime_type,size_bytes)
VALUES('20000000-0000-4000-8000-000000000010','10000000-0000-4000-8000-000000000001','avatar','pending/10000000-0000-4000-8000-000000000001/20000000-0000-4000-8000-000000000010.jpg','image/jpeg',128);
SELECT pg_temp.assert_denied('owner cannot start processing by direct status update',
  $stmt$UPDATE public.media_assets SET status='processing',updated_at=now() WHERE id='20000000-0000-4000-8000-000000000006'$stmt$);
SELECT upload_nonce AS nonce,object_key AS objkey FROM public.nova_begin_media_upload('20000000-0000-4000-8000-000000000005') \gset first_
SELECT pg_temp.assert_true('first attempt key embeds a fresh nonce',
  :'first_nonce'::uuid IS NOT NULL AND :'first_objkey' LIKE '%/20000000-0000-4000-8000-000000000005/'||:'first_nonce'||'.jpg');
RESET ROLE;
SET LOCAL ROLE nova_media_upload_gateway;
SELECT pg_temp.assert_true('trusted gateway records first-generation proof',
  public.nova_record_media_upload_verification('20000000-0000-4000-8000-000000000005',:'first_nonce'::uuid,'fixture-object-v1',96,repeat('1',64),'upload-attempt-one'));
RESET ROLE;
SET LOCAL ROLE nova_fastify_runtime;
SELECT set_config('app.user_id','10000000-0000-4000-8000-000000000001',true);
SELECT set_config('app.auth_subject','fixture-only-owner-subject',true);
SELECT set_config('app.user_role','reader',true);
SELECT pg_temp.assert_true('owner cancellation resets processing and invalidates proof',
  public.nova_cancel_media_upload('20000000-0000-4000-8000-000000000005'));
RESET ROLE;
SELECT pg_temp.assert_true('cancel removes stale proof but preserves only pending row',
  NOT EXISTS (SELECT 1 FROM nova_security_fixture.media_upload_verifications WHERE media_id='20000000-0000-4000-8000-000000000005')
  AND (SELECT status::text='pending' FROM public.media_assets WHERE id='20000000-0000-4000-8000-000000000005'));
SET LOCAL ROLE nova_fastify_runtime;
SELECT upload_nonce AS nonce,object_key AS objkey FROM public.nova_begin_media_upload('20000000-0000-4000-8000-000000000005') \gset second_
SELECT pg_temp.assert_true('restart uses a different nonce and never reuses the prior object key',
  :'first_nonce'::uuid IS DISTINCT FROM :'second_nonce'::uuid AND :'first_objkey' IS DISTINCT FROM :'second_objkey');
SELECT pg_temp.assert_denied('runtime cannot call trusted upload verifier',
  format($stmt$SELECT public.nova_record_media_upload_verification('20000000-0000-4000-8000-000000000005',%L::uuid,'fixture-object-v2',96,repeat('2',64),'forged')$stmt$, :'second_nonce'));
SELECT pg_temp.assert_true('second attempt cancellation returns fixture asset to pending',
  public.nova_cancel_media_upload('20000000-0000-4000-8000-000000000005'));
RESET ROLE;
SET LOCAL ROLE nova_media_upload_gateway;
SELECT pg_temp.assert_denied('stale prior nonce cannot record proof after restart',
  format($stmt$SELECT public.nova_record_media_upload_verification('20000000-0000-4000-8000-000000000005',%L::uuid,'fixture-object-v1',96,repeat('1',64),'replayed')$stmt$, :'first_nonce'));
RESET ROLE;
SET LOCAL ROLE nova_fastify_runtime;
SELECT upload_nonce AS nonce,object_key AS objkey FROM public.nova_begin_media_upload('20000000-0000-4000-8000-000000000006') \gset active_
SELECT pg_temp.assert_true('upload start issued nonce-bound temporary key',
  :'active_nonce'::uuid IS NOT NULL AND :'active_objkey' LIKE '%/20000000-0000-4000-8000-000000000006/'||:'active_nonce'||'.jpg');
SELECT pg_temp.assert_denied('API runtime cannot record storage verification',
  format($stmt$SELECT public.nova_record_media_upload_verification('20000000-0000-4000-8000-000000000006',%L::uuid,'fixture-object-v3',96,repeat('3',64),'forged')$stmt$, :'active_nonce'));
SELECT pg_temp.assert_denied('API runtime cannot insert upload proof directly',
  format($stmt$INSERT INTO nova_security_fixture.media_upload_verifications(media_id,owner_id,upload_nonce,source_key,storage_object_version,measured_size,checksum_sha256,audit_ref,verified_by,verified_at)
    VALUES('20000000-0000-4000-8000-000000000006','10000000-0000-4000-8000-000000000001',%L::uuid,%L,'fixture-object-v3',96,repeat('3',64),'forged','nova_fastify_runtime',now())$stmt$, :'active_nonce', :'active_objkey'));
SELECT pg_temp.assert_denied('completion cannot proceed before verifier proof',
  $stmt$SELECT public.nova_complete_media_upload('20000000-0000-4000-8000-000000000006')$stmt$);
RESET ROLE;
SET LOCAL ROLE nova_media_upload_gateway;
SELECT pg_temp.assert_denied('trusted verifier enforces server-side avatar byte limit before recording proof',
  format($stmt$SELECT public.nova_record_media_upload_verification('20000000-0000-4000-8000-000000000006',%L::uuid,'fixture-object-v3',5242881,repeat('3',64),'fixture-too-large')$stmt$, :'active_nonce'),'22023');
SELECT pg_temp.assert_true('trusted gateway records measured fields and immutable storage object version',
  public.nova_record_media_upload_verification('20000000-0000-4000-8000-000000000006',:'active_nonce'::uuid,'fixture-object-v3',96,repeat('3',64),'fixture-upload-audit-001'));
SELECT pg_temp.assert_denied('upload gateway has no direct table write access after proof',
  $stmt$UPDATE public.media_assets SET object_key='forged' WHERE id='20000000-0000-4000-8000-000000000006'$stmt$);
RESET ROLE;
SELECT pg_temp.assert_true('upload proof persists current nonce, key, object version and trusted owner',
  (SELECT count(*)=1 AND min(owner_id::text)='10000000-0000-4000-8000-000000000001'
      AND min(upload_nonce::text)=:'active_nonce' AND min(source_key)=:'active_objkey'
      AND min(storage_object_version)='fixture-object-v3' AND min(measured_size)=96
      AND min(checksum_sha256)=repeat('3',64) AND min(audit_ref)='fixture-upload-audit-001'
      AND min(verified_by::text)='nova_media_upload_verifier'
    FROM nova_security_fixture.media_upload_verifications WHERE media_id='20000000-0000-4000-8000-000000000006'));
SET LOCAL ROLE nova_fastify_runtime;
SELECT pg_temp.assert_true('runtime completion consumes proof for current nonce without client measurements',
  public.nova_complete_media_upload('20000000-0000-4000-8000-000000000006'));
SELECT pg_temp.assert_denied('ready media cannot replay completion against stale proof',
  $stmt$SELECT public.nova_complete_media_upload('20000000-0000-4000-8000-000000000006')$stmt$);
SELECT pg_temp.assert_true('completed media is canonical and ready',
  (SELECT status::text='ready' AND object_key='ready/10000000-0000-4000-8000-000000000001/20000000-0000-4000-8000-000000000006.jpg'
     AND size_bytes=96 AND checksum=repeat('3',64) AND ready_at IS NOT NULL
   FROM public.media_assets WHERE id='20000000-0000-4000-8000-000000000006'));
RESET ROLE;
COMMIT;
REVOKE UPDATE(object_key,size_bytes,checksum,ready_at,upload_nonce) ON public.media_assets FROM nova_fastify_runtime;
UPDATE public.users SET avatar_media_id='20000000-0000-4000-8000-000000000001'
 WHERE id='10000000-0000-4000-8000-000000000001';
SELECT pg_temp.assert_true('valid owner avatar reference accepted',
  (SELECT avatar_media_id='20000000-0000-4000-8000-000000000001'
   FROM public.users WHERE id='10000000-0000-4000-8000-000000000001'));
SELECT pg_temp.assert_denied('avatar reference rejects wrong purpose',
  $stmt$UPDATE public.users SET avatar_media_id='20000000-0000-4000-8000-000000000002' WHERE id='10000000-0000-4000-8000-000000000001'$stmt$,'23514');
SELECT pg_temp.assert_denied('story cover rejects foreign owner',
  $stmt$INSERT INTO public.stories(id,author_id,title,slug,body,cover_media_id) VALUES('30000000-0000-4000-8000-000000000006','10000000-0000-4000-8000-000000000001','Bad foreign cover','bad-foreign-cover','Test','20000000-0000-4000-8000-000000000003')$stmt$,'23514');
SELECT pg_temp.assert_denied('story cover rejects pending media',
  $stmt$INSERT INTO public.stories(id,author_id,title,slug,body,cover_media_id) VALUES('30000000-0000-4000-8000-000000000007','10000000-0000-4000-8000-000000000001','Bad pending cover','bad-pending-cover','Test','20000000-0000-4000-8000-000000000005')$stmt$,'23514');
INSERT INTO public.stories(id,author_id,title,slug,body,cover_media_id)
VALUES('30000000-0000-4000-8000-000000000010','10000000-0000-4000-8000-000000000001','Valid cover','valid-cover','Test','20000000-0000-4000-8000-000000000002');
SELECT pg_temp.assert_denied('feedback screenshot rejects foreign owner',
  $stmt$INSERT INTO public.beta_feedback(reporter_id,category,summary,screenshot_media_id,expires_at) VALUES('10000000-0000-4000-8000-000000000001','bug','Test','20000000-0000-4000-8000-000000000008',now()+interval '1 day')$stmt$,'23514');
SELECT pg_temp.assert_denied('feedback screenshot rejects wrong purpose',
  $stmt$INSERT INTO public.beta_feedback(reporter_id,category,summary,screenshot_media_id,expires_at) VALUES('10000000-0000-4000-8000-000000000001','bug','Test','20000000-0000-4000-8000-000000000002',now()+interval '1 day')$stmt$,'23514');
COMMIT;
REVOKE UPDATE(object_key,size_bytes,checksum,ready_at) ON public.media_assets FROM nova_fastify_runtime;

-- A moderator can perform only a constrained hide/restore transition; no soft delete or content edit.
BEGIN;
SET LOCAL ROLE nova_fastify_runtime;
SELECT set_config('app.user_id','10000000-0000-4000-8000-000000000003',true);
SELECT set_config('app.auth_subject','fixture-only-moderator-subject',true);
SELECT set_config('app.user_role','moderator',true);
SELECT pg_temp.assert_true('runtime has no direct moderation_actions INSERT privilege',
  NOT has_table_privilege('nova_fastify_runtime','public.moderation_actions','INSERT')
  AND NOT has_column_privilege('nova_fastify_runtime','public.moderation_actions','action','INSERT'));
SELECT pg_temp.assert_denied('moderator direct hide without linked moderation action is denied',
  $stmt$UPDATE public.stories SET status='removed',visibility='private',comments_open=false,version=version+1,updated_at=now()
    WHERE id='30000000-0000-4000-8000-000000000003'$stmt$);
SELECT pg_temp.assert_true('direct hide denial leaves story and action log unchanged',
  (SELECT status::text='published' AND visibility::text='public' FROM public.stories WHERE id='30000000-0000-4000-8000-000000000003')
  AND (SELECT count(*)=0 FROM public.moderation_actions WHERE target_type='story'
       AND target_id='30000000-0000-4000-8000-000000000003' AND action='hide_story'));
SELECT pg_temp.assert_denied('atomic hide rejects already removed target without orphan action',
  $stmt$SELECT public.nova_moderate_hide_story('30000000-0000-4000-8000-000000000004','invalid duplicate hide')$stmt$);
SELECT pg_temp.assert_true('rejected atomic hide leaves no extra linked action',
  (SELECT count(*)=1 FROM public.moderation_actions WHERE target_type='story'
    AND target_id='30000000-0000-4000-8000-000000000004' AND action='hide_story'));
SELECT public.nova_moderate_hide_story('30000000-0000-4000-8000-000000000003','Fixture validated hide');
SELECT pg_temp.assert_true('atomic hide creates a matching action and removes story together',
  EXISTS (SELECT 1 FROM public.moderation_actions a WHERE a.target_type='story'
    AND a.target_id='30000000-0000-4000-8000-000000000003' AND a.action='hide_story'
    AND a.moderator_id='10000000-0000-4000-8000-000000000003')
  AND (SELECT status::text='removed' AND visibility::text='private' AND deleted_at IS NULL
       FROM public.stories WHERE id='30000000-0000-4000-8000-000000000003'));
SELECT pg_temp.assert_denied('moderator cannot directly restore removed story to draft',
  $stmt$UPDATE public.stories SET status='draft',visibility='private',comments_open=false,version=version+1
    WHERE id='30000000-0000-4000-8000-000000000003'$stmt$);
SELECT pg_temp.assert_denied('moderator cannot directly restore removed story to published',
  $stmt$UPDATE public.stories SET status='published',visibility='public',comments_open=true,version=version+1
    WHERE id='30000000-0000-4000-8000-000000000003'$stmt$);
SELECT pg_temp.assert_denied('moderator cannot insert forged unlinked moderation action',
  $stmt$INSERT INTO public.moderation_actions(moderator_id,target_type,target_id,action,reason)
    VALUES('10000000-0000-4000-8000-000000000003','story','30000000-0000-4000-8000-000000000099','restore_story','forged')$stmt$);
SELECT pg_temp.assert_true('direct restore/action attempts left hidden story without restore action',
  (SELECT status::text='removed' AND visibility::text='private' FROM public.stories
    WHERE id='30000000-0000-4000-8000-000000000003')
  AND NOT EXISTS (SELECT 1 FROM public.moderation_actions WHERE target_id='30000000-0000-4000-8000-000000000003' AND action='restore_story'));
SELECT set_config('app.user_id','10000000-0000-4000-8000-000000000004',true);
SELECT set_config('app.auth_subject','fixture-only-admin-subject',true);
SELECT set_config('app.user_role','admin',true);
SELECT pg_temp.assert_denied('admin cannot insert forged unlinked moderation action',
  $stmt$INSERT INTO public.moderation_actions(moderator_id,target_type,target_id,action,reason)
    VALUES('10000000-0000-4000-8000-000000000004','story','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','suspend_user','forged')$stmt$);
SELECT set_config('app.user_id','10000000-0000-4000-8000-000000000003',true);
SELECT set_config('app.auth_subject','fixture-only-moderator-subject',true);
SELECT set_config('app.user_role','moderator',true);
SELECT public.nova_moderate_restore_story(
  '30000000-0000-4000-8000-000000000003',
  (SELECT id FROM public.moderation_actions WHERE target_type='story'
    AND target_id='30000000-0000-4000-8000-000000000003' AND action='hide_story'
    ORDER BY created_at DESC,id DESC LIMIT 1),
  'Fixture validated restore');
SELECT pg_temp.assert_true('atomic restore adds linked allowlisted action and restores story together',
  EXISTS (SELECT 1 FROM public.moderation_actions a WHERE a.target_type='story'
    AND a.target_id='30000000-0000-4000-8000-000000000003' AND a.action='restore_story'
    AND a.moderator_id='10000000-0000-4000-8000-000000000003'
    AND a.metadata->>'restoredCommentsOpen'='true')
  AND (SELECT status::text='published' AND visibility::text='public' AND published_at IS NOT NULL
      AND comments_open FROM public.stories WHERE id='30000000-0000-4000-8000-000000000003'));
SELECT public.nova_moderate_hide_story('30000000-0000-4000-8000-000000000008','Hide story with no cover') AS action_id \gset no_media_
RESET ROLE;
SELECT pg_temp.assert_true('no-media outcome is explicitly linked atomically to hide action and removed story',
  EXISTS (SELECT 1 FROM public.moderation_actions a JOIN public.media_no_media_required n ON n.action_id=a.id
    JOIN public.stories s ON s.id=n.target_story_id
    WHERE a.id=:'no_media_action_id'::uuid AND a.target_id='30000000-0000-4000-8000-000000000008'
      AND a.action='hide_story' AND a.metadata->>'removalStatus'='no_media_required'
      AND n.result='no_media_required' AND n.recorded_by='nova_story_moderation_manager'
      AND s.cover_media_id IS NULL AND s.status::text='removed' AND s.visibility::text='private'));
SELECT public.nova_moderate_hide_story('30000000-0000-4000-8000-000000000011','Hide separate valid cover target') AS action_id \gset unrelated_
SET LOCAL ROLE nova_fastify_runtime;
SELECT pg_temp.assert_denied('runtime cannot fabricate no-media proof',
  $stmt$INSERT INTO nova_security_fixture.media_no_media_required(action_id,target_story_id,result,recorded_by,recorded_at)
    VALUES('40000000-0000-4000-8000-000000000099','30000000-0000-4000-8000-000000000008','no_media_required','nova_fastify_runtime',now())$stmt$);
SELECT pg_temp.assert_true('successful hide action and story transition roll back together',
  pg_temp.atomic_hide_rollback_probe('30000000-0000-4000-8000-000000000009','Fixture forced rollback'));
SELECT pg_temp.assert_denied('moderator cannot set deleted_at by direct update',
  $stmt$UPDATE public.stories SET deleted_at=now(),version=version+1 WHERE id='30000000-0000-4000-8000-000000000003'$stmt$);
SELECT pg_temp.assert_denied('moderator cannot edit another owner story body',
  $stmt$UPDATE public.stories SET body='tampered',version=version+1 WHERE id='30000000-0000-4000-8000-000000000003'$stmt$);
COMMIT;
INSERT INTO public.reports(id,reporter_id,target_type,target_id,reason,status,removal_pending)
VALUES('50000000-0000-4000-8000-000000000004','10000000-0000-4000-8000-000000000001',
  'story','30000000-0000-4000-8000-000000000003','other','reviewing',true);
INSERT INTO public.reports(id,reporter_id,target_type,target_id,reason,status,removal_pending)
VALUES('50000000-0000-4000-8000-000000000005','10000000-0000-4000-8000-000000000002',
  'story','30000000-0000-4000-8000-000000000008','other','reviewing',true);
INSERT INTO public.reports(id,reporter_id,target_type,target_id,reason,status,removal_pending)
VALUES('50000000-0000-4000-8000-000000000006','10000000-0000-4000-8000-000000000003',
  'story','30000000-0000-4000-8000-000000000004','other','received',false);

BEGIN;
SET LOCAL ROLE nova_revocation_enqueuer_owner;
SELECT pg_temp.assert_true('separate cover and hide action form a valid but unqueued tuple',
  public.nova_rls_valid_media_revocation('20000000-0000-4000-8000-000000000003',
    'ready/10000000-0000-4000-8000-000000000002/20000000-0000-4000-8000-000000000003.jpg',
    :'unrelated_action_id'::uuid));
COMMIT;

-- Worker isolation: metadata-only revocation queue, no media_assets access, and only pending removal reports.
BEGIN;
SET LOCAL ROLE nova_media_revocation_worker;
SELECT pg_temp.assert_true('revocation worker sees only valid linked queue row',
  (SELECT count(*)=1 FROM public.media_key_revocations));
SELECT pg_temp.assert_true('worker arbitrary media/action identifiers return false',
  NOT public.nova_rls_valid_media_revocation('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','ready/arbitrary/key.jpg','cccccccc-cccc-4ccc-8ccc-cccccccccccc'));
SELECT pg_temp.assert_true('queue-bound helper accepts its exact row tuple',
  (SELECT count(*)=1 AND bool_and(public.nova_rls_valid_media_revocation(id,media_id,source_key,moderation_action_id))
   FROM public.media_key_revocations));
SELECT pg_temp.assert_true('queue-bound helper rejects an unrelated but independently valid media/action tuple',
  (SELECT count(*)=1 AND bool_and(NOT public.nova_rls_valid_media_revocation(id,
    '20000000-0000-4000-8000-000000000003',
    'ready/10000000-0000-4000-8000-000000000002/20000000-0000-4000-8000-000000000003.jpg',
    :'unrelated_action_id'::uuid)) FROM public.media_key_revocations));
SELECT pg_temp.assert_denied('revocation worker cannot read media_assets',
  $stmt$SELECT id FROM public.media_assets$stmt$);
SELECT pg_temp.assert_denied('revocation worker cannot update media_assets',
  $stmt$UPDATE public.media_assets SET object_key='x' WHERE id='20000000-0000-4000-8000-000000000007'$stmt$);
SELECT pg_temp.assert_denied('revocation worker cannot delete due queue without trusted purge verification',
  $stmt$DELETE FROM public.media_key_revocations WHERE moderation_action_id='40000000-0000-4000-8000-000000000001'$stmt$);
SELECT pg_temp.assert_denied('revocation worker cannot mark moderation action verified',
  $stmt$UPDATE public.moderation_actions SET metadata=metadata||jsonb_build_object('removalStatus','verified','removalVerifiedAt',now())
    WHERE id='40000000-0000-4000-8000-000000000001'$stmt$);
SELECT pg_temp.assert_true('revocation worker sees valid linked actions but excludes the invalid decoy',
  (SELECT count(*)=4 AND count(*) FILTER (WHERE id='40000000-0000-4000-8000-000000000002')=0
   FROM public.moderation_actions));
SELECT pg_temp.assert_denied('worker cannot alter retry counter arbitrarily',
  $stmt$UPDATE public.media_key_revocations SET attempt_count=attempt_count+2,retry_after=now()+interval '10 seconds' WHERE moderation_action_id='40000000-0000-4000-8000-000000000001'$stmt$);
UPDATE public.media_key_revocations SET attempt_count=attempt_count+1,
  retry_after=statement_timestamp()+interval '30 seconds'
 WHERE moderation_action_id='40000000-0000-4000-8000-000000000001';
SELECT pg_temp.assert_true('first retry has the fixed 30-second backoff',
  (SELECT count(*)=1 AND min(attempt_count)=1 AND min(retry_after)>statement_timestamp()
   FROM public.media_key_revocations));
SELECT pg_temp.assert_no_effect('worker cannot retry a row before it is due',
  $stmt$UPDATE public.media_key_revocations SET attempt_count=attempt_count+1,
    retry_after=statement_timestamp()+interval '2 minutes' WHERE moderation_action_id='40000000-0000-4000-8000-000000000001'$stmt$);
SELECT pg_temp.assert_denied('worker cannot directly delete a scheduled retry row',
  $stmt$DELETE FROM public.media_key_revocations WHERE moderation_action_id='40000000-0000-4000-8000-000000000001'$stmt$);
COMMIT;

UPDATE public.media_key_revocations SET retry_after=statement_timestamp()-interval '1 second'
 WHERE moderation_action_id='40000000-0000-4000-8000-000000000001';
BEGIN;
SET LOCAL ROLE nova_media_revocation_worker;
SELECT pg_temp.assert_denied('worker cannot choose a shorter second retry delay',
  $stmt$UPDATE public.media_key_revocations SET attempt_count=2,
    retry_after=statement_timestamp()+interval '5 seconds'
    WHERE moderation_action_id='40000000-0000-4000-8000-000000000001'$stmt$);
UPDATE public.media_key_revocations SET attempt_count=2,retry_after=statement_timestamp()+interval '2 minutes'
 WHERE moderation_action_id='40000000-0000-4000-8000-000000000001';
COMMIT;

UPDATE public.media_key_revocations SET retry_after=statement_timestamp()-interval '1 second'
 WHERE moderation_action_id='40000000-0000-4000-8000-000000000001';
BEGIN;
SET LOCAL ROLE nova_media_revocation_worker;
UPDATE public.media_key_revocations SET attempt_count=3,retry_after=statement_timestamp()+interval '10 minutes'
 WHERE moderation_action_id='40000000-0000-4000-8000-000000000001';
COMMIT;

UPDATE public.media_key_revocations SET retry_after=statement_timestamp()-interval '1 second'
 WHERE moderation_action_id='40000000-0000-4000-8000-000000000001';
BEGIN;
SET LOCAL ROLE nova_media_revocation_worker;
UPDATE public.media_key_revocations SET attempt_count=4,retry_after=statement_timestamp()+interval '30 minutes'
 WHERE moderation_action_id='40000000-0000-4000-8000-000000000001';
COMMIT;

UPDATE public.media_key_revocations SET retry_after=statement_timestamp()-interval '1 second'
 WHERE moderation_action_id='40000000-0000-4000-8000-000000000001';
BEGIN;
SET LOCAL ROLE nova_media_revocation_worker;
UPDATE public.media_key_revocations SET attempt_count=5,retry_after=statement_timestamp()+interval '2 hours',
  escalated_at=statement_timestamp() WHERE moderation_action_id='40000000-0000-4000-8000-000000000001';
SELECT pg_temp.assert_true('fifth retry escalates and leaves queue in terminal state',
  (SELECT count(*)=1 AND min(attempt_count)=5 AND min(escalated_at) IS NOT NULL
   FROM public.media_key_revocations));
SELECT pg_temp.assert_no_effect('worker cannot retry a terminally escalated row',
  $stmt$UPDATE public.media_key_revocations SET attempt_count=6,retry_after=statement_timestamp()+interval '1 day'
    WHERE moderation_action_id='40000000-0000-4000-8000-000000000001'$stmt$);
SELECT pg_temp.assert_denied('worker cannot delete terminal escalated row without trusted verification',
  $stmt$DELETE FROM public.media_key_revocations WHERE moderation_action_id='40000000-0000-4000-8000-000000000001'$stmt$);
COMMIT;

-- A synthetic attestation is only a test input; it is not evidence of real storage bytes or cache purge.
SELECT id AS purge_revocation_id FROM public.media_key_revocations
 WHERE moderation_action_id='40000000-0000-4000-8000-000000000001' \gset
BEGIN;
SET LOCAL ROLE nova_media_purge_attester;
SELECT public.nova_record_media_purge_attestation(:'purge_revocation_id'::uuid,
  'fixture-object-v1','synthetic-attestation-only-test-input');
COMMIT;
SELECT pg_temp.assert_true('attestation alone leaves queue, moderation status and authoritative outcome pending',
  EXISTS (SELECT 1 FROM public.media_key_revocations WHERE id=:'purge_revocation_id'::uuid)
  AND EXISTS (SELECT 1 FROM nova_security_fixture.media_purge_attestations v
    WHERE v.revocation_id=:'purge_revocation_id'::uuid AND v.storage_object_version='fixture-object-v1'
      AND v.attestation_ref='synthetic-attestation-only-test-input'
      AND v.attested_by='nova_media_purge_attester')
  AND NOT EXISTS (SELECT 1 FROM nova_security_fixture.media_removal_authoritative_outcomes
    WHERE revocation_id=:'purge_revocation_id'::uuid)
  AND (SELECT metadata->>'removalStatus'='pending' FROM public.moderation_actions
    WHERE id='40000000-0000-4000-8000-000000000001'));

BEGIN;
SET LOCAL ROLE nova_reports_worker;
SELECT pg_temp.assert_true('reports worker sees only valid row-bound removal-pending reports',
  (SELECT count(*)=3 FROM public.reports));
SELECT set_config('nova.fixture_reports_target_type','story',true),
  set_config('nova.fixture_reports_target_id','30000000-0000-4000-8000-000000000004',true);
SELECT pg_temp.assert_true('conflicting caller GUC cannot expand visibility to a report without a valid row-bound hide action',
  (SELECT count(*)=0 FROM public.reports WHERE id='50000000-0000-4000-8000-000000000002'));
SELECT pg_temp.assert_true('conflicting caller GUC does not hide an independently valid row-bound pending report',
  (SELECT count(*)=1 FROM public.reports WHERE id='50000000-0000-4000-8000-000000000001'));
SELECT set_config('nova.fixture_reports_target_type','',true),
  set_config('nova.fixture_reports_target_id','',true);
SELECT pg_temp.assert_true('absent caller GUC still permits only a valid row-bound pending report',
  (SELECT count(*)=1 FROM public.reports WHERE id='50000000-0000-4000-8000-000000000001'));
SELECT pg_temp.assert_true('reports worker cannot read a non-pending case on a valid hidden target',
  (SELECT count(*)=0 FROM public.reports WHERE id='50000000-0000-4000-8000-000000000006'));
SELECT pg_temp.assert_true('reports worker cannot read a report whose target has no hide action',
  (SELECT count(*)=0 FROM public.reports WHERE id='50000000-0000-4000-8000-000000000002'));
SELECT pg_temp.assert_denied('reports worker cannot read report details',
  $stmt$SELECT details FROM public.reports$stmt$);
SELECT pg_temp.assert_denied('reports worker cannot close while queue remains after attestation only',
  $stmt$UPDATE public.reports SET status='actioned',removal_pending=false,updated_at=now(),closed_at=NULL WHERE id='50000000-0000-4000-8000-000000000001'$stmt$);
SELECT pg_temp.assert_denied('reports worker cannot close unrelated target merely because queue is absent',
  $stmt$UPDATE public.reports SET status='actioned',removal_pending=false,updated_at=now(),closed_at=NULL WHERE id='50000000-0000-4000-8000-000000000004'$stmt$);
SELECT pg_temp.assert_no_effect('reports worker cannot update a non-pending report even for a valid hidden target',
  $stmt$UPDATE public.reports SET status='actioned',removal_pending=false,updated_at=now(),closed_at=NULL WHERE id='50000000-0000-4000-8000-000000000006'$stmt$);
UPDATE public.reports SET status='actioned',removal_pending=false,updated_at=now(),closed_at=NULL
 WHERE id='50000000-0000-4000-8000-000000000005';
RESET ROLE;
SELECT pg_temp.assert_true('case with no cover closes only after explicit linked no_media_required outcome',
  (SELECT status::text='actioned' AND NOT removal_pending FROM public.reports WHERE id='50000000-0000-4000-8000-000000000005'));
COMMIT;

-- Neither runtime nor either gateway can delete the queue, close a case, or invoke the authority finalizer.
BEGIN;
SET LOCAL ROLE nova_fastify_runtime;
SELECT set_config('app.user_id','10000000-0000-4000-8000-000000000003',true);
SELECT set_config('app.auth_subject','fixture-only-moderator-subject',true);
SELECT set_config('app.user_role','moderator',true);
SELECT pg_temp.assert_denied('runtime cannot delete revocation queue',
  $stmt$DELETE FROM public.media_key_revocations WHERE id='20000000-0000-4000-8000-000000000007'$stmt$);
SELECT pg_temp.assert_no_effect('runtime cannot close removal case',
  $stmt$UPDATE public.reports SET status='actioned',removal_pending=false WHERE id='50000000-0000-4000-8000-000000000001'$stmt$);
RESET ROLE;
SELECT pg_temp.assert_true('runtime no-effect leaves removal case pending',
  (SELECT status::text='reviewing' AND removal_pending FROM public.reports WHERE id='50000000-0000-4000-8000-000000000001'));
SET LOCAL ROLE nova_fastify_runtime;
SELECT pg_temp.assert_denied('runtime cannot invoke trusted authority finalizer',
  format($stmt$SELECT public.nova_finalize_media_key_revocation(%L::uuid,'fixture-object-v1','synthetic-ref','storage_object_and_all_cache_variants')$stmt$,
    :'purge_revocation_id'));
COMMIT;
BEGIN;
SET LOCAL ROLE nova_media_purge_gateway;
SELECT pg_temp.assert_denied('purge gateway cannot delete queue',
  $stmt$DELETE FROM public.media_key_revocations WHERE moderation_action_id='40000000-0000-4000-8000-000000000001'$stmt$);
SELECT pg_temp.assert_denied('purge gateway cannot close removal case',
  $stmt$UPDATE public.reports SET status='actioned',removal_pending=false WHERE id='50000000-0000-4000-8000-000000000001'$stmt$);
SELECT pg_temp.assert_denied('purge gateway cannot invoke backend authority finalizer',
  format($stmt$SELECT public.nova_finalize_media_key_revocation(%L::uuid,'fixture-object-v1','synthetic-ref','storage_object_and_all_cache_variants')$stmt$,
    :'purge_revocation_id'));
COMMIT;
BEGIN;
SET LOCAL ROLE nova_media_upload_gateway;
SELECT pg_temp.assert_denied('upload gateway cannot delete revocation queue',
  $stmt$DELETE FROM public.media_key_revocations WHERE moderation_action_id='40000000-0000-4000-8000-000000000001'$stmt$);
SELECT pg_temp.assert_denied('upload gateway cannot close removal case',
  $stmt$UPDATE public.reports SET status='actioned',removal_pending=false WHERE id='50000000-0000-4000-8000-000000000001'$stmt$);
COMMIT;
BEGIN;
SET LOCAL ROLE nova_media_purge_attester;
SELECT pg_temp.assert_denied('attester cannot finalize queue or case',
  format($stmt$SELECT public.nova_finalize_media_key_revocation(%L::uuid,'fixture-object-v1','synthetic-ref','storage_object_and_all_cache_variants')$stmt$,
    :'purge_revocation_id'));
COMMIT;

-- Wrong version or incomplete scope cannot finalize. Correct synthetic inputs are then checked for atomic rollback.
BEGIN;
SET LOCAL ROLE nova_media_removal_authority;
SELECT pg_temp.assert_denied('authority rejects storage evidence for a different immutable object version',
  format($stmt$SELECT public.nova_finalize_media_key_revocation(%L::uuid,'fixture-object-v2','synthetic-evidence-v2','storage_object_and_all_cache_variants')$stmt$,
    :'purge_revocation_id'));
SELECT pg_temp.assert_denied('authority rejects evidence that omits cache variants from purge scope',
  format($stmt$SELECT public.nova_finalize_media_key_revocation(%L::uuid,'fixture-object-v1','synthetic-evidence-v1','storage_object_only')$stmt$,
    :'purge_revocation_id'));
SELECT set_config('nova.fixture_probe_revocation_id',:'purge_revocation_id',true);
DO $atomic_rollback$
BEGIN
  BEGIN
    PERFORM public.nova_finalize_media_key_revocation(
      current_setting('nova.fixture_probe_revocation_id')::uuid,'fixture-object-v1',
      'synthetic-test-only-authority-evidence','storage_object_and_all_cache_variants');
    RAISE EXCEPTION 'force rollback after atomic authoritative finalization' USING ERRCODE='P0001';
  EXCEPTION WHEN SQLSTATE 'P0001' THEN NULL;
  END;
END
$atomic_rollback$;
RESET ROLE;
SELECT pg_temp.assert_true('forced rollback restores queue, removes outcome and preserves pending action/case',
  EXISTS (SELECT 1 FROM public.media_key_revocations WHERE id=:'purge_revocation_id'::uuid)
  AND NOT EXISTS (SELECT 1 FROM nova_security_fixture.media_removal_authoritative_outcomes
    WHERE revocation_id=:'purge_revocation_id'::uuid)
  AND (SELECT metadata->>'removalStatus'='pending' FROM public.moderation_actions
    WHERE id='40000000-0000-4000-8000-000000000001')
  AND (SELECT removal_pending AND status::text='reviewing' FROM public.reports
    WHERE id='50000000-0000-4000-8000-000000000001'));
SET LOCAL ROLE nova_media_removal_authority;
SELECT public.nova_finalize_media_key_revocation(:'purge_revocation_id'::uuid,
  'fixture-object-v1','synthetic-test-only-authority-evidence','storage_object_and_all_cache_variants');
RESET ROLE;
SELECT pg_temp.assert_true('authority atomically records scoped outcome, deletes queue and marks action verified',
  EXISTS (SELECT 1 FROM nova_security_fixture.media_purge_attestations a
    JOIN nova_security_fixture.media_removal_authoritative_outcomes o USING (revocation_id)
    WHERE a.revocation_id=:'purge_revocation_id'::uuid
      AND (o.media_id,o.moderation_action_id,o.source_key,o.storage_object_version)
        IS NOT DISTINCT FROM (a.media_id,a.moderation_action_id,a.source_key,a.storage_object_version)
      AND o.authority_reference='synthetic-test-only-authority-evidence'
      AND o.purge_scope='storage_object_and_all_cache_variants'
      AND o.outcome='media_removed_and_cache_purged'
      AND o.confirmed_by='nova_media_removal_authority')
  AND NOT EXISTS (SELECT 1 FROM public.media_key_revocations WHERE id=:'purge_revocation_id'::uuid)
  AND (SELECT metadata->>'removalStatus'='verified' FROM public.moderation_actions
    WHERE id='40000000-0000-4000-8000-000000000001')
  AND (SELECT removal_pending AND status::text='reviewing' FROM public.reports
    WHERE id='50000000-0000-4000-8000-000000000001'));
COMMIT;
BEGIN;
SET LOCAL ROLE nova_reports_worker;
UPDATE public.reports SET status='actioned',removal_pending=false,updated_at=now(),closed_at=NULL
 WHERE id='50000000-0000-4000-8000-000000000001';
RESET ROLE;
SELECT pg_temp.assert_true('reports worker can close case only after authority commits matching version and full purge scope',
  (SELECT status::text='actioned' AND NOT removal_pending FROM public.reports
   WHERE id='50000000-0000-4000-8000-000000000001'));
COMMIT;

-- Cleanup can inspect screenshot metadata only after expiry.
BEGIN;
SET LOCAL ROLE nova_feedback_cleanup;
SELECT pg_temp.assert_true('feedback cleanup cannot see screenshot_media_id before expiry',
  (SELECT count(*)=0 FROM public.beta_feedback));
COMMIT;
UPDATE public.beta_feedback SET expires_at=now()-interval '1 second' WHERE id='60000000-0000-4000-8000-000000000001';
BEGIN;
SET LOCAL ROLE nova_feedback_cleanup;
SELECT pg_temp.assert_true('feedback cleanup sees expired screenshot reference only',
  (SELECT count(*)=1 AND bool_and(screenshot_media_id='20000000-0000-4000-8000-000000000004') FROM public.beta_feedback));
COMMIT;

SELECT count(*) AS probes, count(*) FILTER (WHERE passed) AS passed,
       count(*) FILTER (WHERE NOT passed) AS failed
FROM nova_rls_probe_results;
SELECT name FROM nova_rls_probe_results WHERE NOT passed ORDER BY name;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM nova_rls_probe_results WHERE NOT passed) THEN
    RAISE EXCEPTION 'one or more disposable fixture probes failed';
  END IF;
END $$;
-- The database is disposable; all synthetic probe rows can be dropped with the database.
