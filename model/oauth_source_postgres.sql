CREATE SCHEMA IF NOT EXISTS newapi_oauth_source
-- statement
REVOKE ALL ON SCHEMA newapi_oauth_source FROM PUBLIC
-- statement
CREATE OR REPLACE FUNCTION newapi_oauth_source.lock_sources(p_user bigint, p_grant text)
RETURNS SETOF public.oauth_derived_token_sources
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
    SELECT s.* FROM public.oauth_derived_token_sources s
    WHERE s.user_id = p_user AND (p_grant = '' OR s.grant_ref = p_grant)
    ORDER BY s.grant_ref FOR UPDATE
$body$
-- statement
CREATE OR REPLACE FUNCTION newapi_oauth_source.terminal_source(p_user bigint, p_grant text, p_reason text, p_now bigint)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
BEGIN
    IF p_reason IS NULL OR p_reason NOT IN ('disabled', 'deleted', 'revoked')
       OR p_now IS NULL OR p_now <= 0 OR p_now > floor(extract(epoch FROM clock_timestamp())) THEN
        RAISE EXCEPTION 'OAuth source transition refused' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM public.oauth_derived_token_sources
    WHERE grant_ref = p_grant AND user_id = p_user
      AND p_now >= coalesce(created_at, verified_at)
      AND (p_reason <> 'deleted' OR terminal_at IS NULL OR terminal_reason = 'deleted' OR p_now >= terminal_at)
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'OAuth source transition refused' USING ERRCODE = '22023';
    END IF;
    UPDATE public.oauth_derived_token_sources SET terminal_reason = p_reason, terminal_at = p_now
    WHERE grant_ref = p_grant AND user_id = p_user
      AND (terminal_at IS NULL OR (p_reason = 'deleted' AND terminal_reason <> 'deleted' AND p_now >= terminal_at));
END;
$body$
-- statement
CREATE OR REPLACE FUNCTION newapi_oauth_source.reserve_source(
    p_user bigint, p_grant text, p_proof bigint, p_quota bigint, p_expiry bigint,
    p_policy text, p_binding text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
DECLARE v_now bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed'
       OR p_user IS NULL OR p_user <= 0 OR p_proof IS NULL OR p_proof NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION 'OAuth source reservation refused' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM public.users WHERE id = p_user FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'OAuth source reservation refused' USING ERRCODE = '22023';
    END IF;
    v_now := floor(extract(epoch FROM clock_timestamp()));
    INSERT INTO public.oauth_derived_token_sources
        (grant_ref, user_id, schema_version, quota_limit, expires_at, policy_hash, binding_hash,
         verified_at, proof_expires_at, permit_deadline, verified_method, proof_flow_id,
         token_id, key_ref, idem_hash, request_hash, created_at, terminal_at, terminal_reason)
    SELECT g.grant_ref, g.user_id, 1, p_quota, p_expiry, p_policy, p_binding,
           floor(extract(epoch FROM f.created_at)), floor(extract(epoch FROM f.expires_at)),
           least(floor(extract(epoch FROM f.created_at)) + 60, floor(extract(epoch FROM f.expires_at))),
           f.payload::jsonb ->> 'method', f.id, NULL, NULL, NULL, NULL, NULL, NULL, NULL
    FROM public.oauth_grants g
    JOIN public.auth_flows f ON f.id = p_proof AND f.user_id = g.user_id AND f.session_id = g.origin_sid
    JOIN public.users u ON u.id = g.user_id AND u.auth_version = g.user_auth_version
    JOIN public.user_sessions s ON s.sid = g.origin_sid AND s.user_id = g.user_id
    WHERE g.grant_ref = p_grant AND g.user_id = p_user AND g.state IN ('approved', 'active') AND g.revoked_at = 0
      AND u.status = 1 AND u.deleted_at IS NULL AND s.status = 'active' AND s.revoked_at = 0 AND s.expires_at >= g.expires_at
      AND s.version = g.session_version AND s.user_auth_version = g.user_auth_version
      AND g.subject = p_user::text AND g.issuer <> '' AND g.client_id <> ''
      AND g.session_version > 0 AND g.user_auth_version > 0
      AND g.approved_at BETWEEN g.created_at AND v_now AND g.revision >= 2
      AND jsonb_typeof(g.scopes::jsonb) = 'array' AND g.scopes::jsonb @> '["tokens:write"]'::jsonb
      AND g.scopes::jsonb <@ '["openid","profile","email","offline_access","balance:read","usage:read","tokens:read","tokens:write"]'::jsonb
      AND p_grant ~ '^[0-9a-f]{64}$' AND p_policy ~ '^[0-9a-f]{64}$' AND p_binding ~ '^[0-9a-f]{64}$'
      AND p_quota BETWEEN 1 AND 10000000 AND p_expiry BETWEEN v_now + 300 AND v_now + 604800 AND p_expiry <= g.expires_at
      AND f.purpose = 'security_proof' AND f.consumed_at IS NOT NULL AND f.consumed_at >= f.created_at AND f.consumed_at <= clock_timestamp()
      AND floor(extract(epoch FROM f.created_at)) <= g.created_at
      AND v_now < least(floor(extract(epoch FROM f.created_at)) + 60, floor(extract(epoch FROM f.expires_at)))
      AND f.payload::jsonb ->> 'scope' = 'oauth.derived_token.issue'
      AND f.payload::jsonb ->> 'context_hash' = p_binding
      AND f.payload::jsonb ->> 'grant_ref' = p_grant
      AND jsonb_typeof(f.payload::jsonb -> 'session_version') = 'number'
      AND jsonb_typeof(f.payload::jsonb -> 'user_auth_version') = 'number'
      AND jsonb_typeof(f.payload::jsonb -> 'quota_limit') = 'number'
      AND jsonb_typeof(f.payload::jsonb -> 'expires_at') = 'number'
      AND f.payload::jsonb ->> 'grant_policy_hash' = g.policy_hash
      AND f.payload::jsonb ->> 'session_version' = g.session_version::text
      AND f.payload::jsonb ->> 'user_auth_version' = g.user_auth_version::text
      AND f.payload::jsonb ->> 'policy_hash' = p_policy
      AND f.payload::jsonb ->> 'quota_limit' = p_quota::text
      AND f.payload::jsonb ->> 'expires_at' = p_expiry::text
      AND f.payload::jsonb ->> 'method' IN ('password', '2fa', 'passkey');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'OAuth source reservation refused' USING ERRCODE = '22023';
    END IF;
END;
$body$
-- statement
REVOKE ALL ON FUNCTION newapi_oauth_source.lock_sources(bigint, text),
    newapi_oauth_source.terminal_source(bigint, text, text, bigint),
    newapi_oauth_source.reserve_source(bigint, text, bigint, bigint, bigint, text, text) FROM PUBLIC
