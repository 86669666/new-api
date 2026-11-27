CREATE OR REPLACE FUNCTION newapi_oauth_source.lock_issue_grant(p_user bigint, p_grant text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
DECLARE v_sid text;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'OAuth key issuance refused' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM public.users WHERE id = p_user FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'OAuth key issuance refused' USING ERRCODE = '22023';
    END IF;
    SELECT origin_s_id INTO v_sid FROM public.oauth_grants WHERE grant_ref = p_grant AND user_id = p_user;
    PERFORM 1 FROM public.user_sessions WHERE sid = v_sid AND user_id = p_user FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'OAuth key issuance refused' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM public.oauth_grants WHERE grant_ref = p_grant AND user_id = p_user AND origin_s_id = v_sid FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'OAuth key issuance refused' USING ERRCODE = '22023';
    END IF;
END;
$body$
-- statement
CREATE OR REPLACE FUNCTION newapi_oauth_source.complete_issue(
    p_user bigint, p_grant text, p_token bigint, p_key_ref text, p_idem text, p_request text, p_bearer_expiry bigint
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
DECLARE v_now bigint;
BEGIN
    PERFORM newapi_oauth_source.lock_issue_grant(p_user, p_grant);
    PERFORM 1 FROM public.oauth_derived_token_sources WHERE grant_ref = p_grant AND user_id = p_user FOR UPDATE;
    PERFORM 1 FROM public.tokens WHERE id = p_token AND user_id = p_user FOR UPDATE;
    v_now := floor(extract(epoch FROM clock_timestamp()));
    UPDATE public.oauth_derived_token_sources s
    SET token_id = p_token, key_ref = p_key_ref, idem_hash = p_idem, request_hash = p_request, created_at = t.created_time
    FROM public.tokens t, public.oauth_grants g, public.users u, public.user_sessions us
    WHERE s.grant_ref = p_grant AND s.user_id = p_user AND s.token_id IS NULL AND s.key_ref IS NULL
      AND s.idem_hash IS NULL AND s.request_hash IS NULL AND s.created_at IS NULL AND s.terminal_at IS NULL AND s.terminal_reason IS NULL
      AND p_key_ref ~ '^[0-9a-f]{64}$' AND p_idem ~ '^[0-9a-f]{64}$' AND p_request ~ '^[0-9a-f]{64}$'
      AND p_bearer_expiry IS NOT NULL AND v_now < least(s.permit_deadline, s.expires_at, p_bearer_expiry, g.expires_at, us.expires_at)
      AND t.id = p_token AND t.user_id = p_user AND t.deleted_at IS NULL AND t.status = 1
      AND NOT t.unlimited_quota AND t.used_quota = 0 AND t.remain_quota = s.quota_limit AND t.expired_time = s.expires_at
      AND t.created_time BETWEEN s.verified_at AND v_now
      AND g.grant_ref = s.grant_ref AND g.user_id = s.user_id AND g.policy_hash = s.policy_hash
      AND g.state = 'active' AND g.revoked_at = 0 AND u.id = p_user AND u.status = 1 AND u.deleted_at IS NULL
      AND u.auth_version = g.user_auth_version AND us.sid = g.origin_s_id AND us.user_id = p_user
      AND us.status = 'active' AND us.revoked_at = 0
      AND us.version = g.session_version AND us.user_auth_version = g.user_auth_version;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'OAuth key issuance refused' USING ERRCODE = '22023';
    END IF;
END;
$body$
