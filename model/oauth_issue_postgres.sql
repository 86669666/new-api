CREATE OR REPLACE FUNCTION newapi_oauth_source.reserve_attested_source(p_user bigint, p_grant text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
DECLARE v_now bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'OAuth source reservation refused' USING ERRCODE = '22023';
    END IF;
    -- All writers use the same user barrier, including a direct routine caller.
    PERFORM 1 FROM public.users WHERE id = p_user FOR UPDATE;
    v_now := floor(extract(epoch FROM clock_timestamp()));
    INSERT INTO public.oauth_derived_token_sources
        (grant_ref, user_id, schema_version, quota_limit, expires_at, policy_hash, binding_hash,
         verified_at, proof_expires_at, permit_deadline, verified_method, proof_flow_id,
         token_id, key_ref, idem_hash, request_hash, created_at, terminal_at, terminal_reason)
    SELECT a.grant_ref, a.user_id, 1, a.quota_limit, a.expires_at, a.policy_hash, a.binding_hash,
           a.verified_at, a.proof_expires_at, least(a.verified_at + 60, a.proof_expires_at),
           a.verified_method, a.proof_flow_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL
    FROM public.oauth_derived_issue_attestations a
    JOIN public.oauth_grants g ON g.grant_ref = a.grant_ref AND g.consent_ref = a.consent_ref
    JOIN public.users u ON u.id = a.user_id AND u.auth_version = a.user_auth_version
    JOIN public.user_sessions s ON s.sid = a.origin_sid AND s.user_id = a.user_id
    WHERE a.grant_ref = p_grant AND a.user_id = p_user AND g.user_id = a.user_id
      AND g.subject = p_user::text AND g.origin_s_id = a.origin_sid
      AND g.session_version = a.session_version AND g.user_auth_version = a.user_auth_version
      AND g.issuer = a.issuer AND g.client_id = a.client_id AND g.policy_hash = a.policy_hash AND g.scopes = a.scopes
      AND g.state = 'approved' AND g.revoked_at = 0 AND u.status = 1 AND u.deleted_at IS NULL
      AND s.status = 'active' AND s.revoked_at = 0 AND s.version = a.session_version
      AND s.user_auth_version = a.user_auth_version AND s.expires_at >= g.expires_at
      AND a.verified_at <= g.created_at AND g.approved_at BETWEEN g.created_at AND v_now
      AND v_now < least(a.verified_at + 60, a.proof_expires_at)
      AND a.expires_at > v_now AND a.expires_at <= g.expires_at;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'OAuth source reservation refused' USING ERRCODE = '22023';
    END IF;
END;
$body$
