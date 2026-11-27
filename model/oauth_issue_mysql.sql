CREATE PROCEDURE @database@.newapi_oauth_reserve_attested_source(IN p_user BIGINT, IN p_grant VARCHAR(64))
SQL SECURITY DEFINER
BEGIN
    DECLARE v_now BIGINT;
    DECLARE v_user BIGINT DEFAULT NULL;
    SELECT id INTO v_user FROM @database@.users WHERE id = p_user FOR UPDATE;
    IF v_user IS NULL THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = 'OAuth source reservation refused';
    END IF;
    SET v_now = floor(UNIX_TIMESTAMP(SYSDATE(6)));
    INSERT INTO @database@.oauth_derived_token_sources
        (grant_ref, user_id, schema_version, quota_limit, expires_at, policy_hash, binding_hash,
         verified_at, proof_expires_at, permit_deadline, verified_method, proof_flow_id,
         token_id, key_ref, idem_hash, request_hash, created_at, terminal_at, terminal_reason)
    SELECT a.grant_ref, a.user_id, 1, a.quota_limit, a.expires_at, a.policy_hash, a.binding_hash,
           a.verified_at, a.proof_expires_at, least(a.verified_at + 60, a.proof_expires_at),
           a.verified_method, a.proof_flow_id, NULL, NULL, NULL, NULL, NULL, NULL, NULL
    FROM @database@.oauth_derived_issue_attestations a
    JOIN @database@.oauth_grants g ON g.grant_ref = a.grant_ref AND BINARY g.consent_ref = BINARY a.consent_ref
    JOIN @database@.users u ON u.id = a.user_id AND u.auth_version = a.user_auth_version
    JOIN @database@.user_sessions s ON s.sid = a.origin_sid AND BINARY s.sid = BINARY a.origin_sid AND s.user_id = a.user_id
    WHERE a.grant_ref = p_grant AND BINARY a.grant_ref = BINARY p_grant AND a.user_id = p_user AND g.user_id = a.user_id
      AND BINARY g.subject = BINARY CAST(p_user AS CHAR) AND BINARY g.origin_s_id = BINARY a.origin_sid
      AND g.session_version = a.session_version AND g.user_auth_version = a.user_auth_version
      AND BINARY g.issuer = BINARY a.issuer AND BINARY g.client_id = BINARY a.client_id
      AND BINARY g.policy_hash = BINARY a.policy_hash AND BINARY g.scopes = BINARY a.scopes
      AND BINARY g.state = 'approved' AND g.revoked_at = 0 AND u.status = 1 AND u.deleted_at IS NULL
      AND BINARY s.status = 'active' AND s.revoked_at = 0 AND s.version = a.session_version
      AND s.user_auth_version = a.user_auth_version AND s.expires_at >= g.expires_at
      AND a.verified_at <= g.created_at AND g.approved_at BETWEEN g.created_at AND v_now
      AND v_now < least(a.verified_at + 60, a.proof_expires_at)
      AND a.expires_at > v_now AND a.expires_at <= g.expires_at;
    IF ROW_COUNT() <> 1 THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = 'OAuth source reservation refused';
    END IF;
END
