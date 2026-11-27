CREATE PROCEDURE @database@.newapi_oauth_lock_sources(IN p_user BIGINT, IN p_grant VARCHAR(64))
SQL SECURITY DEFINER
BEGIN
    SELECT s.* FROM @database@.oauth_derived_token_sources s
    WHERE s.user_id = p_user AND (p_grant = '' OR (s.grant_ref = p_grant AND BINARY s.grant_ref = BINARY p_grant))
    ORDER BY s.grant_ref FOR UPDATE;
END
-- statement
CREATE PROCEDURE @database@.newapi_oauth_terminal_source(
    IN p_user BIGINT, IN p_grant VARCHAR(64), IN p_reason VARCHAR(32), IN p_now BIGINT
)
SQL SECURITY DEFINER
BEGIN
    DECLARE v_ref VARCHAR(64) DEFAULT NULL;
    IF p_reason IS NULL OR BINARY p_reason NOT IN ('disabled', 'deleted', 'revoked')
       OR p_now IS NULL OR p_now <= 0 OR p_now > UNIX_TIMESTAMP() THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = 'OAuth source transition refused';
    END IF;
    SELECT grant_ref INTO v_ref FROM @database@.oauth_derived_token_sources
    WHERE grant_ref = p_grant AND BINARY grant_ref = BINARY p_grant AND user_id = p_user
      AND p_now >= coalesce(created_at, verified_at)
      AND (p_reason <> 'deleted' OR terminal_at IS NULL OR terminal_reason = 'deleted' OR p_now >= terminal_at)
    FOR UPDATE;
    IF v_ref IS NULL THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = 'OAuth source transition refused';
    END IF;
    UPDATE @database@.oauth_derived_token_sources SET terminal_reason = p_reason, terminal_at = p_now
    WHERE grant_ref = p_grant AND BINARY grant_ref = BINARY p_grant AND user_id = p_user
      AND (terminal_at IS NULL OR (p_reason = 'deleted' AND terminal_reason <> 'deleted' AND p_now >= terminal_at));
END
-- statement
CREATE PROCEDURE @database@.newapi_oauth_reserve_source(
    IN p_user BIGINT, IN p_grant VARCHAR(64), IN p_proof BIGINT, IN p_quota BIGINT,
    IN p_expiry BIGINT, IN p_policy VARCHAR(64), IN p_binding VARCHAR(64)
)
SQL SECURITY DEFINER
BEGIN
    DECLARE v_user BIGINT DEFAULT NULL;
    DECLARE v_now BIGINT;
    DECLARE v_sid VARCHAR(64);
    DECLARE v_locked_ref VARCHAR(64);
    DECLARE v_proof BIGINT;
    DECLARE v_verified BIGINT;
    DECLARE v_proof_expiry BIGINT;
    DECLARE v_method VARCHAR(16);
    IF p_user IS NULL OR p_user <= 0 OR p_proof IS NULL OR p_proof NOT BETWEEN 1 AND 9007199254740991 THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = 'OAuth source reservation refused';
    END IF;
    SELECT id INTO v_user FROM @database@.users WHERE id = p_user FOR UPDATE;
    IF v_user IS NULL THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = 'OAuth source reservation refused';
    END IF;
    SELECT sid INTO v_sid FROM @database@.user_sessions
    WHERE sid = (SELECT origin_sid FROM @database@.oauth_grants WHERE grant_ref = p_grant AND user_id = p_user)
      AND user_id = p_user FOR UPDATE;
    SELECT grant_ref INTO v_locked_ref FROM @database@.oauth_grants
    WHERE grant_ref = p_grant AND user_id = p_user AND BINARY origin_sid = BINARY v_sid FOR UPDATE;
    SELECT id INTO v_proof FROM @database@.auth_flows
    WHERE id = p_proof AND user_id = p_user AND BINARY session_id = BINARY v_sid FOR UPDATE;
    IF v_locked_ref IS NULL OR v_proof IS NULL THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = 'OAuth source reservation refused';
    END IF;
    SET v_now = FLOOR(UNIX_TIMESTAMP(SYSDATE(6)));
    SELECT floor(UNIX_TIMESTAMP(f.created_at)), floor(UNIX_TIMESTAMP(f.expires_at)),
           JSON_UNQUOTE(JSON_EXTRACT(f.payload, '$.method'))
    INTO v_verified, v_proof_expiry, v_method
    FROM @database@.oauth_grants g
    JOIN @database@.auth_flows f ON f.id = p_proof AND f.user_id = g.user_id AND BINARY f.session_id = BINARY g.origin_sid
    JOIN @database@.users u ON u.id = g.user_id AND u.auth_version = g.user_auth_version
    JOIN @database@.user_sessions s ON BINARY s.sid = BINARY g.origin_sid AND s.user_id = g.user_id
    WHERE g.grant_ref = p_grant AND BINARY g.grant_ref = BINARY p_grant AND g.user_id = p_user AND BINARY g.state IN ('approved', 'active') AND g.revoked_at = 0
      AND u.status = 1 AND u.deleted_at IS NULL AND BINARY s.status = 'active' AND s.revoked_at = 0 AND s.expires_at >= g.expires_at
      AND s.version = g.session_version AND s.user_auth_version = g.user_auth_version
      AND BINARY g.subject = BINARY CAST(p_user AS CHAR) AND g.issuer <> '' AND g.client_id <> ''
      AND g.session_version > 0 AND g.user_auth_version > 0
      AND g.approved_at BETWEEN g.created_at AND v_now AND g.revision >= 2
      AND JSON_TYPE(g.scopes) = 'ARRAY' AND JSON_CONTAINS(g.scopes, '"tokens:write"')
      AND JSON_CONTAINS('["openid","profile","email","offline_access","balance:read","usage:read","tokens:read","tokens:write"]', g.scopes)
      AND LOWER(p_grant) = BINARY p_grant AND p_grant REGEXP '^[0-9a-f]{64}$'
      AND LOWER(p_policy) = BINARY p_policy AND p_policy REGEXP '^[0-9a-f]{64}$'
      AND LOWER(p_binding) = BINARY p_binding AND p_binding REGEXP '^[0-9a-f]{64}$'
      AND p_quota BETWEEN 1 AND 10000000 AND p_expiry BETWEEN v_now + 300 AND v_now + 604800 AND p_expiry <= g.expires_at
      AND BINARY f.purpose = 'security_proof' AND f.consumed_at IS NOT NULL AND f.consumed_at >= f.created_at AND f.consumed_at <= SYSDATE(6)
      AND floor(UNIX_TIMESTAMP(f.created_at)) <= g.created_at
      AND v_now < least(floor(UNIX_TIMESTAMP(f.created_at)) + 60, floor(UNIX_TIMESTAMP(f.expires_at)))
      AND BINARY JSON_UNQUOTE(JSON_EXTRACT(f.payload, '$.scope')) = 'oauth.derived_token.issue'
      AND BINARY JSON_UNQUOTE(JSON_EXTRACT(f.payload, '$.context_hash')) = BINARY p_binding
      AND BINARY JSON_UNQUOTE(JSON_EXTRACT(f.payload, '$.grant_ref')) = BINARY p_grant
      AND JSON_TYPE(JSON_EXTRACT(f.payload, '$.session_version')) = 'INTEGER'
      AND JSON_TYPE(JSON_EXTRACT(f.payload, '$.user_auth_version')) = 'INTEGER'
      AND JSON_TYPE(JSON_EXTRACT(f.payload, '$.quota_limit')) = 'INTEGER'
      AND JSON_TYPE(JSON_EXTRACT(f.payload, '$.expires_at')) = 'INTEGER'
      AND BINARY JSON_UNQUOTE(JSON_EXTRACT(f.payload, '$.grant_policy_hash')) = BINARY g.policy_hash
      AND BINARY JSON_UNQUOTE(JSON_EXTRACT(f.payload, '$.session_version')) = BINARY CAST(g.session_version AS CHAR)
      AND BINARY JSON_UNQUOTE(JSON_EXTRACT(f.payload, '$.user_auth_version')) = BINARY CAST(g.user_auth_version AS CHAR)
      AND BINARY JSON_UNQUOTE(JSON_EXTRACT(f.payload, '$.policy_hash')) = BINARY p_policy
      AND BINARY JSON_UNQUOTE(JSON_EXTRACT(f.payload, '$.quota_limit')) = BINARY CAST(p_quota AS CHAR)
      AND BINARY JSON_UNQUOTE(JSON_EXTRACT(f.payload, '$.expires_at')) = BINARY CAST(p_expiry AS CHAR)
      AND BINARY JSON_UNQUOTE(JSON_EXTRACT(f.payload, '$.method')) IN ('password', '2fa', 'passkey')
    FOR UPDATE;
    IF v_verified IS NULL THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = 'OAuth source reservation refused';
    END IF;
    INSERT INTO @database@.oauth_derived_token_sources
        (grant_ref, user_id, schema_version, quota_limit, expires_at, policy_hash, binding_hash,
         verified_at, proof_expires_at, permit_deadline, verified_method, proof_flow_id,
         token_id, key_ref, idem_hash, request_hash, created_at, terminal_at, terminal_reason)
    VALUES (p_grant, p_user, 1, p_quota, p_expiry, p_policy, p_binding, v_verified, v_proof_expiry,
            least(v_verified + 60, v_proof_expiry), v_method, p_proof, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
END
