CREATE PROCEDURE @database@.newapi_oauth_lock_issue_grant(IN p_user BIGINT, IN p_grant VARCHAR(64))
SQL SECURITY DEFINER
BEGIN
    DECLARE v_user BIGINT DEFAULT NULL;
    DECLARE v_sid VARCHAR(64) DEFAULT NULL;
    DECLARE v_session VARCHAR(64) DEFAULT NULL;
    DECLARE v_grant VARCHAR(64) DEFAULT NULL;
    SELECT id INTO v_user FROM @database@.users WHERE id = p_user FOR UPDATE;
    SELECT origin_s_id INTO v_sid FROM @database@.oauth_grants
    WHERE grant_ref = p_grant AND BINARY grant_ref = BINARY p_grant AND user_id = p_user;
    SELECT sid INTO v_session FROM @database@.user_sessions
    WHERE sid = v_sid AND BINARY sid = BINARY v_sid AND user_id = p_user FOR UPDATE;
    SELECT grant_ref INTO v_grant FROM @database@.oauth_grants
    WHERE grant_ref = p_grant AND BINARY grant_ref = BINARY p_grant AND user_id = p_user
      AND BINARY origin_s_id = BINARY v_session FOR UPDATE;
    IF v_user IS NULL OR v_grant IS NULL THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = 'OAuth key issuance refused';
    END IF;
END
-- statement
CREATE PROCEDURE @database@.newapi_oauth_complete_issue(
    IN p_user BIGINT, IN p_grant VARCHAR(64), IN p_token BIGINT, IN p_key_ref VARCHAR(64), IN p_idem VARCHAR(64),
    IN p_request VARCHAR(64), IN p_bearer_expiry BIGINT
)
SQL SECURITY DEFINER
BEGIN
    DECLARE v_now BIGINT;
    DECLARE v_source VARCHAR(64);
    DECLARE v_token BIGINT;
    CALL @database@.newapi_oauth_lock_issue_grant(p_user, p_grant);
    SELECT grant_ref INTO v_source FROM @database@.oauth_derived_token_sources
    WHERE grant_ref = p_grant AND BINARY grant_ref = BINARY p_grant AND user_id = p_user FOR UPDATE;
    SELECT id INTO v_token FROM @database@.tokens WHERE id = p_token AND user_id = p_user FOR UPDATE;
    SET v_now = floor(UNIX_TIMESTAMP(SYSDATE(6)));
    UPDATE @database@.oauth_derived_token_sources s
    JOIN @database@.tokens t ON t.id = v_token AND t.user_id = s.user_id
    JOIN @database@.oauth_grants g ON g.grant_ref = s.grant_ref AND g.user_id = s.user_id
    JOIN @database@.users u ON u.id = s.user_id AND u.auth_version = g.user_auth_version
    JOIN @database@.user_sessions us ON us.sid = g.origin_s_id AND BINARY us.sid = BINARY g.origin_s_id AND us.user_id = s.user_id
    SET s.token_id = p_token, s.key_ref = p_key_ref, s.idem_hash = p_idem, s.request_hash = p_request, s.created_at = t.created_time
    WHERE s.grant_ref = v_source AND BINARY s.grant_ref = BINARY v_source AND s.user_id = p_user
      AND s.token_id IS NULL AND s.key_ref IS NULL AND s.idem_hash IS NULL AND s.request_hash IS NULL
      AND s.created_at IS NULL AND s.terminal_at IS NULL AND s.terminal_reason IS NULL
      AND p_key_ref REGEXP '^[0-9a-f]{64}$' AND p_idem REGEXP '^[0-9a-f]{64}$' AND p_request REGEXP '^[0-9a-f]{64}$'
      AND p_bearer_expiry IS NOT NULL AND v_now < least(s.permit_deadline, s.expires_at, p_bearer_expiry, g.expires_at, us.expires_at)
      AND t.deleted_at IS NULL AND t.status = 1 AND NOT t.unlimited_quota
      AND t.used_quota = 0 AND t.remain_quota = s.quota_limit AND t.expired_time = s.expires_at
      AND t.created_time BETWEEN s.verified_at AND v_now
      AND BINARY g.policy_hash = BINARY s.policy_hash AND BINARY g.state = 'active' AND g.revoked_at = 0
      AND u.status = 1 AND u.deleted_at IS NULL AND BINARY us.status = 'active' AND us.revoked_at = 0
      AND us.version = g.session_version AND us.user_auth_version = g.user_auth_version;
    IF ROW_COUNT() <> 1 THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = 'OAuth key issuance refused';
    END IF;
END
