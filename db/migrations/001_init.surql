-- Namespace & DB
DEFINE NAMESPACE IF NOT EXISTS app;
DEFINE DATABASE IF NOT EXISTS dashboard;
USE NS app DB dashboard;

-- Users table
DEFINE TABLE user SCHEMAFULL
  PERMISSIONS
    FOR select WHERE id = $auth.id OR $auth.role = "admin"
    FOR update WHERE id = $auth.id OR $auth.role = "admin"
    FOR create WHERE $auth.role = "admin" OR true
    FOR delete WHERE $auth.role = "admin";

DEFINE FIELD email         ON TABLE user TYPE string ASSERT string::is::email($value);
DEFINE FIELD email_norm    ON TABLE user TYPE string;
DEFINE FIELD password_hash ON TABLE user TYPE string;
DEFINE FIELD role          ON TABLE user TYPE string DEFAULT "user";
DEFINE FIELD created_at    ON TABLE user TYPE datetime VALUE time::now();
DEFINE FIELD updated_at    ON TABLE user TYPE datetime VALUE time::now();
DEFINE FIELD name          ON TABLE user TYPE option<string>;
DEFINE FIELD avatar_url    ON TABLE user TYPE option<string>;
DEFINE FIELD preferences   ON TABLE user TYPE object DEFAULT {};
DEFINE FIELD status        ON TABLE user TYPE string DEFAULT "active";
DEFINE FIELD deleted_at    ON TABLE user TYPE option<datetime>;
DEFINE FIELD totp_secret   ON TABLE user TYPE option<string>;
DEFINE FIELD pending_totp_secret ON TABLE user TYPE option<string>;
DEFINE FIELD totp_enabled  ON TABLE user TYPE bool DEFAULT false;
DEFINE FIELD totp_backup_codes ON TABLE user TYPE array DEFAULT [];
DEFINE FIELD email_verified ON TABLE user TYPE bool DEFAULT false;
DEFINE FIELD last_login_at ON TABLE user TYPE option<datetime>;
DEFINE FIELD org_roles     ON TABLE user TYPE array DEFAULT [];

DEFINE INDEX idx_user_email_norm ON TABLE user COLUMNS email_norm UNIQUE;

-- Trigger-ish: keep updated_at current
DEFINE EVENT user_touch ON TABLE user WHEN $event = "UPDATE" THEN {
  UPDATE $after SET updated_at = time::now();
};

-- Roles
DEFINE TABLE role SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin"
    FOR update WHERE $auth.role = "admin"
    FOR create WHERE $auth.role = "admin"
    FOR delete WHERE $auth.role = "admin";

DEFINE FIELD name        ON TABLE role TYPE string;
DEFINE FIELD permissions ON TABLE role TYPE array DEFAULT [];
DEFINE FIELD description ON TABLE role TYPE option<string>;
DEFINE FIELD created_at  ON TABLE role TYPE datetime VALUE time::now();
DEFINE FIELD updated_at  ON TABLE role TYPE datetime VALUE time::now();
DEFINE INDEX idx_role_name ON TABLE role COLUMNS name UNIQUE;
DEFINE EVENT role_touch ON TABLE role WHEN $event = "UPDATE" THEN {
  UPDATE $after SET updated_at = time::now();
};

-- Refresh tokens
DEFINE TABLE refresh_token SCHEMAFULL
  PERMISSIONS
    FOR select WHERE user = $auth.id OR $auth.role = "admin"
    FOR update WHERE user = $auth.id OR $auth.role = "admin"
    FOR create WHERE user = $auth.id OR $auth.role = "admin"
    FOR delete WHERE $auth.role = "admin";

DEFINE FIELD user        ON TABLE refresh_token TYPE string;
DEFINE FIELD session_id  ON TABLE refresh_token TYPE option<string>;
DEFINE FIELD token_hash  ON TABLE refresh_token TYPE string;
DEFINE FIELD expires_at  ON TABLE refresh_token TYPE datetime;
DEFINE FIELD created_at  ON TABLE refresh_token TYPE datetime VALUE time::now();
DEFINE FIELD rotated_at  ON TABLE refresh_token TYPE option<datetime>;
DEFINE FIELD revoked_at  ON TABLE refresh_token TYPE option<datetime>;
DEFINE INDEX idx_refresh_token_hash ON TABLE refresh_token COLUMNS token_hash UNIQUE;
DEFINE INDEX idx_refresh_user ON TABLE refresh_token COLUMNS user;

-- Password reset codes
DEFINE TABLE password_reset SCHEMAFULL
  PERMISSIONS
    FOR select WHERE user = $auth.id OR $auth.role = "admin"
    FOR update WHERE user = $auth.id OR $auth.role = "admin"
    FOR create WHERE true
    FOR delete WHERE $auth.role = "admin";

DEFINE FIELD user       ON TABLE password_reset TYPE string;
DEFINE FIELD code       ON TABLE password_reset TYPE string;
DEFINE FIELD expires_at ON TABLE password_reset TYPE datetime;
DEFINE FIELD used_at    ON TABLE password_reset TYPE option<datetime>;
DEFINE FIELD created_at ON TABLE password_reset TYPE datetime VALUE time::now();
DEFINE INDEX idx_password_reset_code ON TABLE password_reset COLUMNS code UNIQUE;

-- Email verification codes
DEFINE TABLE email_verification SCHEMAFULL
  PERMISSIONS
    FOR select WHERE user = $auth.id OR $auth.role = "admin"
    FOR update WHERE user = $auth.id OR $auth.role = "admin"
    FOR create WHERE true
    FOR delete WHERE $auth.role = "admin";

DEFINE FIELD user       ON TABLE email_verification TYPE string;
DEFINE FIELD code       ON TABLE email_verification TYPE string;
DEFINE FIELD expires_at ON TABLE email_verification TYPE datetime;
DEFINE FIELD verified_at ON TABLE email_verification TYPE option<datetime>;
DEFINE FIELD created_at ON TABLE email_verification TYPE datetime VALUE time::now();
DEFINE INDEX idx_email_verification_code ON TABLE email_verification COLUMNS code UNIQUE;

-- Sessions
DEFINE TABLE session SCHEMAFULL
  PERMISSIONS
    FOR select WHERE user = $auth.id OR $auth.role = "admin"
    FOR update WHERE user = $auth.id OR $auth.role = "admin"
    FOR create WHERE user = $auth.id OR $auth.role = "admin"
    FOR delete WHERE user = $auth.id OR $auth.role = "admin";

DEFINE FIELD user        ON TABLE session TYPE string;
DEFINE FIELD jti         ON TABLE session TYPE string;
DEFINE FIELD user_agent  ON TABLE session TYPE option<string>;
DEFINE FIELD ip          ON TABLE session TYPE option<string>;
DEFINE FIELD created_at  ON TABLE session TYPE datetime VALUE time::now();
DEFINE FIELD last_seen   ON TABLE session TYPE datetime VALUE time::now();
DEFINE FIELD revoked_at  ON TABLE session TYPE option<datetime>;
DEFINE INDEX idx_session_user ON TABLE session COLUMNS user;
DEFINE INDEX idx_session_jti ON TABLE session COLUMNS jti UNIQUE;

-- Organizations
DEFINE TABLE organization SCHEMAFULL
  PERMISSIONS
    FOR select WHERE owner = $auth.id OR $auth.role = "admin" OR array::contains(members, $auth.id)
    FOR update WHERE owner = $auth.id OR $auth.role = "admin"
    FOR create WHERE $auth.id != NONE
    FOR delete WHERE owner = $auth.id OR $auth.role = "admin";

DEFINE FIELD name        ON TABLE organization TYPE string;
DEFINE FIELD slug        ON TABLE organization TYPE string;
DEFINE FIELD owner       ON TABLE organization TYPE string;
DEFINE FIELD members     ON TABLE organization TYPE array DEFAULT [];
DEFINE FIELD created_at  ON TABLE organization TYPE datetime VALUE time::now();
DEFINE FIELD updated_at  ON TABLE organization TYPE datetime VALUE time::now();
DEFINE INDEX idx_org_slug ON TABLE organization COLUMNS slug UNIQUE;

DEFINE EVENT organization_touch ON TABLE organization WHEN $event = "UPDATE" THEN {
  UPDATE $after SET updated_at = time::now();
};

-- Teams
DEFINE TABLE team SCHEMAFULL
  PERMISSIONS
    FOR select WHERE created_by = $auth.id OR $auth.role = "admin"
    FOR update WHERE created_by = $auth.id OR $auth.role = "admin"
    FOR create WHERE $auth.id != NONE
    FOR delete WHERE created_by = $auth.id OR $auth.role = "admin";

DEFINE FIELD org         ON TABLE team TYPE string;
DEFINE FIELD name        ON TABLE team TYPE string;
DEFINE FIELD description ON TABLE team TYPE option<string>;
DEFINE FIELD created_by  ON TABLE team TYPE string;
DEFINE FIELD created_at  ON TABLE team TYPE datetime VALUE time::now();
DEFINE FIELD updated_at  ON TABLE team TYPE datetime VALUE time::now();
DEFINE EVENT team_touch ON TABLE team WHEN $event = "UPDATE" THEN {
  UPDATE $after SET updated_at = time::now();
};

DEFINE TABLE team_member SCHEMAFULL
  PERMISSIONS
    FOR select WHERE user = $auth.id OR $auth.role = "admin"
    FOR update WHERE user = $auth.id OR $auth.role = "admin"
    FOR create WHERE user = $auth.id OR $auth.role = "admin"
    FOR delete WHERE user = $auth.id OR $auth.role = "admin";

DEFINE FIELD team       ON TABLE team_member TYPE string;
DEFINE FIELD user       ON TABLE team_member TYPE string;
DEFINE FIELD role       ON TABLE team_member TYPE string DEFAULT "member";
DEFINE FIELD created_at ON TABLE team_member TYPE datetime VALUE time::now();
DEFINE INDEX idx_team_member_unique ON TABLE team_member COLUMNS team, user UNIQUE;

-- Projects
DEFINE TABLE project SCHEMAFULL
  PERMISSIONS
    FOR select WHERE created_by = $auth.id OR $auth.role = "admin"
    FOR update WHERE created_by = $auth.id OR $auth.role = "admin"
    FOR create WHERE $auth.id != NONE
    FOR delete WHERE created_by = $auth.id OR $auth.role = "admin";

DEFINE FIELD org         ON TABLE project TYPE option<string>;
DEFINE FIELD name        ON TABLE project TYPE string;
DEFINE FIELD description ON TABLE project TYPE option<string>;
DEFINE FIELD status      ON TABLE project TYPE string DEFAULT "active";
DEFINE FIELD metadata    ON TABLE project TYPE object DEFAULT {};
DEFINE FIELD created_by  ON TABLE project TYPE string;
DEFINE FIELD created_at  ON TABLE project TYPE datetime VALUE time::now();
DEFINE FIELD updated_at  ON TABLE project TYPE datetime VALUE time::now();
DEFINE FIELD archived_at ON TABLE project TYPE option<datetime>;
DEFINE EVENT project_touch ON TABLE project WHEN $event = "UPDATE" THEN {
  UPDATE $after SET updated_at = time::now();
};

DEFINE TABLE project_member SCHEMAFULL
  PERMISSIONS
    FOR select WHERE user = $auth.id OR $auth.role = "admin"
    FOR update WHERE $auth.role = "admin"
    FOR create WHERE $auth.id != NONE
    FOR delete WHERE $auth.id != NONE;

DEFINE FIELD project    ON TABLE project_member TYPE string;
DEFINE FIELD user       ON TABLE project_member TYPE string;
DEFINE FIELD role       ON TABLE project_member TYPE string DEFAULT "contributor";
DEFINE FIELD created_at ON TABLE project_member TYPE datetime VALUE time::now();
DEFINE INDEX idx_project_member_unique ON TABLE project_member COLUMNS project, user UNIQUE;

-- Audit log
DEFINE TABLE audit_log SCHEMALESS
  PERMISSIONS
    FOR select WHERE $auth.role = "admin"
    FOR create WHERE true
    FOR update WHERE false
    FOR delete WHERE false;

DEFINE FIELD actor      ON TABLE audit_log TYPE option<string>;
DEFINE FIELD event      ON TABLE audit_log TYPE string;
DEFINE FIELD entity     ON TABLE audit_log TYPE option<string>;
DEFINE FIELD metadata   ON TABLE audit_log TYPE object DEFAULT {};
DEFINE FIELD created_at ON TABLE audit_log TYPE datetime VALUE time::now();

-- Notifications
DEFINE TABLE notification SCHEMAFULL
  PERMISSIONS
    FOR select WHERE user = $auth.id OR $auth.role = "admin"
    FOR update WHERE user = $auth.id OR $auth.role = "admin"
    FOR create WHERE $auth.id != NONE
    FOR delete WHERE user = $auth.id OR $auth.role = "admin";

DEFINE FIELD user       ON TABLE notification TYPE string;
DEFINE FIELD title      ON TABLE notification TYPE string;
DEFINE FIELD body       ON TABLE notification TYPE string;
DEFINE FIELD level      ON TABLE notification TYPE string DEFAULT "info";
DEFINE FIELD read_at    ON TABLE notification TYPE option<datetime>;
DEFINE FIELD created_at ON TABLE notification TYPE datetime VALUE time::now();
DEFINE INDEX idx_notification_user ON TABLE notification COLUMNS user;

-- API Keys
DEFINE TABLE api_key SCHEMAFULL
  PERMISSIONS
    FOR select WHERE user = $auth.id OR $auth.role = "admin"
    FOR update WHERE user = $auth.id OR $auth.role = "admin"
    FOR create WHERE user = $auth.id OR $auth.role = "admin"
    FOR delete WHERE user = $auth.id OR $auth.role = "admin";

DEFINE FIELD user        ON TABLE api_key TYPE string;
DEFINE FIELD name        ON TABLE api_key TYPE string;
DEFINE FIELD token_hash  ON TABLE api_key TYPE string;
DEFINE FIELD scopes      ON TABLE api_key TYPE array DEFAULT [];
DEFINE FIELD expires_at  ON TABLE api_key TYPE option<datetime>;
DEFINE FIELD created_at  ON TABLE api_key TYPE datetime VALUE time::now();
DEFINE FIELD last_used_at ON TABLE api_key TYPE option<datetime>;
DEFINE FIELD rotated_at  ON TABLE api_key TYPE option<datetime>;
DEFINE FIELD revoked_at  ON TABLE api_key TYPE option<datetime>;
DEFINE INDEX idx_api_key_token_hash ON TABLE api_key COLUMNS token_hash UNIQUE;

-- Webhooks
DEFINE TABLE webhook SCHEMAFULL
  PERMISSIONS
    FOR select WHERE created_by = $auth.id OR $auth.role = "admin"
    FOR update WHERE created_by = $auth.id OR $auth.role = "admin"
    FOR create WHERE $auth.id != NONE
    FOR delete WHERE created_by = $auth.id OR $auth.role = "admin";

DEFINE FIELD created_by  ON TABLE webhook TYPE string;
DEFINE FIELD org         ON TABLE webhook TYPE option<string>;
DEFINE FIELD url         ON TABLE webhook TYPE string;
DEFINE FIELD events      ON TABLE webhook TYPE array DEFAULT [];
DEFINE FIELD secret      ON TABLE webhook TYPE option<string>;
DEFINE FIELD description ON TABLE webhook TYPE option<string>;
DEFINE FIELD created_at  ON TABLE webhook TYPE datetime VALUE time::now();
DEFINE FIELD updated_at  ON TABLE webhook TYPE datetime VALUE time::now();
DEFINE FIELD deleted_at  ON TABLE webhook TYPE option<datetime>;
DEFINE EVENT webhook_touch ON TABLE webhook WHEN $event = "UPDATE" THEN {
  UPDATE $after SET updated_at = time::now();
};

-- Files / Media
DEFINE TABLE file_asset SCHEMAFULL
  PERMISSIONS
    FOR select WHERE owner = $auth.id OR $auth.role = "admin"
    FOR update WHERE owner = $auth.id OR $auth.role = "admin"
    FOR create WHERE $auth.id != NONE
    FOR delete WHERE owner = $auth.id OR $auth.role = "admin";

DEFINE FIELD owner       ON TABLE file_asset TYPE string;
DEFINE FIELD filename    ON TABLE file_asset TYPE string;
DEFINE FIELD storage_key ON TABLE file_asset TYPE string;
DEFINE FIELD mime_type   ON TABLE file_asset TYPE string;
DEFINE FIELD size        ON TABLE file_asset TYPE number;
DEFINE FIELD checksum    ON TABLE file_asset TYPE option<string>;
DEFINE FIELD created_at  ON TABLE file_asset TYPE datetime VALUE time::now();

-- Tasks
DEFINE TABLE task SCHEMAFULL
  PERMISSIONS
    FOR select WHERE created_by = $auth.id OR $auth.role = "admin" OR array::contains(assignees, $auth.id)
    FOR update WHERE created_by = $auth.id OR $auth.role = "admin"
    FOR create WHERE $auth.id != NONE
    FOR delete WHERE created_by = $auth.id OR $auth.role = "admin";

DEFINE FIELD project     ON TABLE task TYPE option<string>;
DEFINE FIELD title       ON TABLE task TYPE string;
DEFINE FIELD description ON TABLE task TYPE option<string>;
DEFINE FIELD status      ON TABLE task TYPE string DEFAULT "open";
DEFINE FIELD assignees   ON TABLE task TYPE array DEFAULT [];
DEFINE FIELD created_by  ON TABLE task TYPE string;
DEFINE FIELD created_at  ON TABLE task TYPE datetime VALUE time::now();
DEFINE FIELD updated_at  ON TABLE task TYPE datetime VALUE time::now();
DEFINE FIELD due_at      ON TABLE task TYPE option<datetime>;
DEFINE EVENT task_touch ON TABLE task WHEN $event = "UPDATE" THEN {
  UPDATE $after SET updated_at = time::now();
};

-- User invites
DEFINE TABLE user_invite SCHEMAFULL
  PERMISSIONS
    FOR select WHERE invited_by = $auth.id OR $auth.role = "admin"
    FOR update WHERE invited_by = $auth.id OR $auth.role = "admin"
    FOR create WHERE $auth.role = "admin"
    FOR delete WHERE $auth.role = "admin";

DEFINE FIELD email      ON TABLE user_invite TYPE string;
DEFINE FIELD invite_code ON TABLE user_invite TYPE string;
DEFINE FIELD invited_by ON TABLE user_invite TYPE string;
DEFINE FIELD created_at ON TABLE user_invite TYPE datetime VALUE time::now();
DEFINE FIELD accepted_at ON TABLE user_invite TYPE option<datetime>;
DEFINE INDEX idx_user_invite_code ON TABLE user_invite COLUMNS invite_code UNIQUE;
