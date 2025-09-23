USE NS app DB dashboard;

-- Extend user schema
DEFINE FIELD name ON TABLE user TYPE option<string>;
DEFINE FIELD avatar ON TABLE user TYPE option<string>;
DEFINE FIELD preferences ON TABLE user TYPE option<object>;
DEFINE FIELD status ON TABLE user TYPE string DEFAULT "active";
DEFINE FIELD deleted_at ON TABLE user TYPE option<datetime>;
DEFINE FIELD totp_secret ON TABLE user TYPE option<string>;
DEFINE FIELD totp_enabled ON TABLE user TYPE bool DEFAULT false;
DEFINE FIELD backup_codes ON TABLE user TYPE option<array>;
DEFINE FIELD email_verified ON TABLE user TYPE bool DEFAULT false;
DEFINE FIELD last_login_at ON TABLE user TYPE option<datetime>;
DEFINE FIELD profile_updated_at ON TABLE user TYPE option<datetime>;

-- Roles
DEFINE TABLE role SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin"
    FOR create WHERE $auth.role = "admin"
    FOR update WHERE $auth.role = "admin"
    FOR delete WHERE $auth.role = "admin";
DEFINE FIELD name ON TABLE role TYPE string;
DEFINE FIELD description ON TABLE role TYPE option<string>;
DEFINE FIELD permissions ON TABLE role TYPE array<string>;
DEFINE FIELD created_at ON TABLE role TYPE datetime VALUE time::now();
DEFINE FIELD updated_at ON TABLE role TYPE datetime VALUE time::now();
DEFINE INDEX idx_role_name ON TABLE role COLUMNS name UNIQUE;

-- Organizations
DEFINE TABLE organization SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin" OR array::contains(members, $auth.id)
    FOR create WHERE $auth.role = "admin" OR true
    FOR update WHERE $auth.role = "admin"
    FOR delete WHERE $auth.role = "admin";
DEFINE FIELD name ON TABLE organization TYPE string;
DEFINE FIELD owner_id ON TABLE organization TYPE string;
DEFINE FIELD members ON TABLE organization TYPE array<string> DEFAULT [];
DEFINE FIELD created_at ON TABLE organization TYPE datetime VALUE time::now();
DEFINE FIELD updated_at ON TABLE organization TYPE datetime VALUE time::now();

-- Teams
DEFINE TABLE team SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin" OR $auth.id = owner_id
    FOR create WHERE $auth.role = "admin" OR true
    FOR update WHERE $auth.role = "admin" OR $auth.id = owner_id
    FOR delete WHERE $auth.role = "admin" OR $auth.id = owner_id;
DEFINE FIELD name ON TABLE team TYPE string;
DEFINE FIELD description ON TABLE team TYPE option<string>;
DEFINE FIELD owner_id ON TABLE team TYPE string;
DEFINE FIELD org_id ON TABLE team TYPE option<string>;
DEFINE FIELD created_at ON TABLE team TYPE datetime VALUE time::now();
DEFINE FIELD updated_at ON TABLE team TYPE datetime VALUE time::now();

DEFINE TABLE team_member SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR create WHERE $auth.role = "admin"
    FOR update WHERE $auth.role = "admin"
    FOR delete WHERE $auth.role = "admin" OR $auth.id = user_id;
DEFINE FIELD team_id ON TABLE team_member TYPE string;
DEFINE FIELD user_id ON TABLE team_member TYPE string;
DEFINE FIELD role ON TABLE team_member TYPE string;
DEFINE FIELD added_at ON TABLE team_member TYPE datetime VALUE time::now();
DEFINE INDEX idx_team_member_unique ON TABLE team_member COLUMNS team_id, user_id UNIQUE;

-- Projects
DEFINE TABLE project SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin" OR $auth.id = owner_id
    FOR create WHERE $auth.role = "admin" OR true
    FOR update WHERE $auth.role = "admin" OR $auth.id = owner_id
    FOR delete WHERE $auth.role = "admin" OR $auth.id = owner_id;
DEFINE FIELD name ON TABLE project TYPE string;
DEFINE FIELD description ON TABLE project TYPE option<string>;
DEFINE FIELD status ON TABLE project TYPE string DEFAULT "active";
DEFINE FIELD org_id ON TABLE project TYPE option<string>;
DEFINE FIELD owner_id ON TABLE project TYPE string;
DEFINE FIELD settings ON TABLE project TYPE option<object>;
DEFINE FIELD created_at ON TABLE project TYPE datetime VALUE time::now();
DEFINE FIELD updated_at ON TABLE project TYPE datetime VALUE time::now();
DEFINE FIELD archived_at ON TABLE project TYPE option<datetime>;
DEFINE INDEX idx_project_name ON TABLE project COLUMNS name;

-- Tasks
DEFINE TABLE task SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin" OR $auth.id = owner_id
    FOR create WHERE $auth.role = "admin" OR true
    FOR update WHERE $auth.role = "admin" OR $auth.id = owner_id
    FOR delete WHERE $auth.role = "admin" OR $auth.id = owner_id;
DEFINE FIELD title ON TABLE task TYPE string;
DEFINE FIELD description ON TABLE task TYPE option<string>;
DEFINE FIELD status ON TABLE task TYPE string DEFAULT "open";
DEFINE FIELD project_id ON TABLE task TYPE string;
DEFINE FIELD owner_id ON TABLE task TYPE string;
DEFINE FIELD metadata ON TABLE task TYPE option<object>;
DEFINE FIELD created_at ON TABLE task TYPE datetime VALUE time::now();
DEFINE FIELD updated_at ON TABLE task TYPE datetime VALUE time::now();

DEFINE TABLE task_assignment SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR create WHERE $auth.role = "admin"
    FOR update WHERE $auth.role = "admin"
    FOR delete WHERE $auth.role = "admin" OR $auth.id = user_id;
DEFINE FIELD task_id ON TABLE task_assignment TYPE string;
DEFINE FIELD user_id ON TABLE task_assignment TYPE string;
DEFINE FIELD added_at ON TABLE task_assignment TYPE datetime VALUE time::now();
DEFINE INDEX idx_task_assignment_unique ON TABLE task_assignment COLUMNS task_id, user_id UNIQUE;

-- Audit logs
DEFINE TABLE audit_log SCHEMALESS
  PERMISSIONS
    FOR select WHERE $auth.role = "admin"
    FOR create WHERE true;
DEFINE INDEX idx_audit_resource ON TABLE audit_log COLUMNS resource_type, resource_id;

-- Notifications
DEFINE TABLE notification SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR create WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR update WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR delete WHERE $auth.role = "admin" OR $auth.id = user_id;
DEFINE FIELD user_id ON TABLE notification TYPE string;
DEFINE FIELD subject ON TABLE notification TYPE string;
DEFINE FIELD body ON TABLE notification TYPE option<string>;
DEFINE FIELD read ON TABLE notification TYPE bool DEFAULT false;
DEFINE FIELD read_at ON TABLE notification TYPE option<datetime>;
DEFINE FIELD created_at ON TABLE notification TYPE datetime VALUE time::now();

-- API keys
DEFINE TABLE api_key SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR create WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR update WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR delete WHERE $auth.role = "admin" OR $auth.id = user_id;
DEFINE FIELD user_id ON TABLE api_key TYPE string;
DEFINE FIELD name ON TABLE api_key TYPE string;
DEFINE FIELD token_prefix ON TABLE api_key TYPE string;
DEFINE FIELD token_hash ON TABLE api_key TYPE string;
DEFINE FIELD scopes ON TABLE api_key TYPE option<array<string>>;
DEFINE FIELD created_at ON TABLE api_key TYPE datetime VALUE time::now();
DEFINE FIELD last_used_at ON TABLE api_key TYPE option<datetime>;
DEFINE FIELD expires_at ON TABLE api_key TYPE option<datetime>;
DEFINE FIELD revoked ON TABLE api_key TYPE bool DEFAULT false;
DEFINE INDEX idx_api_key_prefix ON TABLE api_key COLUMNS token_prefix UNIQUE;

-- Webhooks
DEFINE TABLE webhook SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin" OR $auth.id = owner_id
    FOR create WHERE $auth.role = "admin" OR $auth.id = owner_id
    FOR update WHERE $auth.role = "admin" OR $auth.id = owner_id
    FOR delete WHERE $auth.role = "admin" OR $auth.id = owner_id;
DEFINE FIELD owner_id ON TABLE webhook TYPE string;
DEFINE FIELD org_id ON TABLE webhook TYPE option<string>;
DEFINE FIELD name ON TABLE webhook TYPE string;
DEFINE FIELD url ON TABLE webhook TYPE string;
DEFINE FIELD events ON TABLE webhook TYPE array<string>;
DEFINE FIELD secret ON TABLE webhook TYPE string;
DEFINE FIELD active ON TABLE webhook TYPE bool DEFAULT true;
DEFINE FIELD created_at ON TABLE webhook TYPE datetime VALUE time::now();
DEFINE FIELD updated_at ON TABLE webhook TYPE datetime VALUE time::now();

-- Files
DEFINE TABLE file_asset SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin" OR $auth.id = owner_id
    FOR create WHERE $auth.role = "admin" OR $auth.id = owner_id
    FOR update WHERE $auth.role = "admin" OR $auth.id = owner_id
    FOR delete WHERE $auth.role = "admin" OR $auth.id = owner_id;
DEFINE FIELD owner_id ON TABLE file_asset TYPE string;
DEFINE FIELD filename ON TABLE file_asset TYPE string;
DEFINE FIELD content_type ON TABLE file_asset TYPE option<string>;
DEFINE FIELD size ON TABLE file_asset TYPE int;
DEFINE FIELD path ON TABLE file_asset TYPE string;
DEFINE FIELD metadata ON TABLE file_asset TYPE option<object>;
DEFINE FIELD created_at ON TABLE file_asset TYPE datetime VALUE time::now();

-- Refresh tokens
DEFINE TABLE refresh_token SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR create WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR update WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR delete WHERE $auth.role = "admin" OR $auth.id = user_id;
DEFINE FIELD user_id ON TABLE refresh_token TYPE string;
DEFINE FIELD session_id ON TABLE refresh_token TYPE string;
DEFINE FIELD token_hash ON TABLE refresh_token TYPE string;
DEFINE FIELD active ON TABLE refresh_token TYPE bool DEFAULT true;
DEFINE FIELD created_at ON TABLE refresh_token TYPE datetime VALUE time::now();
DEFINE FIELD expires_at ON TABLE refresh_token TYPE datetime;
DEFINE FIELD rotated_at ON TABLE refresh_token TYPE option<datetime>;
DEFINE INDEX idx_refresh_token_hash ON TABLE refresh_token COLUMNS token_hash;

-- Password reset tokens
DEFINE TABLE password_reset SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin"
    FOR create WHERE true
    FOR update WHERE true
    FOR delete WHERE true;
DEFINE FIELD user_id ON TABLE password_reset TYPE string;
DEFINE FIELD token_hash ON TABLE password_reset TYPE string;
DEFINE FIELD expires_at ON TABLE password_reset TYPE datetime;
DEFINE FIELD used ON TABLE password_reset TYPE bool DEFAULT false;
DEFINE FIELD created_at ON TABLE password_reset TYPE datetime VALUE time::now();
DEFINE INDEX idx_password_reset_token ON TABLE password_reset COLUMNS token_hash;

-- Email verification codes
DEFINE TABLE email_verification SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin"
    FOR create WHERE true
    FOR update WHERE true
    FOR delete WHERE true;
DEFINE FIELD user_id ON TABLE email_verification TYPE string;
DEFINE FIELD code_hash ON TABLE email_verification TYPE string;
DEFINE FIELD expires_at ON TABLE email_verification TYPE datetime;
DEFINE FIELD used ON TABLE email_verification TYPE bool DEFAULT false;
DEFINE FIELD created_at ON TABLE email_verification TYPE datetime VALUE time::now();
DEFINE INDEX idx_email_verification_code ON TABLE email_verification COLUMNS code_hash;

-- Sessions
DEFINE TABLE session SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR create WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR update WHERE $auth.role = "admin" OR $auth.id = user_id
    FOR delete WHERE $auth.role = "admin" OR $auth.id = user_id;
DEFINE FIELD user_id ON TABLE session TYPE string;
DEFINE FIELD user_agent ON TABLE session TYPE option<string>;
DEFINE FIELD ip_address ON TABLE session TYPE option<string>;
DEFINE FIELD created_at ON TABLE session TYPE datetime VALUE time::now();
DEFINE FIELD last_seen_at ON TABLE session TYPE datetime VALUE time::now();
DEFINE FIELD revoked ON TABLE session TYPE bool DEFAULT false;
DEFINE INDEX idx_session_user ON TABLE session COLUMNS user_id;

-- Invitations
DEFINE TABLE invite SCHEMAFULL
  PERMISSIONS
    FOR select WHERE $auth.role = "admin"
    FOR create WHERE $auth.role = "admin"
    FOR update WHERE $auth.role = "admin"
    FOR delete WHERE $auth.role = "admin";
DEFINE FIELD email ON TABLE invite TYPE string;
DEFINE FIELD invited_by ON TABLE invite TYPE string;
DEFINE FIELD token_hash ON TABLE invite TYPE string;
DEFINE FIELD status ON TABLE invite TYPE string DEFAULT "pending";
DEFINE FIELD created_at ON TABLE invite TYPE datetime VALUE time::now();
DEFINE INDEX idx_invite_email ON TABLE invite COLUMNS email;

-- Search helper index for tasks
DEFINE INDEX idx_task_title ON TABLE task COLUMNS title;

