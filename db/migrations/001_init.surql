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

DEFINE INDEX idx_user_email_norm ON TABLE user COLUMNS email_norm UNIQUE;

-- Trigger-ish: keep updated_at current
DEFINE EVENT user_touch ON TABLE user WHEN $event = "UPDATE" THEN {
  UPDATE $after SET updated_at = time::now();
};
