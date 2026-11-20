use sqlx::{Pool, Sqlite, sqlite::SqlitePoolOptions};
use std::sync::Arc;
use tauri::Manager;

pub type DbPool = Arc<Pool<Sqlite>>;

pub async fn init_db(app_handle: &tauri::AppHandle) -> Result<DbPool, String> {
    let data_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to get app data dir: {}", e))?;
    
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("Failed to create data dir: {}", e))?;
    
    let db_path = data_dir.join("auth.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
    
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .map_err(|e| format!("Failed to connect to database: {}", e))?;
    
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            nickname TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("Failed to create users table: {}", e))?;
    
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            refresh_token_hash TEXT NOT NULL,
            device_fp TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("Failed to create user_sessions table: {}", e))?;
    
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS oauth_accounts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            access_token_enc TEXT,
            refresh_token_enc TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(provider, provider_user_id)
        )
        "#,
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("Failed to create oauth_accounts table: {}", e))?;
    
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id)
        "#,
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("Failed to create index: {}", e))?;
    
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_user_sessions_refresh_token_hash ON user_sessions(refresh_token_hash)
        "#,
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("Failed to create index: {}", e))?;
    
    Ok(Arc::new(pool))
}