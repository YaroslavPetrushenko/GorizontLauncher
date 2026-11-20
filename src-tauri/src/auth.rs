use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite, Row};
use std::sync::Arc;
use uuid::Uuid;

pub type DbPool = Arc<Pool<Sqlite>>;

const ACCESS_TOKEN_TTL_MINUTES: i64 = 30;
const REFRESH_TOKEN_TTL_DAYS: i64 = 30;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,      // user_id
    pub nickname: String,
    pub exp: i64,
    pub iat: i64,
    pub typ: String,      // "access" or "refresh"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub nickname: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub nickname: String,
    pub password: String,
    pub remember: bool,
    pub device_fp: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub nickname: String,
    pub password: String,
    pub device_fp: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
    pub device_fp: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ForgotPasswordRequest {
    pub nickname: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthRequest {
    pub provider: String,
    pub code: String,
    pub device_fp: String,
}

/// Secret used to sign the launcher's own access/refresh tokens.
///
/// There is no default in the repository: a random secret is generated on first run
/// and stored in the launcher data folder next to the database. JWT_SECRET overrides
/// it for development and CI.
static JWT_SECRET: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn get_jwt_secret() -> String {
    JWT_SECRET.get_or_init(|| {
        let from_env = std::env::var("JWT_SECRET").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        match from_env {
            Some(value) => value,
            None => {
                let dir = crate::launcher_data_dir().unwrap_or_else(|_| std::env::temp_dir().join("GorizontLauncher"));
                let _ = std::fs::create_dir_all(&dir);
                let path = dir.join("jwt.key");
                match std::fs::read_to_string(&path) {
                    Ok(text) if text.trim().len() >= 32 => text.trim().to_string(),
                    _ => {
                        // Two UUIDv4 values = 244 random bits, plenty for HS256.
                        let generated = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
                        if let Err(e) = std::fs::write(&path, &generated) {
                            eprintln!("[AUTH] Could not persist jwt.key: {e}");
                        }
                        generated
                    }
                }
            }
        }
    }).clone()
}

fn encoding_key() -> EncodingKey {
    EncodingKey::from_secret(get_jwt_secret().as_bytes())
}

fn decoding_key() -> DecodingKey {
    DecodingKey::from_secret(get_jwt_secret().as_bytes())
}

fn create_token(user_id: &str, nickname: &str, typ: &str, ttl: Duration) -> Result<String, String> {
    let now = Utc::now();
    let exp = now + ttl;
    let claims = Claims {
        sub: user_id.to_string(),
        nickname: nickname.to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        typ: typ.to_string(),
    };
    encode(&Header::default(), &claims, &encoding_key())
        .map_err(|e| format!("Failed to create token: {}", e))
}

pub fn create_access_token(user_id: &str, nickname: &str) -> Result<String, String> {
    create_token(user_id, nickname, "access", Duration::minutes(ACCESS_TOKEN_TTL_MINUTES))
}

pub fn create_refresh_token(user_id: &str, nickname: &str) -> Result<String, String> {
    create_token(user_id, nickname, "refresh", Duration::days(REFRESH_TOKEN_TTL_DAYS))
}

pub fn decode_token(token: &str) -> Result<Claims, String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    decode::<Claims>(token, &decoding_key(), &validation)
        .map(|data| data.claims)
        .map_err(|e| format!("Invalid token: {}", e))
}

pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    URL_SAFE_NO_PAD.encode(result)
}

pub async fn hash_password(password: &str) -> Result<String, String> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash password: {}", e))?;
    Ok(hash.to_string())
}

pub async fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    let parsed_hash = PasswordHash::new(hash).map_err(|e| format!("Invalid hash format: {}", e))?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}

pub async fn register_user(
    pool: &DbPool,
    nickname: &str,
    password: &str,
    device_fp: &str,
) -> Result<AuthResponse, String> {
    let nickname = nickname.trim().to_string();
    
    if nickname.is_empty() || password.len() < 8 {
        return Err("Invalid input".to_string());
    }
    
    let existing = sqlx::query("SELECT id FROM users WHERE nickname = ?")
        .bind(&nickname)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| format!("DB error: {}", e))?;
    
    if existing.is_some() {
        return Err("Nickname already exists".to_string());
    }
    
    let password_hash = hash_password(password).await?;
    let user_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    
    sqlx::query(
        "INSERT INTO users (id, password_hash, nickname, created_at) VALUES (?, ?, ?, ?)"
    )
    .bind(&user_id)
    .bind(&password_hash)
    .bind(&nickname)
    .bind(&now)
    .execute(pool.as_ref())
    .await
    .map_err(|e| format!("Failed to create user: {}", e))?;
    
    let access_token = create_access_token(&user_id, &nickname)?;
    let refresh_token = create_refresh_token(&user_id, &nickname)?;
    let refresh_token_hash = hash_token(&refresh_token);
    let session_id = Uuid::new_v4().to_string();
    let expires_at = (Utc::now() + Duration::days(REFRESH_TOKEN_TTL_DAYS)).to_rfc3339();
    
    sqlx::query(
        "INSERT INTO user_sessions (id, user_id, refresh_token_hash, device_fp, expires_at, revoked, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)"
    )
    .bind(&session_id)
    .bind(&user_id)
    .bind(&refresh_token_hash)
    .bind(device_fp)
    .bind(&expires_at)
    .bind(&now)
    .execute(pool.as_ref())
    .await
    .map_err(|e| format!("Failed to create session: {}", e))?;
    
    Ok(AuthResponse {
        access_token,
        refresh_token,
        user: UserResponse {
            id: user_id,
            nickname,
            created_at: now,
        },
    })
}

pub async fn login_user(
    pool: &DbPool,
    nickname: &str,
    password: &str,
    remember: bool,
    device_fp: &str,
) -> Result<AuthResponse, String> {
    let nickname = nickname.trim().to_string();
    
    let row = sqlx::query("SELECT id, password_hash, nickname, created_at FROM users WHERE nickname = ?")
        .bind(&nickname)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| format!("DB error: {}", e))?;
    
    let row = row.ok_or("Invalid credentials")?;
    
    let user_id: String = row.get("id");
    let password_hash: String = row.get("password_hash");
    let nickname: String = row.get("nickname");
    let created_at: String = row.get("created_at");
    
    let valid = verify_password(password, &password_hash).await?;
    if !valid {
        return Err("Invalid credentials".to_string());
    }
    
    let access_token = create_access_token(&user_id, &nickname)?;
    let refresh_token = create_refresh_token(&user_id, &nickname)?;
    let refresh_token_hash = hash_token(&refresh_token);
    let session_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let ttl_days = if remember { REFRESH_TOKEN_TTL_DAYS } else { 1 };
    let expires_at = (Utc::now() + Duration::days(ttl_days)).to_rfc3339();
    
    sqlx::query(
        "INSERT INTO user_sessions (id, user_id, refresh_token_hash, device_fp, expires_at, revoked, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)"
    )
    .bind(&session_id)
    .bind(&user_id)
    .bind(&refresh_token_hash)
    .bind(device_fp)
    .bind(&expires_at)
    .bind(&now)
    .execute(pool.as_ref())
    .await
    .map_err(|e| format!("Failed to create session: {}", e))?;
    
    Ok(AuthResponse {
        access_token,
        refresh_token,
        user: UserResponse {
            id: user_id,
            nickname,
            created_at,
        },
    })
}

pub async fn refresh_tokens(
    pool: &DbPool,
    refresh_token: &str,
    device_fp: &str,
) -> Result<AuthResponse, String> {
    let claims = decode_token(refresh_token)?;
    
    if claims.typ != "refresh" {
        return Err("Invalid token type".to_string());
    }
    
    let refresh_token_hash = hash_token(refresh_token);
    
    let row = sqlx::query(
        "SELECT id, user_id, expires_at, revoked FROM user_sessions WHERE refresh_token_hash = ?"
    )
    .bind(&refresh_token_hash)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| format!("DB error: {}", e))?;
    
    let row = row.ok_or("Session not found")?;
    
    let revoked: i64 = row.get("revoked");
    if revoked != 0 {
        return Err("Session revoked".to_string());
    }
    
    let expires_at: String = row.get("expires_at");
    let expires = DateTime::parse_from_rfc3339(&expires_at)
        .map_err(|e| format!("Invalid expiry date: {}", e))?;
    
    if Utc::now() > expires {
        return Err("Session expired".to_string());
    }
    
    let user_id: String = row.get("user_id");
    
    let user_row = sqlx::query("SELECT id, nickname, created_at FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| format!("DB error: {}", e))?
        .ok_or("User not found")?;
    
    let nickname: String = user_row.get("nickname");
    let created_at: String = user_row.get("created_at");
    
    sqlx::query("UPDATE user_sessions SET revoked = 1 WHERE refresh_token_hash = ?")
        .bind(&refresh_token_hash)
        .execute(pool.as_ref())
        .await
        .map_err(|e| format!("Failed to revoke old session: {}", e))?;
    
    let access_token = create_access_token(&user_id, &nickname)?;
    let new_refresh_token = create_refresh_token(&user_id, &nickname)?;
    let new_refresh_token_hash = hash_token(&new_refresh_token);
    let session_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let new_expires_at = (Utc::now() + Duration::days(REFRESH_TOKEN_TTL_DAYS)).to_rfc3339();
    
    sqlx::query(
        "INSERT INTO user_sessions (id, user_id, refresh_token_hash, device_fp, expires_at, revoked, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)"
    )
    .bind(&session_id)
    .bind(&user_id)
    .bind(&new_refresh_token_hash)
    .bind(device_fp)
    .bind(&new_expires_at)
    .bind(&now)
    .execute(pool.as_ref())
    .await
    .map_err(|e| format!("Failed to create new session: {}", e))?;
    
    Ok(AuthResponse {
        access_token,
        refresh_token: new_refresh_token,
        user: UserResponse {
            id: user_id,
            nickname,
            created_at,
        },
    })
}

pub async fn logout_user(
    pool: &DbPool,
    refresh_token: &str,
) -> Result<(), String> {
    let refresh_token_hash = hash_token(refresh_token);
    
    sqlx::query("UPDATE user_sessions SET revoked = 1 WHERE refresh_token_hash = ?")
        .bind(&refresh_token_hash)
        .execute(pool.as_ref())
        .await
        .map_err(|e| format!("Failed to revoke session: {}", e))?;
    
    Ok(())
}

pub async fn get_user_profile(
    pool: &DbPool,
    access_token: &str,
) -> Result<UserResponse, String> {
    let claims = decode_token(access_token)?;
    
    if claims.typ != "access" {
        return Err("Invalid token type".to_string());
    }
    
    let row = sqlx::query("SELECT id, nickname, created_at FROM users WHERE id = ?")
        .bind(&claims.sub)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| format!("DB error: {}", e))?
        .ok_or("User not found")?;
    
    Ok(UserResponse {
        id: row.get("id"),
        nickname: row.get("nickname"),
        created_at: row.get("created_at"),
    })
}

pub async fn forgot_password(
    pool: &DbPool,
    nickname: &str,
) -> Result<(), String> {
    let nickname = nickname.trim().to_string();
    
    let _ = sqlx::query("SELECT id FROM users WHERE nickname = ?")
        .bind(&nickname)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| format!("DB error: {}", e))?;
    
    Ok(())
}

pub async fn oauth_login(
    pool: &DbPool,
    provider: &str,
    provider_user_id: &str,
    nickname: &str,
    access_token: Option<String>,
    refresh_token: Option<String>,
    device_fp: &str,
) -> Result<AuthResponse, String> {
    let nickname = nickname.trim().to_string();
    
    let oauth_row = sqlx::query(
        "SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_user_id = ?"
    )
    .bind(provider)
    .bind(provider_user_id)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| format!("DB error: {}", e))?;
    
    let user_id = if let Some(row) = oauth_row {
        let existing_user_id: String = row.get("user_id");
        
        sqlx::query(
            "UPDATE oauth_accounts SET access_token_enc = ?, refresh_token_enc = ?, expires_at = ? WHERE provider = ? AND provider_user_id = ?"
        )
        .bind(access_token.unwrap_or_default())
        .bind(refresh_token.unwrap_or_default())
        .bind(Utc::now().to_rfc3339())
        .bind(provider)
        .bind(provider_user_id)
        .execute(pool.as_ref())
        .await
        .map_err(|e| format!("Failed to update oauth account: {}", e))?;
        
        existing_user_id
    } else {
        let user_row = sqlx::query("SELECT id FROM users WHERE nickname = ?")
            .bind(&nickname)
            .fetch_optional(pool.as_ref())
            .await
            .map_err(|e| format!("DB error: {}", e))?;
        
        let user_id = if let Some(row) = user_row {
            let existing_user_id: String = row.get("id");
            
            sqlx::query(
                "UPDATE users SET nickname = ? WHERE id = ?"
            )
            .bind(&nickname)
            .bind(&existing_user_id)
            .execute(pool.as_ref())
            .await
            .map_err(|e| format!("Failed to update user: {}", e))?;
            
            sqlx::query(
                "INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&existing_user_id)
            .bind(provider)
            .bind(provider_user_id)
            .bind(access_token.unwrap_or_default())
            .bind(refresh_token.unwrap_or_default())
            .bind(Utc::now().to_rfc3339())
            .bind(Utc::now().to_rfc3339())
            .execute(pool.as_ref())
            .await
            .map_err(|e| format!("Failed to link oauth account: {}", e))?;
            
            existing_user_id
        } else {
            let new_user_id = Uuid::new_v4().to_string();
            let now = Utc::now().to_rfc3339();
            
            sqlx::query(
                "INSERT INTO users (id, password_hash, nickname, created_at) VALUES (?, '', ?, ?)"
            )
            .bind(&new_user_id)
            .bind(&nickname)
            .bind(&now)
            .execute(pool.as_ref())
            .await
            .map_err(|e| format!("Failed to create user: {}", e))?;
            
            sqlx::query(
                "INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&new_user_id)
            .bind(provider)
            .bind(provider_user_id)
            .bind(access_token.unwrap_or_default())
            .bind(refresh_token.unwrap_or_default())
            .bind(Utc::now().to_rfc3339())
            .bind(&now)
            .execute(pool.as_ref())
            .await
            .map_err(|e| format!("Failed to create oauth account: {}", e))?;
            
            new_user_id
        };
        
        user_id
    };
    
    let user_row = sqlx::query("SELECT id, nickname, created_at FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(pool.as_ref())
        .await
        .map_err(|e| format!("DB error: {}", e))?;
    
    let nickname: String = user_row.get("nickname");
    let created_at: String = user_row.get("created_at");
    
    let access_token = create_access_token(&user_id, &nickname)?;
    let refresh_token = create_refresh_token(&user_id, &nickname)?;
    let refresh_token_hash = hash_token(&refresh_token);
    let session_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let expires_at = (Utc::now() + Duration::days(REFRESH_TOKEN_TTL_DAYS)).to_rfc3339();
    
    sqlx::query(
        "INSERT INTO user_sessions (id, user_id, refresh_token_hash, device_fp, expires_at, revoked, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)"
    )
    .bind(&session_id)
    .bind(&user_id)
    .bind(&refresh_token_hash)
    .bind(device_fp)
    .bind(&expires_at)
    .bind(&now)
    .execute(pool.as_ref())
    .await
    .map_err(|e| format!("Failed to create session: {}", e))?;
    
    Ok(AuthResponse {
        access_token,
        refresh_token,
        user: UserResponse {
            id: user_id,
            nickname,
            created_at,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_secret_has_no_repository_default_and_is_stable() {
        let first = get_jwt_secret();
        assert!(first.len() >= 32, "secret must be long enough for HS256");
        assert_ne!(first, "gorizont-launcher-dev-secret-change-in-production");
        assert_eq!(first, get_jwt_secret(), "secret must stay stable inside one process");
    }

    #[test]
    fn access_token_round_trips_with_that_secret() {
        let token = create_access_token("user-1", "Ogonick").expect("token");
        let claims = decode_token(&token).expect("decode");
        assert_eq!(claims.nickname, "Ogonick");
        assert_eq!(claims.typ, "access");
    }
}
