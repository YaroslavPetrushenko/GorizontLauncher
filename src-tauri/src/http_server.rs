use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

use crate::auth::{login_user, register_user, DbPool};
use crate::ActiveAccountState;

#[derive(Clone)]
pub struct ApiState {
    pub pool: DbPool,
    pub active: ActiveAccountState,
}

#[derive(Deserialize)]
pub struct VerifyPasswordRequest {
    pub nickname: String,
    pub password: String,
    pub device_fp: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub nickname: String,
    pub password: String,
    pub device_fp: String,
}

#[derive(Serialize)]
pub struct VerifyPasswordResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct CheckPlayerQuery {
    pub nickname: String,
}

/// Answer the Bukkit plugin's silent check: is this nickname signed in inside the launcher?
/// Always HTTP 200, so the plugin never fails on a "false" answer.
#[derive(Serialize)]
pub struct CheckPlayerResponse {
    pub authorized: bool,
    pub nickname: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

async fn verify_password_handler(
    State(state): State<ApiState>,
    Json(request): Json<VerifyPasswordRequest>,
) -> Result<Json<VerifyPasswordResponse>, (StatusCode, Json<VerifyPasswordResponse>)> {
    match login_user(&state.pool, &request.nickname, &request.password, true, &request.device_fp).await {
        Ok(auth_response) => {
            crate::remember_active_account(&state.active, &auth_response);
            Ok(Json(VerifyPasswordResponse {
                success: true,
                access_token: Some(auth_response.access_token),
                refresh_token: Some(auth_response.refresh_token),
                error: None,
            }))
        }
        Err(e) => Ok(Json(VerifyPasswordResponse {
            success: false,
            access_token: None,
            refresh_token: None,
            error: Some(e),
        })),
    }
}

async fn register(
    State(state): State<ApiState>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<VerifyPasswordResponse>, (StatusCode, Json<VerifyPasswordResponse>)> {
    match register_user(&state.pool, &request.nickname, &request.password, &request.device_fp).await {
        Ok(auth_response) => {
            crate::remember_active_account(&state.active, &auth_response);
            Ok(Json(VerifyPasswordResponse {
                success: true,
                access_token: Some(auth_response.access_token),
                refresh_token: Some(auth_response.refresh_token),
                error: None,
            }))
        }
        Err(e) => Ok(Json(VerifyPasswordResponse {
            success: false,
            access_token: None,
            refresh_token: None,
            error: Some(e),
        })),
    }
}

async fn check_player(
    State(state): State<ApiState>,
    Query(query): Query<CheckPlayerQuery>,
) -> Json<CheckPlayerResponse> {
    let nickname = query.nickname.trim().to_string();
    if nickname.is_empty() {
        return Json(CheckPlayerResponse {
            authorized: false,
            nickname,
            reason: Some("nickname is required".into()),
        });
    }
    let guard = state.active.read().unwrap_or_else(|e| e.into_inner());
    let response = match guard.as_ref() {
        Some(active) if active.nickname.eq_ignore_ascii_case(&nickname) => {
            let now = chrono::Utc::now().timestamp();
            if active.expires_at > now {
                CheckPlayerResponse { authorized: true, nickname, reason: None }
            } else {
                CheckPlayerResponse { authorized: false, nickname, reason: Some("launcher session expired".into()) }
            }
        }
        Some(_) => CheckPlayerResponse {
            authorized: false,
            nickname,
            reason: Some("another account is signed in inside the launcher".into()),
        },
        None => CheckPlayerResponse {
            authorized: false,
            nickname,
            reason: Some("nobody is signed in inside the launcher".into()),
        },
    };
    Json(response)
}

async fn health() -> &'static str {
    "OK"
}

pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/check-player", get(check_player))
        .route("/auth/verify-password", post(verify_password_handler))
        .route("/auth/register", post(register))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
        .with_state(state)
}

pub async fn start_http_server(pool: DbPool, active: ActiveAccountState, port: u16) -> Result<(), String> {
    let app = create_router(ApiState { pool, active });
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = TcpListener::bind(addr).await
        .map_err(|e| format!("Не удалось занять порт {port} для API лаунчера: {e}"))?;

    eprintln!("[HTTP] Launcher API listening on {} (plugin endpoint: /auth/check-player)", addr);

    axum::serve(listener, app).await
        .map_err(|e| format!("HTTP server error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::{Arc, RwLock};
    use tower::ServiceExt;

    fn state_with(account: Option<crate::ActiveAccount>) -> ApiState {
        // A lazily connected pool is enough: these tests never touch the database.
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_lazy("sqlite://:memory:")
            .expect("lazy sqlite pool");
        ApiState {
            pool: Arc::new(pool),
            active: Arc::new(RwLock::new(account)),
        }
    }

    async fn body_json(app: Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let response = app.oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap()).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 8192).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, value)
    }

    #[tokio::test]
    async fn check_player_authorizes_matching_account() {
        let account = crate::ActiveAccount { nickname: "Ogonick".into(), user_id: "1".into(), expires_at: chrono::Utc::now().timestamp() + 600 };
        let (status, body) = body_json(create_router(state_with(Some(account))), "/auth/check-player?nickname=ogonick").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["authorized"], serde_json::json!(true));
        assert_eq!(body["nickname"], serde_json::json!("ogonick"));
    }

    #[tokio::test]
    async fn check_player_rejects_other_account_with_http_200() {
        let account = crate::ActiveAccount { nickname: "Ogonick".into(), user_id: "1".into(), expires_at: chrono::Utc::now().timestamp() + 600 };
        let (status, body) = body_json(create_router(state_with(Some(account))), "/auth/check-player?nickname=Cheater").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["authorized"], serde_json::json!(false));
        assert!(body["reason"].as_str().unwrap_or_default().contains("another account"));
    }

    #[tokio::test]
    async fn check_player_rejects_when_nobody_signed_in() {
        let (status, body) = body_json(create_router(state_with(None)), "/auth/check-player?nickname=Ogonick").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["authorized"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn check_player_rejects_expired_session() {
        let account = crate::ActiveAccount { nickname: "Ogonick".into(), user_id: "1".into(), expires_at: chrono::Utc::now().timestamp() - 10 };
        let (status, body) = body_json(create_router(state_with(Some(account))), "/auth/check-player?nickname=Ogonick").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["authorized"], serde_json::json!(false));
        assert!(body["reason"].as_str().unwrap_or_default().contains("expired"));
    }

    #[tokio::test]
    async fn health_endpoint_is_ok() {
        let response = create_router(state_with(None))
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
