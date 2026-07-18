use crate::control_plane::models::{ErrorEnvelope, LoginRequest};
use crate::control_plane::{audit, repository, AppState};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|x| x.to_string())
        .map_err(|e| e.to_string())
}
pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .ok()
        .map(|p| {
            Argon2::default()
                .verify_password(password.as_bytes(), &p)
                .is_ok()
        })
        .unwrap_or(false)
}
pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
pub async fn login(
    State(state): State<AppState>,
    Json(input): Json<LoginRequest>,
) -> impl IntoResponse {
    let found = repository::find_user(&state.db, &input.email)
        .await
        .ok()
        .flatten();
    if let Some((user, hash)) = found {
        if verify_password(&input.password, &hash) {
            let token = Uuid::new_v4().to_string();
            let exp = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
            if repository::create_session(&state.db, user.id, &token_hash(&token), &exp)
                .await
                .is_ok()
            {
                audit::record(&state.db, Some(user.id), "login_success", "session_created").await;
                let mut h = HeaderMap::new();
                h.insert(header::SET_COOKIE,format!("bearust_session={token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400").parse().unwrap());
                return (h, Json(user)).into_response();
            }
        }
    }
    audit::record(&state.db, None, "login_failed", "invalid_credentials").await;
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorEnvelope {
            code: "invalid_credentials".into(),
            message: "Invalid email or password".into(),
        }),
    )
        .into_response()
}
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(t) = cookie(&headers) {
        let _ = repository::revoke_session(&state.db, &token_hash(t)).await;
        audit::record(&state.db, None, "logout", "session_revoked").await;
    }
    StatusCode::NO_CONTENT
}
pub fn cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|v| v.trim().strip_prefix("bearust_session="))
}
