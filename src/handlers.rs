// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! PMS HTTP handlers — re-exports from sub-modules.
pub mod admin_data;
pub mod availability;
pub mod back_office;
pub mod blocks;
pub mod cashiering;
pub mod events;
pub mod front_desk;
pub mod graphql;
pub mod guest_surfaces;
pub mod housekeeping;
pub mod integration;
pub mod lov;
pub mod profiles;
pub mod properties;
pub mod rate_plans;
pub mod reservations;
pub mod rooms;
pub mod staff_corporate;

use crate::config::H8pmsConfig;
use sentin8::auth::client::AuthContext;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<H8pmsConfig>,
    pub pool: sqlx::PgPool,
    /// M2M-backed Bus client built at startup via DCR (RFC 7591).
    pub bus_client: sentin8::bus::client::BusClient,
    /// Shield policy engine: step 5 is the ONLY gate —
    /// handlers verify the token (steps 1–4) then evaluate a
    /// `hotel8:pms:<resource>:<action>` target; no JWT scope check remains.
    pub policy: Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface — same engine
    /// instance the request path evaluates.
    pub admin: sentin8::shield::admin::SharedAdminState,
}

/// Set the RLS tenant context on a connection (transaction-local).
pub async fn set_tenant_context(conn: &mut sqlx::PgConnection, env_id: uuid::Uuid) {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(conn)
        .await;
}

/// Extended tenant context — admin flags + Auth user UUID for holder-scoped RLS.
pub async fn set_tenant_context_ext(
    conn: &mut sqlx::PgConnection,
    env_id: uuid::Uuid,
    auth: &AuthContext,
) {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, $2, $3, $4, $5, false, $6, $7)")
        .bind(env_id)
        .bind(&auth.claims.sub)
        .bind(&auth.claims.token_tp)
        .bind(&auth.claims.scope)
        .bind(auth.is_platform_admin())
        .bind(auth.claims.is_env_admin())
        .bind(auth.claims.sentin8_auth_user_uuid())
        .execute(conn)
        .await;
}

pub fn resolve_org_env(auth: &AuthContext) -> uuid::Uuid {
    // env_id is the sole tenant key (globally unique). org_id has been
    // removed from all hotel8 tables — RLS context is set via env_id alone.
    auth.env_id()
}

pub fn err_db(e: sqlx::Error) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Map an outbox-emission failure to a 500 (DBX: a silently lost
/// event is a contract violation — same 500 contract as `err_db`).
fn err_emit(e: sentin8::bus::outbox::OutboxError) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

pub fn err_not_found(msg: &str) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::NOT_FOUND, msg.to_string())
}

pub fn err_bad_request(msg: &str) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::BAD_REQUEST, msg.to_string())
}
#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn health(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "ok",
        "service": "pms",
        "version": sentin8::build_info::id(),
            "build": sentin8::build_info::build_hash(),
        "database": if state.pool.size() > 0 { "connected" } else { "disconnected" },
    }))
}
