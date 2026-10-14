// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! List of Values (LOV) handlers — reference data management.
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sqlx::Row;
use crate::handlers::AppState;
use crate::auth;

pub async fn list_lov(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:read")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, lov_type, lov_code, lov_value, is_active, sort_order FROM pms.lov WHERE property_id = $1 ORDER BY lov_type, sort_order")
        .bind(property_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "id": r.get::<uuid::Uuid, _>("id"),
        "lov_type": r.get::<String, _>("lov_type"),
        "lov_code": r.get::<String, _>("lov_code"),
        "lov_value": r.get::<String, _>("lov_value"),
        "is_active": r.get::<bool, _>("is_active"),
        "sort_order": r.get::<i32, _>("sort_order"),
    })).collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

pub async fn create_lov(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:admin")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let row = sqlx::query("INSERT INTO pms.lov (property_id, lov_type, lov_code, lov_value, is_active, sort_order) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, lov_type, lov_code, lov_value, is_active, sort_order")
        .bind(property_id)
        .bind(req.get("lov_type").and_then(|v| v.as_str()).unwrap_or(""))
        .bind(req.get("lov_code").and_then(|v| v.as_str()).unwrap_or(""))
        .bind(req.get("lov_value").and_then(|v| v.as_str()).unwrap_or(""))
        .bind(req.get("is_active").and_then(|v| v.as_bool()).unwrap_or(true))
        .bind(req.get("sort_order").and_then(|v| v.as_u64()).unwrap_or(0) as i32)
        .fetch_one(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let id: uuid::Uuid = row.get("id");
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:lov:created", serde_json::json!({ "lov_id": id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "id": id,
        "lov_type": row.get::<String, _>("lov_type"),
        "lov_code": row.get::<String, _>("lov_code"),
        "lov_value": row.get::<String, _>("lov_value"),
        "is_active": row.get::<bool, _>("is_active"),
        "sort_order": row.get::<i32, _>("sort_order"),
    })))
}

pub async fn list_lov_by_type(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, lov_type)): Path<(uuid::Uuid, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:read")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, lov_code, lov_value, is_active FROM pms.lov WHERE property_id = $1 AND lov_type = $2 AND is_active = true ORDER BY sort_order")
        .bind(property_id)
        .bind(&lov_type)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "id": r.get::<uuid::Uuid, _>("id"),
        "lov_code": r.get::<String, _>("lov_code"),
        "lov_value": r.get::<String, _>("lov_value"),
    })).collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}