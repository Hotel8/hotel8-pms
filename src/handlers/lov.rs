// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! List of Values (LOV) handlers - reference data management.
use crate::auth;
use crate::handlers::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use hotel8::pms::contracts::{LovCreateRequest, LovEntryList, LovEntryView, LovList, LovRow};
use sqlx::Row;
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/lov",
    responses(
        (status = 200, description = "LOV catalog entries for the property", body = LovList),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn list_lov(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<LovList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, lov_type, lov_code, lov_value, is_active, sort_order FROM pms.lov WHERE property_id = $1 ORDER BY lov_type, sort_order")
        .bind(property_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<LovRow> = rows
        .iter()
        .map(|r| LovRow {
            id: r.get::<uuid::Uuid, _>("id"),
            lov_type: r.get::<String, _>("lov_type"),
            lov_code: r.get::<String, _>("lov_code"),
            lov_value: r.get::<String, _>("lov_value"),
            is_active: r.get::<bool, _>("is_active"),
            sort_order: r.get::<i32, _>("sort_order"),
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(LovList { items }))
}
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/lov",
    request_body = LovCreateRequest,
    responses(
        (status = 200, description = "Created LOV entry", body = LovRow),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn create_lov(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<LovCreateRequest>,
) -> Result<Json<LovRow>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:admin"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let row = sqlx::query("INSERT INTO pms.lov (property_id, lov_type, lov_code, lov_value, is_active, sort_order) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, lov_type, lov_code, lov_value, is_active, sort_order")
        .bind(property_id)
        .bind(&req.lov_type)
        .bind(&req.lov_code)
        .bind(&req.lov_value)
        .bind(req.is_active)
        .bind(req.sort_order)
        .fetch_one(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let id: uuid::Uuid = row.get("id");
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:lov:created",
        serde_json::json!({ "lov_id": id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(LovRow {
        id,
        lov_type: row.get::<String, _>("lov_type"),
        lov_code: row.get::<String, _>("lov_code"),
        lov_value: row.get::<String, _>("lov_value"),
        is_active: row.get::<bool, _>("is_active"),
        sort_order: row.get::<i32, _>("sort_order"),
    }))
}
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/lov/{lov_type}",
    responses(
        (status = 200, description = "Active LOV entries of the given type", body = LovEntryList),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn list_lov_by_type(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, lov_type)): Path<(uuid::Uuid, String)>,
) -> Result<Json<LovEntryList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, lov_code, lov_value, is_active FROM pms.lov WHERE property_id = $1 AND lov_type = $2 AND is_active = true ORDER BY sort_order")
        .bind(property_id)
        .bind(&lov_type)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<LovEntryView> = rows
        .iter()
        .map(|r| LovEntryView {
            id: r.get::<uuid::Uuid, _>("id"),
            lov_code: r.get::<String, _>("lov_code"),
            lov_value: r.get::<String, _>("lov_value"),
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(LovEntryList { items }))
}
