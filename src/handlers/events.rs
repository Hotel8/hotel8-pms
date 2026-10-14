// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Events handlers.
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sqlx::Row;
use crate::handlers::AppState;
use crate::auth;

pub async fn create_event(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:event:write")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let event_code = format!("EVT-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    let row = sqlx::query("INSERT INTO pms.events (property_id, event_code, event_name, event_type, start_date, end_date, status, expected_attendees, banquet_order, contact_name, contact_phone, notes)
         VALUES ($1, $2, $3, $4, $5::date, $6::date, 'TENTATIVE', $7, $8, $9, $10, $11) RETURNING id, event_code, event_name, status")
        .bind(property_id)
        .bind(&event_code)
        .bind(req.get("event_name").and_then(|v| v.as_str()).unwrap_or(""))
        .bind(req.get("event_type").and_then(|v| v.as_str()).unwrap_or("MEETING"))
        .bind(req.get("start_date").and_then(|v| v.as_str()))
        .bind(req.get("end_date").and_then(|v| v.as_str()))
        .bind(req.get("expected_attendees").and_then(|v| v.as_u64()).unwrap_or(0) as i32)
        .bind(req.get("banquet_order").and_then(|v| v.as_str()))
        .bind(req.get("contact_name").and_then(|v| v.as_str()))
        .bind(req.get("contact_phone").and_then(|v| v.as_str()))
        .bind(req.get("notes").and_then(|v| v.as_str()))
        .fetch_one(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let event_id: uuid::Uuid = row.get("id");
    let status: String = row.get("status");
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:event:created", serde_json::json!({ "event_id": event_id, "event_code": &event_code }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "id": event_id, "event_code": event_code, "status": status })))
}

pub async fn list_events(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:event:read")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, event_code, event_name, event_type, start_date, end_date, status, expected_attendees FROM pms.events WHERE property_id = $1 ORDER BY start_date DESC")
        .bind(property_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows.iter().map(|r| {
        let status: String = r.get("status");
        serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id"),
            "event_code": r.get::<String, _>("event_code"),
            "event_name": r.get::<String, _>("event_name"),
            "event_type": r.get::<String, _>("event_type"),
            "start_date": r.get::<chrono::NaiveDate, _>("start_date"),
            "end_date": r.get::<chrono::NaiveDate, _>("end_date"),
            "status": status,
            "expected_attendees": r.get::<i32, _>("expected_attendees"),
        })
    }).collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}