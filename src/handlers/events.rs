// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Events handlers.
use crate::auth;
use crate::handlers::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use hotel8::pms::contracts::{EventCreateRequest, EventCreated, EventSummary, EventSummaryList};
use sqlx::Row;

#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/events",
    request_body = EventCreateRequest,
    responses(
        (status = 200, description = "OK - event created in TENTATIVE state", body = EventCreated),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]
pub async fn create_event(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<EventCreateRequest>,
) -> Result<Json<EventCreated>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:event:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let event_code = format!("EVT-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    let row = sqlx::query("INSERT INTO pms.events (property_id, event_code, event_name, event_type, start_date, end_date, status, expected_attendees, banquet_order, contact_name, contact_phone, notes)
         VALUES ($1, $2, $3, $4, $5::date, $6::date, 'TENTATIVE', $7, $8, $9, $10, $11) RETURNING id, event_code, event_name, status")
        .bind(property_id)
        .bind(&event_code)
        .bind(&req.event_name)
        .bind(&req.event_type)
        .bind(req.start_date.as_deref())
        .bind(req.end_date.as_deref())
        .bind(req.expected_attendees)
        .bind(req.banquet_order.as_deref())
        .bind(req.contact_name.as_deref())
        .bind(req.contact_phone.as_deref())
        .bind(req.notes.as_deref())
        .fetch_one(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let event_id: uuid::Uuid = row.get("id");
    let status: String = row.get("status");
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:event:created",
        serde_json::json!({ "event_id": event_id, "event_code": &event_code }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(EventCreated {
        id: event_id,
        event_code,
        status,
    }))
}

#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/events",
    responses(
        (status = 200, description = "OK", body = EventSummaryList),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]
pub async fn list_events(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<EventSummaryList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:event:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, event_code, event_name, event_type, start_date, end_date, status, expected_attendees FROM pms.events WHERE property_id = $1 ORDER BY start_date DESC")
        .bind(property_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<EventSummary> = rows
        .iter()
        .map(|r| EventSummary {
            id: r.get::<uuid::Uuid, _>("id"),
            event_code: r.get::<String, _>("event_code"),
            event_name: r.get::<String, _>("event_name"),
            event_type: r.get::<String, _>("event_type"),
            start_date: r.get::<chrono::NaiveDate, _>("start_date"),
            end_date: r.get::<chrono::NaiveDate, _>("end_date"),
            status: r.get("status"),
            expected_attendees: r.get::<i32, _>("expected_attendees"),
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(EventSummaryList { items }))
}
