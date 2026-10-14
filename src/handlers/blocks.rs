// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Blocks (allotments) and Events handlers.
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sqlx::Row;
use crate::handlers::AppState;
use crate::auth;
use crate::state_machine::{BlockState, PmsState};

// ── Blocks ──

pub async fn create_block(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:block:write")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let block_code = format!("BLK-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    let row = sqlx::query("INSERT INTO pms.blocks (property_id, block_code, block_name, room_type_id, start_date, end_date, blocked_rooms, released_until, status, block_type, negotiated_rate, cutoff_date)
         VALUES ($1, $2, $3, $4, $5::date, $6::date, $7, $8, 'PROVISIONAL', $9, $10::numeric, $11::date) RETURNING *")
        .bind(property_id)
        .bind(&block_code)
        .bind(req.get("block_name").and_then(|v| v.as_str()).unwrap_or(""))
        .bind(req.get("room_type_id").and_then(|v| v.as_str()).and_then(|s| uuid::Uuid::parse_str(s).ok()))
        .bind(req.get("start_date").and_then(|v| v.as_str()))
        .bind(req.get("end_date").and_then(|v| v.as_str()))
        .bind(req.get("blocked_rooms").and_then(|v| v.as_u64()).unwrap_or(0) as i32)
        .bind(req.get("released_until").and_then(|v| v.as_str()).unwrap_or("0"))
        .bind(req.get("block_type").and_then(|v| v.as_str()).unwrap_or("ALLOTMENT"))
        .bind(req.get("negotiated_rate").and_then(|v| v.as_str()))
        .bind(req.get("cutoff_date").and_then(|v| v.as_str()))
        .fetch_one(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let block_id: uuid::Uuid = row.get("id");
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:block:created", serde_json::json!({ "block_id": block_id, "block_code": &block_code }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "id": block_id, "block_code": block_code, "status": "PROVISIONAL" })))
}

/// `GET /v1/properties/{property_id}/blocks`
#[utoipa::path(
    get,
    path = "/v1/admin/blocks",
    responses(
        (status = 200, description = "List of blocks", body = serde_json::Value),
        (status = 403, description = "Missing pms:admin scope"),
    ),
    security(("pms:admin" = [])),
    tag = "pms",
)]
pub async fn list_blocks(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:block:read")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, block_code, block_name, start_date, end_date, blocked_rooms, picked_up, released_until, status FROM pms.blocks WHERE property_id = $1 ORDER BY start_date DESC")
        .bind(property_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows.iter().map(|r| {
        let status: String = r.get("status");
        serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id"),
            "block_code": r.get::<String, _>("block_code"),
            "block_name": r.get::<String, _>("block_name"),
            "start_date": r.get::<chrono::NaiveDate, _>("start_date"),
            "end_date": r.get::<chrono::NaiveDate, _>("end_date"),
            "blocked_rooms": r.get::<i32, _>("blocked_rooms"),
            "picked_up": r.get::<i32, _>("picked_up"),
            "released_until": r.get::<String, _>("released_until"),
            "status": status,
        })
    }).collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

pub async fn update_block_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, block_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:block:write")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let new_status = req.get("status").and_then(|v| v.as_str()).unwrap_or("PROVISIONAL");
    let next = BlockState::from_label(new_status);
    // Guard the transition server-side: read current, validate against the matrix.
    let cur_row = sqlx::query("SELECT status::text as status FROM pms.blocks WHERE id = $1 AND property_id = $2")
        .bind(block_id)
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => super::err_not_found("Block not found"),
            e => super::err_db(e),
        })?;
    let cur_label: String = cur_row.get("status");
    let cur = BlockState::from_label(&cur_label);
    if !cur.can_transition_to(next) {
        return Err((StatusCode::CONFLICT, format!("Block is {}, cannot transition to {}", cur_label, next)));
    }
    sqlx::query("UPDATE pms.blocks SET status = $3::pms.block_status, updated_at = now() WHERE id = $1 AND property_id = $2")
        .bind(block_id)
        .bind(property_id)
        .bind(new_status)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:block:status_changed", serde_json::json!({ "block_id": block_id, "new_status": new_status }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Block next statuses ──

pub async fn get_next_statuses(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, block_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:block:read")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let row = sqlx::query("SELECT status::text as status FROM pms.blocks WHERE id = $1 AND property_id = $2")
        .bind(block_id).bind(property_id).fetch_one(&mut *conn).await
        .map_err(|e| match e { sqlx::Error::RowNotFound => super::err_not_found("Block not found"), e => super::err_db(e) })?;
    let current: String = row.get("status");
    let cur = BlockState::from_label(&current);
    let next: Vec<&str> = [
        BlockState::Provisional,
        BlockState::Definitive,
        BlockState::Released,
        BlockState::Cancelled,
    ]
    .into_iter()
    .filter(|s| cur.can_transition_to(*s))
    .map(|s| s.label())
    .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "current_status": current, "next_statuses": next })))
}

// ── Posting Master ──

pub async fn create_posting_master(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, block_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    _req: Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:block:write")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    // Create a reservation that serves as the posting master for the block
    let pm_conf = format!("PM-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    let row = sqlx::query("INSERT INTO pms.reservations (property_id, confirmation_number, status, guarantee_type, market_code, special_requests)
        SELECT $2, $3, 'CONFIRMED', 'NONE', 'GROUP', 'Posting Master for Block'
        RETURNING id, confirmation_number")
        .bind(block_id).bind(property_id).bind(&pm_conf)
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let pm_id: uuid::Uuid = row.get("id");
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:block:posting_master_created", serde_json::json!({ "block_id": block_id, "posting_master_id": pm_id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "posting_master_id": pm_id, "block_id": block_id, "confirmation_number": row.get::<String, _>("confirmation_number") })))
}

// ── Function Space Availability ──

pub async fn get_available_spaces(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    axum::extract::Query(params): axum::extract::Query<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:event:read")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let min_capacity: i32 = params.get("min_capacity").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
    let date = params.get("date").and_then(|v| v.as_str());
    let rows = sqlx::query("SELECT id, space_code, space_name, capacity, setup_styles FROM pms.function_spaces WHERE property_id = $1 AND is_active = true AND capacity >= $2 ORDER BY capacity")
        .bind(property_id).bind(min_capacity).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    // For each space, check if it's booked on the given date
    let mut available: Vec<serde_json::Value> = Vec::new();
    for r in &rows {
        let space_id: uuid::Uuid = r.get("id");
        let is_booked = if let Some(d) = date {
            sqlx::query("SELECT COUNT(*) > 0 as booked FROM pms.events e JOIN pms.event_resources er ON er.event_id = e.id WHERE e.property_id = $1 AND e.start_date <= $2 AND e.end_date >= $2 AND er.resource_type = 'SPACE' AND er.resource_name IN (SELECT space_name FROM pms.function_spaces WHERE id = $3)")
                .bind(property_id).bind(d).bind(space_id).fetch_one(&mut *conn).await.map_err(super::err_db)?.get::<bool, _>("booked")
        } else { false };
        if !is_booked {
            available.push(serde_json::json!({
                "id": space_id, "space_code": r.get::<String, _>("space_code"),
                "space_name": r.get::<String, _>("space_name"), "capacity": r.get::<i32, _>("capacity"),
                "setup_styles": r.get::<serde_json::Value, _>("setup_styles"),
            }));
        }
    }
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": available })))
}

// ── Event Resources ──

pub async fn get_event_resources(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, event_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:event:read")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, resource_type, resource_name, quantity, cost::text as cost, notes FROM pms.event_resources WHERE event_id = $1 ORDER BY resource_type")
        .bind(event_id).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "id": r.get::<uuid::Uuid, _>("id"), "resource_type": r.get::<String, _>("resource_type"),
        "resource_name": r.get::<String, _>("resource_name"), "quantity": r.get::<i32, _>("quantity"),
        "cost": r.get::<String, _>("cost"), "notes": r.get::<Option<String>, _>("notes"),
    })).collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

pub async fn update_event_resources(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, event_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:event:write")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let resources = req.get("resources").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut added: Vec<serde_json::Value> = Vec::new();
    for r in &resources {
        let resource_type = r.get("resource_type").and_then(|v| v.as_str()).unwrap_or("AV");
        let resource_name = r.get("resource_name").and_then(|v| v.as_str()).unwrap_or("");
        let quantity: i32 = r.get("quantity").and_then(|v| v.as_i64()).unwrap_or(1) as i32;
        let cost = r.get("cost").and_then(|v| v.as_str()).unwrap_or("0");
        let notes = r.get("notes").and_then(|v| v.as_str());
        let row = sqlx::query("INSERT INTO pms.event_resources (event_id, resource_type, resource_name, quantity, cost, notes) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id")
            .bind(event_id).bind(resource_type).bind(resource_name).bind(quantity).bind(cost).bind(notes)
            .fetch_one(&mut *conn).await.map_err(super::err_db)?;
        added.push(serde_json::json!({ "id": row.get::<uuid::Uuid, _>("id"), "resource_type": resource_type, "resource_name": resource_name }));
    }
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:event:resources_updated", serde_json::json!({ "event_id": event_id, "count": added.len() }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "event_id": event_id, "added": added })))
}

// ── Events ──

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

/// `GET /v1/properties/{property_id}/events`
#[utoipa::path(
    get,
    path = "/v1/admin/events",
    responses(
        (status = 200, description = "List of events", body = serde_json::Value),
        (status = 403, description = "Missing pms:admin scope"),
    ),
    security(("pms:admin" = [])),
    tag = "pms",
)]
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