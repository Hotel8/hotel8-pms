// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Blocks (allotments) and Events handlers.
use crate::auth;
use crate::handlers::AppState;
use crate::state_machine::{BlockState, PmsState};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use hotel8::pms::contracts::{
    BlockCreateRequest, BlockCreated, BlockList, BlockNextStatuses, BlockStatusChange,
    BlockSummary, EventResourceAdded, EventResourceList, EventResourceRow, EventResourceUpdate,
    EventResourceUpdateResult, FunctionSpace, FunctionSpaceList, PostingMasterCreated,
};
use sqlx::Row;

// ── Blocks ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/blocks",
    request_body = BlockCreateRequest,
    responses(
        (status = 200, description = "OK - block created in PROVISIONAL state", body = BlockCreated),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn create_block(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<BlockCreateRequest>,
) -> Result<Json<BlockCreated>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:block:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let block_code = format!("BLK-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    let row = sqlx::query("INSERT INTO pms.blocks (property_id, block_code, block_name, room_type_id, start_date, end_date, blocked_rooms, released_until, status, block_type, negotiated_rate, cutoff_date)
         VALUES ($1, $2, $3, $4, $5::date, $6::date, $7, $8, 'PROVISIONAL', $9, $10::numeric, $11::date) RETURNING *")
        .bind(property_id)
        .bind(&block_code)
        .bind(&req.block_name)
        .bind(req.room_type_id)
        .bind(req.start_date.as_deref())
        .bind(req.end_date.as_deref())
        .bind(req.blocked_rooms)
        .bind(Some(req.released_until.as_str()))
        .bind(Some(req.block_type.as_str()))
        .bind(req.negotiated_rate.as_deref())
        .bind(req.cutoff_date.as_deref())
        .fetch_one(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let block_id: uuid::Uuid = row.get("id");
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:block:created",
        serde_json::json!({ "block_id": block_id, "block_code": &block_code }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(BlockCreated {
        id: block_id,
        block_code: block_code,
        status: "PROVISIONAL".into(),
    }))
}

/// `GET /v1/properties/{property_id}/blocks`
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/blocks",
    responses(
        (status = 200, description = "List of blocks", body = BlockList),
        (status = 403, description = "Missing pms:admin scope"),
    ),
    security(("pms:admin" = [])),
    tag = "pms",
)]
pub async fn list_blocks(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<BlockList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:block:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, block_code, block_name, start_date, end_date, blocked_rooms, picked_up, released_until, status FROM pms.blocks WHERE property_id = $1 ORDER BY start_date DESC")
        .bind(property_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<BlockSummary> = rows
        .iter()
        .map(|r| BlockSummary {
            id: r.get::<uuid::Uuid, _>("id"),
            block_code: r.get::<String, _>("block_code"),
            block_name: r.get::<String, _>("block_name"),
            start_date: r.get::<chrono::NaiveDate, _>("start_date"),
            end_date: r.get::<chrono::NaiveDate, _>("end_date"),
            blocked_rooms: r.get::<i32, _>("blocked_rooms"),
            picked_up: r.get::<i32, _>("picked_up"),
            released_until: r.get::<String, _>("released_until"),
            status: r.get("status"),
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(BlockList { items }))
}
#[utoipa::path(
    put,
    path = "/v1/properties/{property_id}/blocks/{block_id}/status",
    request_body = BlockStatusChange,
    responses(
        (status = 204, description = "Transition applied"),
        (status = 409, description = "Transition not allowed by the block state machine"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn update_block_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, block_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<BlockStatusChange>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:block:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let new_status = req.status.as_str();
    let next = BlockState::from_label(new_status);
    // Guard the transition server-side: read current, validate against the matrix.
    let cur_row = sqlx::query(
        "SELECT status::text as status FROM pms.blocks WHERE id = $1 AND property_id = $2",
    )
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
        return Err((
            StatusCode::CONFLICT,
            format!("Block is {}, cannot transition to {}", cur_label, next),
        ));
    }
    sqlx::query("UPDATE pms.blocks SET status = $3::pms.block_status, updated_at = now() WHERE id = $1 AND property_id = $2")
        .bind(block_id)
        .bind(property_id)
        .bind(new_status)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:block:status_changed",
        serde_json::json!({ "block_id": block_id, "new_status": new_status }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Block next statuses ──
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/blocks/{block_id}/next-statuses",
    responses(
        (status = 200, description = "OK", body = BlockNextStatuses),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn get_next_statuses(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, block_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<BlockNextStatuses>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:block:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let row = sqlx::query(
        "SELECT status::text as status FROM pms.blocks WHERE id = $1 AND property_id = $2",
    )
    .bind(block_id)
    .bind(property_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => super::err_not_found("Block not found"),
        e => super::err_db(e),
    })?;
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
    Ok(Json(BlockNextStatuses {
        current_status: current,
        next_statuses: next.into_iter().map(str::to_owned).collect(),
    }))
}

// ── Posting Master ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/blocks/{block_id}/posting-master",
    responses(
        (status = 200, description = "OK - posting master reservation created", body = PostingMasterCreated),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn create_posting_master(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, block_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<PostingMasterCreated>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:block:write"),
    )
    .await?;
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
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:block:posting_master_created",
        serde_json::json!({ "block_id": block_id, "posting_master_id": pm_id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(PostingMasterCreated {
        posting_master_id: pm_id,
        block_id,
        confirmation_number: row.get::<String, _>("confirmation_number"),
    }))
}

// ── Function Space Availability ──
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/function-spaces",
    responses(
        (status = 200, description = "OK - active spaces with capacity >= min_capacity, minus those booked on the optional date", body = FunctionSpaceList),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn get_available_spaces(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    axum::extract::Query(params): axum::extract::Query<serde_json::Value>,
) -> Result<Json<FunctionSpaceList>, (StatusCode, String)> {
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
    let min_capacity: i32 = params
        .get("min_capacity")
        .and_then(|v| v.as_i64())
        .unwrap_or(0) as i32;
    let date = params.get("date").and_then(|v| v.as_str());
    let rows = sqlx::query("SELECT id, space_code, space_name, capacity, setup_styles FROM pms.function_spaces WHERE property_id = $1 AND is_active = true AND capacity >= $2 ORDER BY capacity")
        .bind(property_id).bind(min_capacity).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    // For each space, check if it's booked on the given date
    let mut available: Vec<FunctionSpace> = Vec::new();
    for r in &rows {
        let space_id: uuid::Uuid = r.get("id");
        let is_booked = if let Some(d) = date {
            sqlx::query("SELECT COUNT(*) > 0 as booked FROM pms.events e JOIN pms.event_resources er ON er.event_id = e.id WHERE e.property_id = $1 AND e.start_date <= $2 AND e.end_date >= $2 AND er.resource_type = 'SPACE' AND er.resource_name IN (SELECT space_name FROM pms.function_spaces WHERE id = $3)")
                .bind(property_id).bind(d).bind(space_id).fetch_one(&mut *conn).await.map_err(super::err_db)?.get::<bool, _>("booked")
        } else {
            false
        };
        if !is_booked {
            available.push(FunctionSpace {
                id: space_id,
                space_code: r.get::<String, _>("space_code"),
                space_name: r.get::<String, _>("space_name"),
                capacity: r.get::<i32, _>("capacity"),
                setup_styles: r
                    .get::<serde_json::Value, _>("setup_styles")
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
            });
        }
    }
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(FunctionSpaceList { items: available }))
}

// ── Event Resources ──
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/events/{event_id}/resources",
    responses(
        (status = 200, description = "OK - resources ordered by resource_type", body = EventResourceList),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn get_event_resources(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, event_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<EventResourceList>, (StatusCode, String)> {
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
    let rows = sqlx::query("SELECT id, resource_type, resource_name, quantity, cost::text as cost, notes FROM pms.event_resources WHERE event_id = $1 ORDER BY resource_type")
        .bind(event_id).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let items: Vec<EventResourceRow> = rows
        .iter()
        .map(|r| EventResourceRow {
            id: r.get::<uuid::Uuid, _>("id"),
            resource_type: r.get::<String, _>("resource_type"),
            resource_name: r.get::<String, _>("resource_name"),
            quantity: r.get::<i32, _>("quantity"),
            cost: r.get::<String, _>("cost"),
            notes: r.get::<Option<String>, _>("notes"),
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(EventResourceList { items }))
}
#[utoipa::path(
    put,
    path = "/v1/properties/{property_id}/events/{event_id}/resources",
    request_body = EventResourceUpdate,
    responses(
        (status = 200, description = "OK - every listed resource line is inserted", body = EventResourceUpdateResult),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn update_event_resources(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, event_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<EventResourceUpdate>,
) -> Result<Json<EventResourceUpdateResult>, (StatusCode, String)> {
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
    let mut added: Vec<EventResourceAdded> = Vec::new();
    for r in &req.resources {
        let resource_type = r.resource_type.as_str();
        let resource_name = r.resource_name.as_str();
        let quantity = r.quantity;
        let cost = r.cost.as_str();
        let notes = r.notes.as_deref();
        let row = sqlx::query("INSERT INTO pms.event_resources (event_id, resource_type, resource_name, quantity, cost, notes) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id")
            .bind(event_id).bind(resource_type).bind(resource_name).bind(quantity).bind(cost).bind(notes)
            .fetch_one(&mut *conn).await.map_err(super::err_db)?;
        added.push(EventResourceAdded {
            id: row.get::<uuid::Uuid, _>("id"),
            resource_type: resource_type.to_string(),
            resource_name: resource_name.to_string(),
        });
    }
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:event:resources_updated",
        serde_json::json!({ "event_id": event_id, "count": added.len() }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(EventResourceUpdateResult {
        event_id,
        added,
    }))
}

// ── Events ──
// `POST`/`GET /v1/properties/{property_id}/events` are owned by the
// `events.rs` handlers (routes + `openapi.rs paths()`); this module only
// carries the function-space and event-resource endpoints of this section.
