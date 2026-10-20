// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Housekeeping handlers.
use crate::auth;
use crate::handlers::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use hotel8::pms::contracts::{
    HkBoardList, HkBoardRow, HkStatusChangeRequest, HkStatusResult, HkTaskCreateRequest,
    HkTaskCreated, HkTaskList, HkTaskUpdateRequest, HkTaskUpdateResult, HkTaskView,
    HousekeepingForecast,
};
use sqlx::Row;

/// `GET /v1/properties/{property_id}/housekeeping`
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/housekeeping",
    responses(
        (status = 200, description = "Housekeeping rooms board", body = HkBoardList),
        (status = 403, description = "Missing pms:admin scope"),
    ),
    security(("pms:admin" = [])),
    tag = "pms",
)]
pub async fn list_housekeeping_tasks(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<HkBoardList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:housekeeping:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, room_number, floor, building, housekeeping_status, front_office_status, last_cleaned_at, last_inspected_at FROM pms.rooms WHERE property_id = $1 AND housekeeping_status IN ('DIRTY', 'CLEAN', 'INSPECTED') ORDER BY CASE housekeeping_status WHEN 'DIRTY' THEN 1 WHEN 'CLEAN' THEN 2 ELSE 3 END, room_number")
        .bind(property_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<HkBoardRow> = rows
        .iter()
        .map(|r| {
            let hk: String = r.get("housekeeping_status");
            let fo: String = r.get("front_office_status");
            HkBoardRow {
                id: r.get::<uuid::Uuid, _>("id"),
                room_number: r.get::<String, _>("room_number"),
                floor: r.get::<String, _>("floor"),
                building: r.get::<String, _>("building"),
                housekeeping_status: hk,
                front_office_status: fo,
                last_cleaned_at: r
                    .get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_cleaned_at"),
                last_inspected_at: r
                    .get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_inspected_at"),
            }
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(HkBoardList { items }))
}
#[utoipa::path(
    put,
    path = "/v1/properties/{property_id}/housekeeping/{room_number}",
    request_body = HkStatusChangeRequest,
    responses(
        (status = 200, description = "Housekeeping status updated", body = HkStatusResult),
        (status = 400, description = "Invalid status (DIRTY | CLEAN | INSPECTED)"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Room not found"),
    ),
    security(),
    tag = "pms",
)]

pub async fn update_housekeeping_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, room_number)): Path<(uuid::Uuid, String)>,
    Json(req): Json<HkStatusChangeRequest>,
) -> Result<Json<HkStatusResult>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:housekeeping:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let status = req.status.as_str();
    let hk_expr = match status {
        "DIRTY" => "'DIRTY'",
        "CLEAN" => "'CLEAN'",
        "INSPECTED" => "'INSPECTED'",
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Invalid housekeeping status: {}", status),
            ))
        }
    };
    let cleaned = if status == "CLEAN" {
        "now()"
    } else {
        "last_cleaned_at"
    };
    let inspected = if status == "INSPECTED" {
        "now()"
    } else {
        "last_inspected_at"
    };
    let query = format!(
        "UPDATE pms.rooms SET housekeeping_status = {}::pms.hk_status, last_cleaned_at = {}, last_inspected_at = {}, updated_at = now() WHERE property_id = $1 AND room_number = $2 RETURNING room_number, housekeeping_status",
        hk_expr, cleaned, inspected
    );
    let row = sqlx::query(&query)
        .bind(property_id)
        .bind(&room_number)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => super::err_not_found("Room not found"),
            e => super::err_db(e),
        })?;
    let hk: String = row.get("housekeeping_status");
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:housekeeping:status_changed",
        serde_json::json!({ "room_number": room_number, "housekeeping_status": hk }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(HkStatusResult {
        room_number,
        housekeeping_status: hk,
    }))
}

// ── Housekeeping Tasks ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/housekeeping/tasks",
    request_body = HkTaskCreateRequest,
    responses(
        (status = 200, description = "Created housekeeping task", body = HkTaskCreated),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn create_task(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<HkTaskCreateRequest>,
) -> Result<Json<HkTaskCreated>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:housekeeping:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let room_number = req.room_number.as_deref();
    let task_type = req.task_type.as_str();
    let priority = req.priority.as_str();
    let assigned_to = req.assigned_to.as_deref();
    let notes = req.notes.as_deref();
    let row = sqlx::query("INSERT INTO pms.hk_tasks (property_id, room_number, task_type, priority, assigned_to, notes) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, room_number, task_type, status, priority, assigned_to, notes, created_at")
        .bind(property_id).bind(room_number).bind(task_type).bind(priority).bind(assigned_to).bind(notes)
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let id: uuid::Uuid = row.get("id");
    let status: String = row.get("status");
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(HkTaskCreated {
        id,
        property_id,
        room_number: row.get::<Option<String>, _>("room_number"),
        task_type: row.get::<String, _>("task_type"),
        status,
        priority: row.get::<String, _>("priority"),
        assigned_to: row.get::<Option<String>, _>("assigned_to"),
        notes: row.get::<Option<String>, _>("notes"),
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    }))
}
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/housekeeping/tasks",
    responses(
        (status = 200, description = "Housekeeping tasks of the property", body = HkTaskList),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn list_tasks(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    axum::extract::Query(params): axum::extract::Query<serde_json::Value>,
) -> Result<Json<HkTaskList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:housekeeping:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let status_filter = params.get("status").and_then(|v| v.as_str());
    let assigned_filter = params.get("assigned_to").and_then(|v| v.as_str());
    let rows = match (status_filter, assigned_filter) {
        (Some(st), Some(asg)) => sqlx::query("SELECT id, room_number, task_type, status, priority, assigned_to, notes, created_at FROM pms.hk_tasks WHERE property_id = $1 AND status = $2 AND assigned_to = $3 ORDER BY created_at").bind(property_id).bind(st).bind(asg).fetch_all(&mut *conn).await,
        (Some(st), None) => sqlx::query("SELECT id, room_number, task_type, status, priority, assigned_to, notes, created_at FROM pms.hk_tasks WHERE property_id = $1 AND status = $2 ORDER BY created_at").bind(property_id).bind(st).fetch_all(&mut *conn).await,
        (None, Some(asg)) => sqlx::query("SELECT id, room_number, task_type, status, priority, assigned_to, notes, created_at FROM pms.hk_tasks WHERE property_id = $1 AND assigned_to = $2 ORDER BY created_at").bind(property_id).bind(asg).fetch_all(&mut *conn).await,
        (None, None) => sqlx::query("SELECT id, room_number, task_type, status, priority, assigned_to, notes, created_at FROM pms.hk_tasks WHERE property_id = $1 ORDER BY created_at").bind(property_id).fetch_all(&mut *conn).await,
    }.map_err(super::err_db)?;
    let items: Vec<HkTaskView> = rows
        .iter()
        .map(|r| {
            let s: String = r.get("status");
            HkTaskView {
                id: r.get::<uuid::Uuid, _>("id"),
                room_number: r.get::<Option<String>, _>("room_number"),
                task_type: r.get::<String, _>("task_type"),
                status: s,
                priority: r.get::<String, _>("priority"),
                assigned_to: r.get::<Option<String>, _>("assigned_to"),
                notes: r.get::<Option<String>, _>("notes"),
                created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            }
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(HkTaskList { items }))
}
#[utoipa::path(
    put,
    path = "/v1/properties/{property_id}/housekeeping/tasks/{task_id}",
    request_body = HkTaskUpdateRequest,
    responses(
        (status = 200, description = "Updated housekeeping task", body = HkTaskUpdateResult),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Task not found"),
    ),
    security(),
    tag = "pms",
)]

pub async fn update_task(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, task_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<HkTaskUpdateRequest>,
) -> Result<Json<HkTaskUpdateResult>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:housekeeping:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let new_status = req.status.as_str();
    let assigned_to = req.assigned_to.as_deref();
    let row = sqlx::query("UPDATE pms.hk_tasks SET status = $3, assigned_to = COALESCE($4, assigned_to), updated_at = now() WHERE id = $1 AND property_id = $2 RETURNING id, status, assigned_to")
        .bind(task_id).bind(property_id).bind(new_status).bind(assigned_to)
        .fetch_one(&mut *conn).await.map_err(|e| match e { sqlx::Error::RowNotFound => super::err_not_found("Task not found"), e => super::err_db(e) })?;
    let status: String = row.get("status");
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:housekeeping:task_updated",
        serde_json::json!({ "task_id": task_id, "status": new_status }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(HkTaskUpdateResult {
        id: row.get::<uuid::Uuid, _>("id"),
        status,
        assigned_to: row.get::<Option<String>, _>("assigned_to"),
    }))
}

// ── Housekeeping Forecast ──
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/housekeeping/forecast",
    responses(
        (status = 200, description = "Housekeeping forecast for the business date", body = HousekeepingForecast),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn get_forecast(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<HousekeepingForecast>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:housekeeping:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let today = chrono::Utc::now().date_naive();
    let expected_checkouts = sqlx::query("SELECT COUNT(*)::int as cnt FROM pms.reservations WHERE property_id = $1 AND arrival_date = $2 AND status = 'CONFIRMED'")
        .bind(property_id).bind(today).fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let stayovers = sqlx::query("SELECT COUNT(*)::int as cnt FROM pms.reservations WHERE property_id = $1 AND arrival_date < $2 AND departure_date > $2 AND status = 'CHECKED_IN'")
        .bind(property_id).bind(today).fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let departures = sqlx::query("SELECT COUNT(*)::int as cnt FROM pms.reservations WHERE property_id = $1 AND departure_date = $2 AND status = 'CHECKED_IN'")
        .bind(property_id).bind(today).fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let dirty_rooms = sqlx::query("SELECT COUNT(*)::int as cnt FROM pms.rooms WHERE property_id = $1 AND housekeeping_status = 'DIRTY'")
        .bind(property_id).fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let open_tasks = sqlx::query("SELECT COUNT(*)::int as cnt FROM pms.hk_tasks WHERE property_id = $1 AND status IN ('OPEN', 'IN_PROGRESS')")
        .bind(property_id).fetch_one(&mut *conn).await.map_err(super::err_db)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(HousekeepingForecast {
        date: today,
        expected_arrivals: expected_checkouts.get::<i32, _>("cnt"),
        stayovers: stayovers.get::<i32, _>("cnt"),
        expected_departures: departures.get::<i32, _>("cnt"),
        dirty_rooms: dirty_rooms.get::<i32, _>("cnt"),
        open_tasks: open_tasks.get::<i32, _>("cnt"),
    }))
}
