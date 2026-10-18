// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Front desk handlers — check-in, check-out, in-house guest list.
use crate::auth;
use crate::handlers::AppState;
use crate::state_machine::{PmsState, ReservationState};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sqlx::Row;
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations/{res_id}/check-in",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn check_in(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;

    let room_number = req.get("room_number").and_then(|v| v.as_str());
    let res = sqlx::query("SELECT status FROM pms.reservations WHERE id = $1 AND property_id = $2")
        .bind(res_id)
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => super::err_not_found("Reservation not found"),
            e => super::err_db(e),
        })?;
    let status: String = res.get("status");
    let cur = ReservationState::from_label(&status);
    if !cur.can_transition_to(ReservationState::CheckedIn) {
        return Err((
            StatusCode::CONFLICT,
            format!("Reservation is {}, cannot check in", status),
        ));
    }

    sqlx::query("UPDATE pms.reservations SET status = 'CHECKED_IN', checked_in_at = now(), assigned_room_number = $3, updated_at = now() WHERE id = $1 AND property_id = $2")
        .bind(res_id)
        .bind(property_id)
        .bind(room_number)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;

    if let Some(rn) = room_number {
        sqlx::query("UPDATE pms.rooms SET front_office_status = 'OCCUPIED', current_reservation_id = $3, updated_at = now() WHERE property_id = $1 AND room_number = $2")
            .bind(property_id)
            .bind(rn)
            .bind(res_id)
            .execute(&mut *conn)
            .await
            .map_err(super::err_db)?;
    }

    // Open folio
    sqlx::query(
        "INSERT INTO pms.folios (property_id, reservation_id, status) VALUES ($1, $2, 'OPEN')",
    )
    .bind(property_id)
    .bind(res_id)
    .execute(&mut *conn)
    .await
    .map_err(super::err_db)?;

    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:reservation:checked_in",
        serde_json::json!({ "reservation_id": res_id, "room_number": room_number }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "reservation_id": res_id, "status": "CHECKED_IN", "room_number": room_number }),
    ))
}
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations/{res_id}/check-out",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn check_out(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;

    let res = sqlx::query("SELECT status, assigned_room_number FROM pms.reservations WHERE id = $1 AND property_id = $2")
        .bind(res_id)
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => super::err_not_found("Reservation not found"),
            e => super::err_db(e),
        })?;
    let status: String = res.get("status");
    let cur = ReservationState::from_label(&status);
    if !cur.can_transition_to(ReservationState::CheckedOut) {
        return Err((
            StatusCode::CONFLICT,
            format!("Reservation is {}, cannot check out", status),
        ));
    }
    let room_number: Option<String> = res.get("assigned_room_number");

    sqlx::query("UPDATE pms.reservations SET status = 'CHECKED_OUT', checked_out_at = now(), updated_at = now() WHERE id = $1 AND property_id = $2")
        .bind(res_id)
        .bind(property_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;

    if let Some(ref rn) = room_number {
        sqlx::query("UPDATE pms.rooms SET front_office_status = 'VACANT', housekeeping_status = 'DIRTY', current_reservation_id = NULL, updated_at = now() WHERE property_id = $1 AND room_number = $2")
            .bind(property_id)
            .bind(rn)
            .execute(&mut *conn)
            .await
            .map_err(super::err_db)?;
    }

    // Revoke any active digital keys — a departed stay loses key access
    // (pms DESIGN.md §3 invariant).
    let _ = sqlx::query(
        "UPDATE pms.digital_keys SET status = 'REVOKED', revoked_at = now(), updated_at = now()
          WHERE reservation_id = $1 AND status = 'ACTIVE'",
    )
    .bind(res_id)
    .execute(&mut *conn)
    .await;

    // Close folio
    let payment_method = req
        .get("payment_method")
        .and_then(|v| v.as_str())
        .unwrap_or("CASH");
    let _ = sqlx::query("UPDATE pms.folios SET status = 'CLOSED', closed_at = now(), payment_method = $3 WHERE reservation_id = $1 AND property_id = $2 AND status = 'OPEN'")
        .bind(res_id)
        .bind(property_id)
        .bind(payment_method)
        .execute(&mut *conn)
        .await;

    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:reservation:checked_out",
        serde_json::json!({ "reservation_id": res_id, "room_number": room_number }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "reservation_id": res_id, "status": "CHECKED_OUT", "room_number": room_number }),
    ))
}

/// `GET /v1/properties/{property_id}/in-house`
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/in-house",
    responses(
        (status = 200, description = "List of in-house guests", body = serde_json::Value),
        (status = 403, description = "Missing pms:admin scope"),
    ),
    security(("pms:admin" = [])),
    tag = "pms",
)]
pub async fn list_in_house(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, confirmation_number, guest_profile_id, room_type_id, assigned_room_number, arrival_date, departure_date, num_adults, num_children FROM pms.reservations WHERE property_id = $1 AND status = 'CHECKED_IN' ORDER BY assigned_room_number")
        .bind(property_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<uuid::Uuid, _>("id"),
                "confirmation_number": r.get::<String, _>("confirmation_number"),
                "guest_profile_id": r.get::<Option<uuid::Uuid>, _>("guest_profile_id"),
                "room_type_id": r.get::<Option<uuid::Uuid>, _>("room_type_id"),
                "room_number": r.get::<Option<String>, _>("assigned_room_number"),
                "arrival_date": r.get::<chrono::NaiveDate, _>("arrival_date"),
                "departure_date": r.get::<chrono::NaiveDate, _>("departure_date"),
                "num_adults": r.get::<i32, _>("num_adults"),
                "num_children": r.get::<i32, _>("num_children"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

// ── Pre-Register ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations/{res_id}/pre-check-in",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn pre_check_in(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let arrival_time = req.get("arrival_time").and_then(|v| v.as_str());
    let special_requests = req.get("special_requests").and_then(|v| v.as_str());
    let row = sqlx::query("UPDATE pms.reservations SET special_requests = COALESCE($3, special_requests), updated_at = now() WHERE id = $1 AND property_id = $2 AND status = 'CONFIRMED' RETURNING id, confirmation_number")
        .bind(res_id).bind(property_id).bind(special_requests)
        .fetch_one(&mut *conn).await.map_err(|e| match e { sqlx::Error::RowNotFound => (StatusCode::CONFLICT, "Reservation not found or not in CONFIRMED status".to_string()), e => super::err_db(e) })?;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:guest:pre_registered",
        serde_json::json!({ "reservation_id": res_id, "arrival_time": arrival_time }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "reservation_id": row.get::<uuid::Uuid, _>("id"), "confirmation_number": row.get::<String, _>("confirmation_number"), "status": "PRE_REGISTERED" }),
    ))
}

// ── Check-In revert ──
#[utoipa::path(
    delete,
    path = "/v1/properties/{property_id}/reservations/{res_id}/check-in",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn revert_check_in(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let res = sqlx::query("SELECT status, assigned_room_number FROM pms.reservations WHERE id = $1 AND property_id = $2")
        .bind(res_id).bind(property_id).fetch_one(&mut *conn).await
        .map_err(|e| match e { sqlx::Error::RowNotFound => super::err_not_found("Reservation not found"), e => super::err_db(e) })?;
    let status: String = res.get("status");
    if status != "CHECKED_IN" {
        return Err((
            StatusCode::CONFLICT,
            format!("Reservation is {}, cannot revert check-in", status),
        ));
    }
    let room_number: Option<String> = res.get("assigned_room_number");
    sqlx::query("UPDATE pms.reservations SET status = 'CONFIRMED', checked_in_at = NULL, assigned_room_number = NULL, updated_at = now() WHERE id = $1")
        .bind(res_id).execute(&mut *conn).await.map_err(super::err_db)?;
    if let Some(ref rn) = room_number {
        sqlx::query("UPDATE pms.rooms SET front_office_status = 'VACANT', current_reservation_id = NULL, updated_at = now() WHERE property_id = $1 AND room_number = $2")
            .bind(property_id).bind(rn).execute(&mut *conn).await.map_err(super::err_db)?;
    }
    // Close any open folio
    let _ = sqlx::query("DELETE FROM pms.folios WHERE reservation_id = $1 AND status = 'OPEN'")
        .bind(res_id)
        .execute(&mut *conn)
        .await;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:guest:checkin_reverted",
        serde_json::json!({ "reservation_id": res_id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Guest Messaging ──
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/reservations/{res_id}/messages",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn get_messages(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, direction, message_type, content, sender, is_read, created_at FROM pms.reservation_messages WHERE reservation_id = $1 ORDER BY created_at")
        .bind(res_id).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "id": r.get::<uuid::Uuid, _>("id"), "direction": r.get::<String, _>("direction"),
        "message_type": r.get::<String, _>("message_type"), "content": r.get::<String, _>("content"),
        "sender": r.get::<Option<String>, _>("sender"), "is_read": r.get::<bool, _>("is_read"),
        "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    })).collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations/{res_id}/messages",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn send_message(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let content = req.get("content").and_then(|v| v.as_str()).unwrap_or("");
    let message_type = req
        .get("message_type")
        .and_then(|v| v.as_str())
        .unwrap_or("MESSAGE");
    let sender = req.get("sender").and_then(|v| v.as_str());
    let row = sqlx::query("INSERT INTO pms.reservation_messages (reservation_id, direction, message_type, content, sender) VALUES ($1, 'OUTBOUND', $2, $3, $4) RETURNING id, direction, message_type, content, sender, created_at")
        .bind(res_id).bind(message_type).bind(content).bind(sender)
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let id: uuid::Uuid = row.get("id");
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "id": id, "direction": row.get::<String, _>("direction"), "message_type": row.get::<String, _>("message_type"), "content": row.get::<String, _>("content"), "sender": row.get::<Option<String>, _>("sender"), "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at") }),
    ))
}

// ── Service Requests ──
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/reservations/{res_id}/service-requests",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn get_service_requests(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, request_type, description, status, assigned_to, created_at, updated_at FROM pms.service_requests WHERE reservation_id = $1 ORDER BY created_at")
        .bind(res_id).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows.iter().map(|r| { let s: String = r.get("status"); serde_json::json!({
        "id": r.get::<uuid::Uuid, _>("id"), "request_type": r.get::<String, _>("request_type"),
        "description": r.get::<Option<String>, _>("description"), "status": s,
        "assigned_to": r.get::<Option<String>, _>("assigned_to"),
        "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    })}).collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations/{res_id}/service-requests",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn create_service_request(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let request_type = req
        .get("request_type")
        .and_then(|v| v.as_str())
        .unwrap_or("HOUSEKEEPING");
    let description = req.get("description").and_then(|v| v.as_str());
    let row = sqlx::query("INSERT INTO pms.service_requests (reservation_id, request_type, description) VALUES ($1, $2, $3) RETURNING id, request_type, description, status, created_at")
        .bind(res_id).bind(request_type).bind(description)
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let id: uuid::Uuid = row.get("id");
    let status: String = row.get("status");
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "id": id, "reservation_id": res_id, "request_type": row.get::<String, _>("request_type"), "description": row.get::<Option<String>, _>("description"), "status": status, "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at") }),
    ))
}
