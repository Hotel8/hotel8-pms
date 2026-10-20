// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Guest-app surface handlers (pms DESIGN.md §3 "Guest-app surfaces").
//!
//! Self-service endpoints consumed by eGuest and eKiosk through the BFF:
//! digital-key lifecycle, folios-by-room settlement view, boarding pass, and
//! stay feedback. Authorization mirrors the front-office scope set
//! (`hotel8:pms:frontdesk:*`, `hotel8:pms:cashiering:*`).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use hotel8::pms::contracts::{
    BoardingPass, CreateGuestPaymentMethodRequest, DigitalKeyList, DigitalKeyTransitionResult,
    DigitalKeyView, FeedbackLookup, FeedbackView, FolioChargeView, FolioPaymentView,
    GuestPaymentMethod, GuestPaymentMethodList, IssueDigitalKeyRequest, IssuedKeyList,
    IssuedKeyRef, LinkGuestRequest, LinkGuestResult, RoomFolioView, SubmitFeedbackRequest,
};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::auth;
use crate::event_emit::{emit_tx, Publisher};
use crate::handlers::{resolve_org_env, set_tenant_context, AppState};

// ── Digital keys ──────────────────────────────────────────────────────────
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/digital-keys",
    responses(
        (status = 200, description = "Digital keys of the reservation", body = DigitalKeyList),
        (status = 400, description = "reservation_id required"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

/// List digital keys for a reservation.
pub async fn list_digital_keys(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<Uuid>,
    Query(params): Query<serde_json::Value>,
) -> Result<Json<DigitalKeyList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:read"),
    )
    .await?;
    let env_id = resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let res_id = params
        .get("reservation_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "reservation_id required".into()))?;
    let rows = sqlx::query(
        "SELECT id, reservation_id, room_number, key_type, status, issued_at,
              activated_at, revoked_at, expires_at, issued_count
         FROM pms.digital_keys WHERE property_id = $1 AND reservation_id = $2
         ORDER BY issued_at",
    )
    .bind(property_id)
    .bind(res_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let items: Vec<DigitalKeyView> = rows
        .iter()
        .map(|r| DigitalKeyView {
            id: r.get::<Uuid, _>("id"),
            reservation_id: r.get::<Uuid, _>("reservation_id"),
            room_number: r.get::<Option<String>, _>("room_number"),
            key_type: r.get::<String, _>("key_type"),
            status: r.get::<String, _>("status"),
            issued_at: r.get::<chrono::DateTime<chrono::Utc>, _>("issued_at"),
            activated_at: r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("activated_at"),
            revoked_at: r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("revoked_at"),
            expires_at: r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("expires_at"),
            issued_count: r.get::<i32, _>("issued_count"),
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(DigitalKeyList { items }))
}
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/digital-keys",
    request_body = IssueDigitalKeyRequest,
    responses(
        (status = 200, description = "Issued (or reused) digital keys", body = IssuedKeyList),
        (status = 400, description = "reservation_id required"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Reservation not found"),
        (status = 409, description = "Keys are issued for checked-in reservations only"),
    ),
    security(),
    tag = "pms",
)]

/// Issue digital keys for a checked-in reservation (idempotent by room + count).
pub async fn issue_digital_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<Uuid>,
    Json(req): Json<IssueDigitalKeyRequest>,
) -> Result<Json<IssuedKeyList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:write"),
    )
    .await?;
    let env_id = resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let res_id = req.reservation_id;
    let key_type = req.key_type.as_str();
    let count = req.count.clamp(1, 8);
    let res = sqlx::query(
        "SELECT status, assigned_room_number FROM pms.reservations
         WHERE id = $1 AND property_id = $2",
    )
    .bind(res_id)
    .bind(property_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => super::err_not_found("Reservation not found"),
        e => super::err_db(e),
    })?;
    let status: String = res.get("status");
    if status != "CHECKED_IN" {
        return Err((
            StatusCode::CONFLICT,
            format!("Keys are issued for checked-in reservations only (is {status})"),
        ));
    }
    let room_number: Option<String> = res.get("assigned_room_number");
    // Idempotent sweep: reuse this reservation's INACTIVE keys before
    // minting new ones so a repeated call converges on `count` active-ready keys.
    let mut issued = Vec::new();
    for _ in 0..count {
        let reused = sqlx::query(
            "UPDATE pms.digital_keys SET updated_at = now()
             WHERE id = (
               SELECT id FROM pms.digital_keys
                WHERE property_id = $1 AND reservation_id = $2
                  AND status = 'INACTIVE' LIMIT 1
                FOR UPDATE SKIP LOCKED
             )
             RETURNING id",
        )
        .bind(property_id)
        .bind(res_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(super::err_db)?;
        if let Some(row) = reused {
            issued.push(row.get::<Uuid, _>("id"));
        } else {
            let row = sqlx::query(
                "INSERT INTO pms.digital_keys
                     (env_id, property_id, reservation_id, room_number, key_type, status)
                 VALUES ($1, $2, $3, $4, $5, 'INACTIVE')
                 RETURNING id",
            )
            .bind(env_id)
            .bind(property_id)
            .bind(res_id)
            .bind(&room_number)
            .bind(key_type)
            .fetch_one(&mut *conn)
            .await
            .map_err(super::err_db)?;
            issued.push(row.get::<Uuid, _>("id"));
        }
    }
    emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:key:issued",
        json!({ "reservation_id": res_id, "room_number": room_number, "key_ids": issued, "key_type": key_type }),
        &Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(IssuedKeyList {
        items: issued.iter().map(|i| IssuedKeyRef { id: *i }).collect(),
    }))
}
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/digital-keys/{key_id}/activate",
    responses(
        (status = 200, description = "Activated key", body = DigitalKeyTransitionResult),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 409, description = "Key is not in a state that allows activation"),
    ),
    security(),
    tag = "pms",
)]

/// Activate a digital key.
pub async fn activate_digital_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, key_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DigitalKeyTransitionResult>, (StatusCode, String)> {
    transition_key(state, headers, property_id, key_id, "ACTIVE").await
}
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/digital-keys/{key_id}/deactivate",
    responses(
        (status = 200, description = "Revoked key", body = DigitalKeyTransitionResult),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 409, description = "Key is not in a state that allows revocation"),
    ),
    security(),
    tag = "pms",
)]

/// Deactivate (revoke) a digital key.
pub async fn deactivate_digital_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, key_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<DigitalKeyTransitionResult>, (StatusCode, String)> {
    transition_key(state, headers, property_id, key_id, "REVOKED").await
}

async fn transition_key(
    state: AppState,
    headers: axum::http::HeaderMap,
    property_id: Uuid,
    key_id: Uuid,
    target: &str,
) -> Result<Json<DigitalKeyTransitionResult>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:write"),
    )
    .await?;
    let env_id = resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    // Legal transitions: INACTIVE → ACTIVE; ACTIVE → REVOKED. Anything else
    // is a conflict (the state machine lives here, not in the client).
    let legal_check = match target {
        "ACTIVE" => "status = 'INACTIVE'",
        _ => "status = 'ACTIVE'",
    };
    let stamp = if target == "ACTIVE" {
        "activated_at"
    } else {
        "revoked_at"
    };
    let row = sqlx::query(&format!(
        "UPDATE pms.digital_keys SET status = $3, {stamp} = now(), updated_at = now()
          WHERE id = $1 AND property_id = $2 AND {legal_check}
          RETURNING id, reservation_id, room_number, status"
    ))
    .bind(key_id)
    .bind(property_id)
    .bind(target)
    .fetch_optional(&mut *conn)
    .await
    .map_err(super::err_db)?
    .ok_or_else(|| {
        (
            StatusCode::CONFLICT,
            format!("Key {key_id} is not in a state that allows {target}"),
        )
    })?;
    let event_type = match target {
        "ACTIVE" => "hotel8:pms:key:activated",
        _ => "hotel8:pms:key:revoked",
    };
    emit_tx(
        &mut *conn,
        env_id,
        event_type,
        json!({ "key_id": key_id, "reservation_id": row.get::<Uuid, _>("reservation_id"), "room_number": row.get::<Option<String>, _>("room_number") }),
        &Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(DigitalKeyTransitionResult {
        id: row.get::<Uuid, _>("id"),
        reservation_id: row.get::<Uuid, _>("reservation_id"),
        room_number: row.get::<Option<String>, _>("room_number"),
        status: row.get::<String, _>("status"),
    }))
}

// ── Folios by room (check-out settlement view) ────────────────────────────
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/folios",
    responses(
        (status = 200, description = "Folio settlement view for the in-house stay in the room", body = RoomFolioView),
        (status = 400, description = "room_number required"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "No in-house stay for that room"),
    ),
    security(),
    tag = "pms",
)]

/// Open folio for the in-house stay in a room - the kiosk/eGuest check-out
/// view over the same folio rows the per-reservation route returns.
pub async fn get_folio_by_room(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<Uuid>,
    Query(params): Query<serde_json::Value>,
) -> Result<Json<RoomFolioView>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:read"),
    )
    .await?;
    let env_id = resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let room = params
        .get("room_number")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "room_number required".into()))?;
    let res = sqlx::query(
        "SELECT id FROM pms.reservations
          WHERE property_id = $1 AND assigned_room_number = $2 AND status = 'CHECKED_IN'
          ORDER BY checked_in_at DESC LIMIT 1",
    )
    .bind(property_id)
    .bind(room)
    .fetch_optional(&mut *conn)
    .await
    .map_err(super::err_db)?
    .ok_or_else(|| super::err_not_found("No in-house stay for that room"))?;
    let res_id: Uuid = res.get("id");
    let folio = sqlx::query(
        "SELECT f.id, f.status, f.payment_method, f.closed_at
           FROM pms.folios f
          WHERE f.reservation_id = $1 AND f.property_id = $2
          ORDER BY f.created_at DESC LIMIT 1",
    )
    .bind(res_id)
    .bind(property_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let folio = match folio {
        Some(f) => f,
        None => {
            return Ok(Json(RoomFolioView {
                id: None,
                reservation_id: res_id,
                room_number: room.to_string(),
                status: "NONE".into(),
                charges: Vec::new(),
                payments: Vec::new(),
                balance: "0".into(),
            }))
        }
    };
    let folio_id: Uuid = folio.get("id");
    let charges = sqlx::query(
        "SELECT id, charge_code, description, amount::text as amount, quantity, created_at
           FROM pms.folio_charges WHERE folio_id = $1 ORDER BY created_at",
    )
    .bind(folio_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let payments = sqlx::query(
        "SELECT id, payment_code, amount::text as amount, reference, created_at
           FROM pms.folio_payments WHERE folio_id = $1 ORDER BY created_at",
    )
    .bind(folio_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let total_charges: f64 = charges
        .iter()
        .map(|r| r.get::<String, _>("amount").parse::<f64>().unwrap_or(0.0))
        .sum();
    let total_payments: f64 = payments
        .iter()
        .map(|r| r.get::<String, _>("amount").parse::<f64>().unwrap_or(0.0))
        .sum();
    let balance = ((total_charges - total_payments) * 100.0).round() / 100.0;
    let status: String = folio.get("status");
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(RoomFolioView {
        id: Some(folio_id),
        reservation_id: res_id,
        room_number: room.to_string(),
        status,
        charges: charges
            .iter()
            .map(|r| FolioChargeView {
                id: r.get::<Uuid, _>("id"),
                charge_code: r.get::<String, _>("charge_code"),
                description: r.get::<String, _>("description"),
                amount: r.get::<String, _>("amount"),
                quantity: r.get::<i32, _>("quantity"),
                created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            })
            .collect(),
        payments: payments
            .iter()
            .map(|r| FolioPaymentView {
                id: r.get::<Uuid, _>("id"),
                payment_code: r.get::<String, _>("payment_code"),
                amount: r.get::<String, _>("amount"),
                reference: r.get::<Option<String>, _>("reference"),
                created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            })
            .collect(),
        balance: format!("{balance:.2}"),
    }))
}

// ── Boarding pass (check-in artifact) ─────────────────────────────────────
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/reservations/{res_id}/boarding-pass",
    responses(
        (status = 200, description = "Check-in boarding pass", body = BoardingPass),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Reservation not found"),
        (status = 409, description = "Boarding pass is issued after check-in"),
    ),
    security(),
    tag = "pms",
)]

/// Boarding pass - the check-in artifact the kiosk completion step renders
/// (room, dates, guest, key count). Computed from live rows, never stored.
pub async fn get_boarding_pass(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<BoardingPass>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:read"),
    )
    .await?;
    let env_id = resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let res = sqlx::query(
        "SELECT r.confirmation_number, r.assigned_room_number, r.arrival_date,
                r.departure_date, r.num_adults, r.status,
                g.first_name, g.last_name, p.property_name
           FROM pms.reservations r
           LEFT JOIN pms.guest_profiles g ON g.id = r.guest_profile_id
           LEFT JOIN pms.properties p ON p.id = r.property_id
          WHERE r.id = $1 AND r.property_id = $2",
    )
    .bind(res_id)
    .bind(property_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(super::err_db)?
    .ok_or_else(|| super::err_not_found("Reservation not found"))?;
    let keys = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM pms.digital_keys WHERE reservation_id = $1 AND status IN ('INACTIVE','ACTIVE')",
    )
    .bind(res_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let status: String = res.get("status");
    if status != "CHECKED_IN" {
        return Err((
            StatusCode::CONFLICT,
            format!("Boarding pass is issued after check-in (reservation is {status})"),
        ));
    }
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(BoardingPass {
        reservation_id: res_id,
        confirmation_number: res.get::<String, _>("confirmation_number"),
        guest_name: format!(
            "{} {}",
            res.get::<Option<String>, _>("first_name")
                .unwrap_or_default(),
            res.get::<Option<String>, _>("last_name")
                .unwrap_or_default()
        )
        .trim()
        .to_string(),
        property_name: res.get::<Option<String>, _>("property_name"),
        room_number: res.get::<Option<String>, _>("assigned_room_number"),
        arrival_date: res.get::<chrono::NaiveDate, _>("arrival_date"),
        departure_date: res.get::<chrono::NaiveDate, _>("departure_date"),
        num_adults: res.get::<i32, _>("num_adults"),
        key_count: keys,
        issued_at: chrono::Utc::now(),
    }))
}

// ── Stay feedback ─────────────────────────────────────────────────────────
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/feedback",
    request_body = SubmitFeedbackRequest,
    responses(
        (status = 200, description = "Submitted stay feedback", body = FeedbackView),
        (status = 400, description = "reservation_id required / rating must be 1-5"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

/// Submit (or update) stay feedback - one row per reservation.
pub async fn submit_feedback(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<Uuid>,
    Json(req): Json<SubmitFeedbackRequest>,
) -> Result<Json<FeedbackView>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:reservation:write"),
    )
    .await?;
    let env_id = resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let res_id = req.reservation_id;
    let rating = req.rating;
    if !(1..=5).contains(&rating) {
        return Err((StatusCode::BAD_REQUEST, "rating must be 1-5".into()));
    }
    let comment = req.comment.as_deref();
    let row = sqlx::query(
        "INSERT INTO pms.feedback (env_id, property_id, reservation_id, rating, comment)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (reservation_id)
         DO UPDATE SET rating = EXCLUDED.rating, comment = EXCLUDED.comment,
                       updated_at = now()
         RETURNING id, rating, comment, updated_at",
    )
    .bind(env_id)
    .bind(property_id)
    .bind(res_id)
    .bind(rating)
    .bind(comment)
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;
    emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:stay:rated",
        json!({ "reservation_id": res_id, "rating": rating }),
        &Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(FeedbackView {
        id: row.get::<Uuid, _>("id"),
        reservation_id: res_id,
        rating: row.get::<i32, _>("rating"),
        comment: row.get::<Option<String>, _>("comment"),
        updated_at: row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at"),
    }))
}
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/feedback",
    responses(
        (status = 200, description = "Stay feedback for the reservation", body = FeedbackLookup),
        (status = 400, description = "reservation_id required"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

/// Read stay feedback for a reservation.
pub async fn get_feedback(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<Uuid>,
    Query(params): Query<serde_json::Value>,
) -> Result<Json<FeedbackLookup>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:reservation:read"),
    )
    .await?;
    let env_id = resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let res_id = params
        .get("reservation_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "reservation_id required".into()))?;
    let row = sqlx::query(
        "SELECT id, rating, comment, submitted_at, updated_at
           FROM pms.feedback WHERE property_id = $1 AND reservation_id = $2",
    )
    .bind(property_id)
    .bind(res_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(super::err_db)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(match row {
        Some(r) => FeedbackLookup {
            reservation_id: res_id,
            rating: Some(r.get::<i32, _>("rating")),
            comment: r.get::<Option<String>, _>("comment"),
            submitted_at: Some(r.get::<chrono::DateTime<chrono::Utc>, _>("submitted_at")),
            updated_at: Some(r.get::<chrono::DateTime<chrono::Utc>, _>("updated_at")),
        },
        None => FeedbackLookup {
            reservation_id: res_id,
            rating: None,
            comment: None,
            submitted_at: None,
            updated_at: None,
        },
    }))
}
// ── Guest payment methods (saved bill8 token references) ──────────────────
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/payment-methods",
    responses(
        (status = 200, description = "The signed-in guest's saved payment methods", body = GuestPaymentMethodList),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

/// `GET /v1/properties/{p}/payment-methods` - the signed-in guest's saved
/// payment methods, resolved by the session subject (holder-scoped). Rows
/// carry bill8 token references only - never PAN or token secrets (DESIGN.md
/// §3 secret-reference rule).
pub async fn list_payment_methods(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<Uuid>,
) -> Result<Json<GuestPaymentMethodList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:profile:read"),
    )
    .await?;
    let env_id = resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query(
        "SELECT id, label, payment_method_id, is_default, created_at
         FROM pms.guest_payment_methods
         WHERE property_id = $1 AND sentin8_auth_user_id = $2
         ORDER BY is_default DESC, created_at DESC",
    )
    .bind(property_id)
    .bind(&a.claims.sub)
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(GuestPaymentMethodList {
        items: rows.iter().map(payment_method_from_row).collect(),
    }))
}
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/payment-methods",
    request_body = CreateGuestPaymentMethodRequest,
    responses(
        (status = 200, description = "Saved payment method", body = GuestPaymentMethod),
        (status = 400, description = "payment_method_id and label required"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

/// `POST /v1/properties/{p}/payment-methods` - save a tokenized method
/// (bill8 already holds the instrument; PMS stores the reference).
pub async fn create_payment_method(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<Uuid>,
    Json(req): Json<CreateGuestPaymentMethodRequest>,
) -> Result<Json<GuestPaymentMethod>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:profile:write"),
    )
    .await?;
    let env_id = resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    if req.payment_method_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "payment_method_id required (bill8 token reference)".into(),
        ));
    }
    let token_ref: &str = req.payment_method_id.as_str();
    let label: &str = req.label.as_str();
    if label.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "label required".into()));
    }
    let is_default = req.is_default;
    let row = sqlx::query(
        "INSERT INTO pms.guest_payment_methods (env_id, property_id, sentin8_auth_user_id, label, payment_method_id, is_default)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, label, payment_method_id, is_default, created_at",
    )
    .bind(env_id)
    .bind(property_id)
    .bind(&a.claims.sub)
    .bind(label)
    .bind(token_ref)
    .bind(is_default)
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;
    emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:payment_method:saved",
        json!({ "payment_method_id": row.get::<Uuid, _>("id"), "label": label }),
        &Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(payment_method_from_row(&row)))
}
#[utoipa::path(
    delete,
    path = "/v1/properties/{property_id}/payment-methods/{method_id}",
    responses(
        (status = 204, description = "Payment method removed"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Payment method not found"),
    ),
    security(),
    tag = "pms",
)]

/// `DELETE /v1/properties/{p}/payment-methods/{method_id}` - remove a saved
/// method (holder-scoped: only the owner's rows are deletable).
pub async fn delete_payment_method(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, method_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:profile:write"),
    )
    .await?;
    let env_id = resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let res = sqlx::query(
        "DELETE FROM pms.guest_payment_methods WHERE id = $1 AND property_id = $2 AND sentin8_auth_user_id = $3",
    )
    .bind(method_id)
    .bind(property_id)
    .bind(&a.claims.sub)
    .execute(&mut *conn)
    .await
    .map_err(super::err_db)?;
    if res.rows_affected() == 0 {
        return Err(super::err_not_found("Payment method not found"));
    }
    conn.commit().await.map_err(super::err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

fn payment_method_from_row(r: &sqlx::postgres::PgRow) -> GuestPaymentMethod {
    GuestPaymentMethod {
        id: r.get::<Uuid, _>("id"),
        label: r.get::<String, _>("label"),
        payment_method_id: r.get::<String, _>("payment_method_id"),
        is_default: r.get::<bool, _>("is_default"),
        created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    }
}

// ── Reservation ↔ guest linking (anonymous bookings → signed-in profile) ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations/{res_id}/link-guest",
    request_body = LinkGuestRequest,
    responses(
        (status = 200, description = "Guest-linking result", body = LinkGuestResult),
        (status = 400, description = "No profile bound to this session; supply target_profile_id"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Reservation not found (or has no booker profile)"),
    ),
    security(),
    tag = "pms",
)]

/// `POST /v1/properties/{p}/reservations/{res_id}/link-guest` - bind the
/// signed-in session's guest profile to a booking made anonymously in eBooking.
///
/// The binding surface is the profile chain: the anonymous booking carries the
/// booker profile row; signing in resolves the (possibly different) profile
/// the session subject owns. Linking merges the booker profile INTO the
/// session's profile via the same merge path ePMS staff use, so folio/keys/
/// requests all follow the stay.
pub async fn link_reservation_guest(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<LinkGuestRequest>,
) -> Result<Json<LinkGuestResult>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:profile:write"),
    )
    .await?;
    let env_id = resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    set_tenant_context(&mut conn, env_id).await;

    // The reservation's current booker profile.
    let booker_profile_id: Uuid = sqlx::query(
        "SELECT guest_profile_id FROM pms.reservations WHERE id = $1 AND property_id = $2 AND guest_profile_id IS NOT NULL",
    )
    .bind(res_id)
    .bind(property_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => super::err_not_found("Reservation not found (or has no booker profile)"),
        e => super::err_db(e),
    })?
    .get("guest_profile_id");

    // The signed-in guest's profile - resolved by the session subject via the
    // loyalty-number binding, or the caller-supplied target profile id.
    let target_profile_id: Uuid = match req.target_profile_id {
        Some(id) => id,
        None => sqlx::query(
            "SELECT id FROM pms.guest_profiles WHERE property_id = $1 AND preferences->>'auth_user_id' = $2 ORDER BY created_at LIMIT 1",
        )
        .bind(property_id)
        .bind(&a.claims.sub)
        .fetch_optional(&mut *conn)
        .await
        .map_err(super::err_db)?
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "no profile bound to this session; supply target_profile_id".into()))?
        .get("id"),
    };

    if booker_profile_id == target_profile_id {
        return Ok(Json(LinkGuestResult {
            linked: true,
            already_linked: true,
            reservation_id: res_id,
            guest_profile_id: target_profile_id,
            booker_profile_id: Some(booker_profile_id),
        }));
    }

    // Bind the session subject onto the target profile (the auth-user link
    // the session resolution reads back), then merge booker → target so the
    // stay's profile idchain follows the session.
    sqlx::query(
        "UPDATE pms.guest_profiles SET preferences = COALESCE(preferences, '{}'::jsonb) || jsonb_build_object('auth_user_id', $3), updated_at = now()
         WHERE id = $1 AND property_id = $2",
    )
    .bind(target_profile_id)
    .bind(property_id)
    .bind(&a.claims.sub)
    .execute(&mut *conn)
    .await
    .map_err(super::err_db)?;

    // Re-point the reservation at the session profile (the same re-point the
    // profile-merge handler runs).
    let moved = sqlx::query(
        "UPDATE pms.reservations SET guest_profile_id = $3 WHERE id = $1 AND property_id = $2 RETURNING confirmation_number",
    )
    .bind(res_id)
    .bind(property_id)
    .bind(target_profile_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;

    emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:reservation:guest_linked",
        json!({
            "reservation_id": res_id,
            "confirmation_number": moved.get::<String, _>("confirmation_number"),
            "booker_profile_id": booker_profile_id,
            "guest_profile_id": target_profile_id,
            "auth_user_id": &a.claims.sub,
        }),
        &Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;

    conn.commit().await.map_err(super::err_db)?;

    Ok(Json(LinkGuestResult {
        linked: true,
        already_linked: false,
        reservation_id: res_id,
        guest_profile_id: target_profile_id,
        booker_profile_id: Some(booker_profile_id),
    }))
}
