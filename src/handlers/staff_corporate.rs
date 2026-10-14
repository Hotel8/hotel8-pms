// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Staff & corporate surface handlers — reservation edit, walk-in booking,
//! company payment methods (credit approval), company user bindings, and
//! kiosk terminal config.
//!
//! Contract: `services/pms/DESIGN.md` §3 "Staff & corporate surfaces" and §4
//! (public surface list). Every handler follows the standard pipeline:
//! verify → Shield require → tenant context → explicit `property_id` clause →
//! outbox event.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sqlx::Row;

use crate::auth;
use crate::handlers::AppState;

// ── Reservation edit (PUT) ──────────────────────────────────────────────────

/// `PUT /v1/properties/{property_id}/reservations/{res_id}` — pre-arrival edit.
///
/// Edits dates, occupancy, room type, rate plan, and special requests.
/// Terminal-status reservations (`CANCELLED`, `CHECKED_OUT`, `NO_SHOW`) refuse
/// edits with 409 — the state machine forbids mutating history.
pub async fn update_reservation(
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
        sentin8::shield::EvalTarget::new("hotel8:pms:reservation:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;

    // Refuse edits on terminal statuses (state machine guard, DESIGN.md §3).
    let status: String = sqlx::query(
        "SELECT status::text AS status FROM pms.reservations WHERE id = $1 AND property_id = $2",
    )
    .bind(res_id)
    .bind(property_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => super::err_not_found("Reservation not found"),
        e => super::err_db(e),
    })?
    .get("status");
    if matches!(status.as_str(), "CANCELLED" | "CHECKED_OUT" | "NO_SHOW") {
        return Err((
            StatusCode::CONFLICT,
            format!("reservation is {status}; only pre-arrival reservations can be edited"),
        ));
    }

    let row = sqlx::query(
        "UPDATE pms.reservations SET
            arrival_date = COALESCE($3::date, arrival_date),
            departure_date = COALESCE($4::date, departure_date),
            num_adults = COALESCE($5, num_adults),
            num_children = COALESCE($6, num_children),
            num_rooms = COALESCE($7, num_rooms),
            room_type_id = COALESCE($8, room_type_id),
            rate_plan_id = COALESCE($9, rate_plan_id),
            special_requests = COALESCE($10, special_requests),
            updated_at = now()
         WHERE id = $1 AND property_id = $2
         RETURNING *",
    )
    .bind(res_id)
    .bind(property_id)
    .bind(req.get("arrival_date").and_then(|v| v.as_str()))
    .bind(req.get("departure_date").and_then(|v| v.as_str()))
    .bind(
        req.get("num_adults")
            .and_then(|v| v.as_u64())
            .map(|v| v as i32),
    )
    .bind(
        req.get("num_children")
            .and_then(|v| v.as_u64())
            .map(|v| v as i32),
    )
    .bind(
        req.get("num_rooms")
            .and_then(|v| v.as_u64())
            .map(|v| v as i32),
    )
    .bind(
        req.get("room_type_id")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok()),
    )
    .bind(
        req.get("rate_plan_id")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok()),
    )
    .bind(req.get("special_requests").and_then(|v| v.as_str()))
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;

    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:reservation:updated",
        serde_json::json!({ "reservation_id": res_id, "confirmation_number": row.get::<String, _>("confirmation_number") }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(super::reservations::row_to_json(&row)))
}

// ── Walk-in booking (kiosk express booking) ─────────────────────────────────

/// `POST /v1/properties/{property_id}/walk-in` — kiosk express booking.
///
/// Creates a `CONFIRMED` reservation from an available room type + guest name
/// (`source_code = 'WALKIN'`, `channel_code = 'KIOSK'`). The kiosk then
/// check-ins via the normal route. Refuses when the room type has no
/// availability for the requested window.
pub async fn create_walk_in(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:reservation:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;

    let room_type_id: uuid::Uuid = req
        .get("room_type_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| super::err_bad_request("room_type_id required"))?;
    let arrival = req
        .get("arrival_date")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let departure = req
        .get("departure_date")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let last_name = req
        .get("last_name")
        .and_then(|v| v.as_str())
        .unwrap_or("Walk-in");
    let first_name = req.get("first_name").and_then(|v| v.as_str()).unwrap_or("");
    let num_rooms = req.get("num_rooms").and_then(|v| v.as_u64()).unwrap_or(1) as i32;
    if arrival.is_empty() || departure.is_empty() {
        return Err(super::err_bad_request(
            "arrival_date and departure_date required",
        ));
    }

    // Availability gate — never oversell (DESIGN.md §8).
    let rt = sqlx::query(
        "SELECT rt.room_type_code,
                COALESCE((SELECT MIN(i.available_rooms)::int FROM pms.inventory i
                          WHERE i.property_id = rt.property_id AND i.room_type_id = rt.id
                            AND i.date >= $2::date AND i.date < $3::date),
                         (SELECT COUNT(*)::int FROM pms.rooms r
                          WHERE r.room_type_id = rt.id
                            AND r.housekeeping_status NOT IN ('OUT_OF_ORDER','OUT_OF_SERVICE'))) AS available
         FROM pms.room_types rt WHERE rt.id = $4 AND rt.property_id = $1",
    )
    .bind(property_id)
    .bind(arrival)
    .bind(departure)
    .bind(room_type_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => super::err_not_found("Room type not found"),
        e => super::err_db(e),
    })?;
    let available: i32 = rt.get("available");
    if available < num_rooms {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "room type sold out for the window (available {available}, requested {num_rooms})"
            ),
        ));
    }

    // Ensure a guest profile row for the walk-in guest.
    let profile_id: uuid::Uuid = sqlx::query(
        "INSERT INTO pms.guest_profiles (property_id, profile_type, first_name, last_name)
         VALUES ($1, 'GUEST', $2, $3) RETURNING id",
    )
    .bind(property_id)
    .bind(first_name)
    .bind(last_name)
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?
    .get("id");

    let conf = format!("WLK-{}", chrono::Utc::now().format("%Y%m%d%H%M%S%3f"));
    let row = sqlx::query(
        "INSERT INTO pms.reservations (property_id, confirmation_number, guest_profile_id, room_type_id, arrival_date, departure_date, num_adults, num_children, num_rooms, status, guarantee_type, source_code, channel_code)
         VALUES ($1, $2, $3, $4, $5::date, $6::date, 1, 0, $7, 'CONFIRMED', 'CCG', 'WALKIN', 'KIOSK') RETURNING *",
    )
    .bind(property_id)
    .bind(&conf)
    .bind(profile_id)
    .bind(room_type_id)
    .bind(arrival)
    .bind(departure)
    .bind(num_rooms)
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let res_id: uuid::Uuid = row.get("id");

    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:reservation:created",
        serde_json::json!({ "reservation_id": res_id, "confirmation_number": &conf, "source_code": "WALKIN" }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;

    conn.commit().await.map_err(super::err_db)?;

    Ok(Json(serde_json::json!({
        "id": res_id,
        "confirmation_number": conf,
        "guest_profile_id": profile_id,
        "room_type_code": rt.get::<String, _>("room_type_code"),
        "arrival_date": row.get::<chrono::NaiveDate, _>("arrival_date"),
        "departure_date": row.get::<chrono::NaiveDate, _>("departure_date"),
        "status": "CONFIRMED",
    })))
}

// ── Corporate payment methods (credit approval) ─────────────────────────────

/// `GET /v1/properties/{property_id}/companies/{profile_id}/payment-methods` —
/// credit-approved methods for a company profile. Checkout surfaces the
/// `POSTPAY`/`BILL_TO_COMPANY` rows; everything else is bookkeeping.
pub async fn list_company_payment_methods(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, profile_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    axum::extract::Query(params): axum::extract::Query<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:profile:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let approved_only = params.get("approved_only").and_then(|v| v.as_str()) == Some("true");
    let where_clause = if approved_only {
        "AND approval IN ('POSTPAY','BILL_TO_COMPANY')"
    } else {
        ""
    };
    let sql = format!(
        "SELECT id, company_profile_id, label, payment_method_id, approval, credit_limit::text AS credit_limit, approved_at, created_at
         FROM pms.company_payment_methods WHERE property_id = $1 AND company_profile_id = $2 {where_clause} ORDER BY created_at"
    );
    let rows = sqlx::query(&sql)
        .bind(property_id)
        .bind(profile_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "items": rows.iter().map(company_method_json).collect::<Vec<_>>() }),
    ))
}

/// `POST .../companies/{profile_id}/payment-methods` — hotel sales registers a
/// method or approves a pending one (admin surface).
pub async fn create_company_payment_method(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, profile_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:profile:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;

    // The company profile must exist and be a COMPANY row.
    let _ = sqlx::query("SELECT id FROM pms.guest_profiles WHERE id = $1 AND property_id = $2 AND profile_type = 'COMPANY'")
        .bind(profile_id)
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => super::err_not_found("Company profile not found"),
            e => super::err_db(e),
        })?;

    let approval = req
        .get("approval")
        .and_then(|v| v.as_str())
        .unwrap_or("PENDING");
    if !["PENDING", "POSTPAY", "BILL_TO_COMPANY", "REJECTED"].contains(&approval) {
        return Err(super::err_bad_request(&format!(
            "unknown approval: {approval}"
        )));
    }
    let label = req
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("Corporate account");
    let row = sqlx::query(
        "INSERT INTO pms.company_payment_methods (property_id, company_profile_id, label, payment_method_id, approval, credit_limit, approved_at)
         VALUES ($1, $2, $3, $4, $5, NULLIF($6,'')::numeric, CASE WHEN $5 IN ('POSTPAY','BILL_TO_COMPANY') THEN now() ELSE NULL END)
         ON CONFLICT (company_profile_id, label) DO UPDATE
            SET payment_method_id = EXCLUDED.payment_method_id,
                approval = EXCLUDED.approval,
                credit_limit = EXCLUDED.credit_limit,
                approved_at = EXCLUDED.approved_at,
                updated_at = now()
         RETURNING id, company_profile_id, label, payment_method_id, approval, credit_limit::text AS credit_limit, approved_at, created_at",
    )
    .bind(property_id)
    .bind(profile_id)
    .bind(label)
    .bind(req.get("payment_method_id").and_then(|v| v.as_str()))
    .bind(approval)
    .bind(req.get("credit_limit").and_then(|v| v.as_str()).unwrap_or(""))
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;

    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:company:method_updated",
        serde_json::json!({ "company_profile_id": profile_id, "label": label, "approval": approval }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(company_method_json(&row)))
}

fn company_method_json(r: &sqlx::postgres::PgRow) -> serde_json::Value {
    serde_json::json!({
        "id": r.get::<uuid::Uuid, _>("id"),
        "company_profile_id": r.get::<uuid::Uuid, _>("company_profile_id"),
        "label": r.get::<String, _>("label"),
        "payment_method_id": r.get::<Option<String>, _>("payment_method_id"),
        "approval": r.get::<String, _>("approval"),
        "credit_limit": r.get::<Option<String>, _>("credit_limit"),
        "approved_at": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("approved_at"),
        "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    })
}

// ── Company user bindings (multi-company travelers) ─────────────────────────

/// `GET .../companies/{profile_id}/users` — the company's traveler roster.
pub async fn list_company_users(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, profile_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:profile:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query(
        "SELECT cu.id, cu.company_profile_id, cu.traveler_profile_id, cu.role_at_company, cu.is_default, cu.created_at,
                tp.first_name, tp.last_name, tp.email
         FROM pms.company_users cu
         JOIN pms.guest_profiles tp ON tp.id = cu.traveler_profile_id
         WHERE cu.property_id = $1 AND cu.company_profile_id = $2
         ORDER BY cu.created_at",
    )
    .bind(property_id)
    .bind(profile_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<uuid::Uuid, _>("id"),
                "company_profile_id": r.get::<uuid::Uuid, _>("company_profile_id"),
                "traveler_profile_id": r.get::<uuid::Uuid, _>("traveler_profile_id"),
                "traveler_name": format!("{} {}", r.get::<String, _>("first_name"), r.get::<String, _>("last_name")),
                "email": r.get::<Option<String>, _>("email"),
                "role_at_company": r.get::<String, _>("role_at_company"),
                "is_default": r.get::<bool, _>("is_default"),
                "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

/// `POST .../companies/{profile_id}/users` — bind a traveler to the company.
pub async fn create_company_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, profile_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:profile:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;

    let traveler_id: uuid::Uuid = req
        .get("traveler_profile_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| super::err_bad_request("traveler_profile_id required"))?;
    let role = req
        .get("role_at_company")
        .and_then(|v| v.as_str())
        .unwrap_or("TRAVELER");
    if !["ADMIN", "BOOKING_AGENT", "TRAVELER"].contains(&role) {
        return Err(super::err_bad_request(&format!(
            "unknown role_at_company: {role}"
        )));
    }
    let is_default = req
        .get("is_default")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let row = sqlx::query(
        "INSERT INTO pms.company_users (property_id, company_profile_id, traveler_profile_id, role_at_company, is_default)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (company_profile_id, traveler_profile_id) DO UPDATE
            SET role_at_company = EXCLUDED.role_at_company, is_default = EXCLUDED.is_default
         RETURNING id, company_profile_id, traveler_profile_id, role_at_company, is_default, created_at",
    )
    .bind(property_id)
    .bind(profile_id)
    .bind(traveler_id)
    .bind(role)
    .bind(is_default)
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;

    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:company:user_bound",
        serde_json::json!({ "company_profile_id": profile_id, "traveler_profile_id": traveler_id, "role": role }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "id": row.get::<uuid::Uuid, _>("id"),
        "company_profile_id": row.get::<uuid::Uuid, _>("company_profile_id"),
        "traveler_profile_id": row.get::<uuid::Uuid, _>("traveler_profile_id"),
        "role_at_company": row.get::<String, _>("role_at_company"),
        "is_default": row.get::<bool, _>("is_default"),
        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    })))
}

/// `GET /v1/properties/{property_id}/companies/by-traveler/{profile_id}` — the
/// companies a traveler is bound to (multi-company session switcher).
pub async fn list_companies_for_traveler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, traveler_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:profile:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query(
        "SELECT cp.id, cp.company_name, cu.role_at_company, cu.is_default
         FROM pms.company_users cu
         JOIN pms.guest_profiles cp ON cp.id = cu.company_profile_id
         WHERE cu.property_id = $1 AND cu.traveler_profile_id = $2
         ORDER BY cu.is_default DESC, cp.company_name",
    )
    .bind(property_id)
    .bind(traveler_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "company_profile_id": r.get::<uuid::Uuid, _>("id"),
                "company_name": r.get::<String, _>("company_name"),
                "role_at_company": r.get::<String, _>("role_at_company"),
                "is_default": r.get::<bool, _>("is_default"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

// ── Kiosk terminal config ───────────────────────────────────────────────────

/// `GET .../kiosk-config` — the terminal's mode menu source of truth (eKiosk
/// bootstrap read). Defaults are materialized on first read so the terminal
/// always gets a row.
pub async fn get_kiosk_config(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
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
    let row = kiosk_config_row(&mut conn, property_id, env_id).await?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(kiosk_config_json(&row)))
}

/// `PUT .../kiosk-config` — admin RFW settings mutation (`hotel8:pms:admin`).
pub async fn update_kiosk_config(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
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

    let modes: Vec<String> = req
        .get("enabled_modes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    for m in &modes {
        if !["CHECK_IN", "CHECK_OUT", "COLLECT_KEY", "WALK_IN"].contains(&m.as_str()) {
            return Err(super::err_bad_request(&format!("unknown kiosk mode: {m}")));
        }
    }
    let defaults = vec![
        "CHECK_IN".to_string(),
        "CHECK_OUT".to_string(),
        "COLLECT_KEY".to_string(),
    ];
    let modes = if modes.is_empty() { defaults } else { modes };
    let addon_codes: Vec<String> = req
        .get("addon_package_codes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let max_keys = req
        .get("max_keys_per_stay")
        .and_then(|v| v.as_u64())
        .unwrap_or(4) as i32;
    let lockdown = req
        .get("lockdown")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    kiosk_config_row(&mut conn, property_id, env_id).await?;
    let row = sqlx::query(
        "UPDATE pms.kiosk_config SET enabled_modes = $2, addon_package_codes = $3, max_keys_per_stay = $4, lockdown = $5, updated_at = now()
         WHERE property_id = $1 RETURNING *",
    )
    .bind(property_id)
    .bind(&modes)
    .bind(&addon_codes)
    .bind(max_keys)
    .bind(lockdown)
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;

    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:kiosk:config_updated",
        serde_json::json!({ "property_id": property_id, "enabled_modes": modes, "lockdown": lockdown }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(kiosk_config_json(&row)))
}

// ── SSO-free first-admin provisioning (ECRP-3) ─────────────────────────────

/// `GET .../companies/{profile_id}/admin-provisioning` — whether the company
/// still needs its first corporate admin provisioned (no IdP + no bound
/// ADMIN user). The corporate login page reads this after company-code
/// verification to decide between the normal login and the provisioning flow.
pub async fn get_company_admin_provisioning(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, profile_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:profile:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let cp = sqlx::query("SELECT id, company_name, preferences FROM pms.guest_profiles WHERE id = $1 AND property_id = $2 AND profile_type = 'COMPANY'")
        .bind(profile_id)
        .bind(property_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(super::err_db)?
        .ok_or_else(|| super::err_not_found("Company profile not found"))?;
    let prefs: serde_json::Value = cp.get("preferences");
    let has_idp = prefs.get("sso_provider").and_then(|v| v.as_str()).is_some();
    let admin_count: i64 = sqlx::query(
        "SELECT COUNT(*)::bigint FROM pms.company_users WHERE property_id = $1 AND company_profile_id = $2 AND role_at_company = 'ADMIN'",
    )
    .bind(property_id)
    .bind(profile_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?
    .get(0);
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "company_profile_id": profile_id,
        "requires_provisioning": admin_count == 0 && !has_idp,
        "has_idp": has_idp,
        "admin_count": admin_count,
    })))
}

/// `PUT .../companies/{profile_id}/admin-provisioning` — provision the first
/// corporate admin: binds the traveler (created on the fly when needed) as
/// `ADMIN` and stamps `preferences.provisioned_admin_at`. Idempotent —
/// re-provisioning an already-admin company is a no-op returning the
/// existing state with `already_provisioned: true`.
pub async fn provision_company_admin(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, profile_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:profile:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;

    let cp = sqlx::query("SELECT id, preferences FROM pms.guest_profiles WHERE id = $1 AND property_id = $2 AND profile_type = 'COMPANY'")
        .bind(profile_id)
        .bind(property_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(super::err_db)?
        .ok_or_else(|| super::err_not_found("Company profile not found"))?;
    let prefs: serde_json::Value = cp.get("preferences");
    let has_idp = prefs.get("sso_provider").and_then(|v| v.as_str()).is_some();
    let admin_count: i64 = sqlx::query(
        "SELECT COUNT(*)::bigint FROM pms.company_users WHERE property_id = $1 AND company_profile_id = $2 AND role_at_company = 'ADMIN'",
    )
    .bind(property_id)
    .bind(profile_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?
    .get(0);
    if has_idp || admin_count > 0 {
        conn.commit().await.map_err(super::err_db)?;
        return Ok(Json(serde_json::json!({
            "company_profile_id": profile_id,
            "already_provisioned": true,
            "requires_provisioning": false,
        })));
    }

    // Resolve or create the first admin's traveler profile by email.
    let email = req
        .get("email")
        .and_then(|v| v.as_str())
        .and_then(some_nonempty)
        .ok_or_else(|| super::err_bad_request("email required"))?;
    let first_name = req.get("first_name").and_then(|v| v.as_str()).unwrap_or("");
    let last_name = req
        .get("last_name")
        .and_then(|v| v.as_str())
        .unwrap_or("Admin");
    let existing: Option<uuid::Uuid> = sqlx::query(
        "SELECT id FROM pms.guest_profiles WHERE property_id = $1 AND profile_type = 'GUEST' AND lower(email) = lower($2) LIMIT 1",
    )
    .bind(property_id)
    .bind(&email)
    .fetch_optional(&mut *conn)
    .await
    .map_err(super::err_db)?
    .map(|r| r.get("id"));
    let traveler_id: uuid::Uuid = match existing {
        Some(id) => id,
        None => {
            let inserted = sqlx::query(
                "INSERT INTO pms.guest_profiles (property_id, profile_type, first_name, last_name, email) VALUES ($1, 'GUEST', $2, $3, $4) RETURNING id",
            )
            .bind(property_id)
            .bind(first_name)
            .bind(last_name)
            .bind(&email)
            .fetch_one(&mut *conn)
            .await
            .map_err(super::err_db)?;
            inserted.get("id")
        }
    };

    sqlx::query(
        "INSERT INTO pms.company_users (property_id, company_profile_id, traveler_profile_id, role_at_company, is_default) VALUES ($1, $2, $3, 'ADMIN', true)",
    )
    .bind(property_id)
    .bind(profile_id)
    .bind(traveler_id)
    .execute(&mut *conn)
    .await
    .map_err(super::err_db)?;
    sqlx::query(
        "UPDATE pms.guest_profiles SET preferences = COALESCE(preferences, '{}'::jsonb) || jsonb_build_object('provisioned_admin_at', to_jsonb(now())) WHERE id = $1",
    )
    .bind(profile_id)
    .execute(&mut *conn)
    .await
    .map_err(super::err_db)?;

    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:company:admin_provisioned",
        serde_json::json!({ "company_profile_id": profile_id, "traveler_profile_id": traveler_id, "role": "ADMIN" }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "company_profile_id": profile_id,
        "traveler_profile_id": traveler_id,
        "already_provisioned": false,
        "requires_provisioning": false,
    })))
}

fn some_nonempty(s: &str) -> Option<String> {
    if s.trim().is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Read the config row, materializing the default row on first access
/// (invariant: the terminal always gets a config).
async fn kiosk_config_row(
    conn: &mut sqlx::PgConnection,
    property_id: uuid::Uuid,
    env_id: uuid::Uuid,
) -> Result<sqlx::postgres::PgRow, (StatusCode, String)> {
    sqlx::query(
        "INSERT INTO pms.kiosk_config (property_id, env_id) VALUES ($1, $2)
         ON CONFLICT (property_id) DO NOTHING",
    )
    .bind(property_id)
    .bind(env_id)
    .execute(&mut *conn)
    .await
    .map_err(super::err_db)?;
    sqlx::query("SELECT * FROM pms.kiosk_config WHERE property_id = $1")
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => super::err_not_found("Kiosk config not found"),
            e => super::err_db(e),
        })
}

fn kiosk_config_json(r: &sqlx::postgres::PgRow) -> serde_json::Value {
    let modes: Vec<String> = r.get("enabled_modes");
    let addons: Vec<String> = r.get("addon_package_codes");
    serde_json::json!({
        "property_id": r.get::<uuid::Uuid, _>("property_id"),
        "enabled_modes": modes,
        "addon_package_codes": addons,
        "max_keys_per_stay": r.get::<i32, _>("max_keys_per_stay"),
        "lockdown": r.get::<bool, _>("lockdown"),
        "updated_at": r.get::<chrono::DateTime<chrono::Utc>, _>("updated_at"),
    })
}
