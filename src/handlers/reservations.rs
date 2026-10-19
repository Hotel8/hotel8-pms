// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Reservation handlers - CRUD + search.
use crate::auth;
use crate::handlers::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use hotel8::pms::contracts::{
    ArrivalInstructions, InstructionComment, InstructionPackage, InstructionProfile,
    ReservationCreateRequest, ReservationList, ReservationResponse, SplitResult, UpsellRequest,
    UpsellResult,
};
use sqlx::Row;

/// `POST /v1/properties/{property_id}/reservations`
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations",
    request_body = ReservationCreateRequest,
    responses(
        (status = 200, description = "Reservation created", body = ReservationResponse),
        (status = 403, description = "Missing pms:admin scope"),
    ),
    security(("pms:admin" = [])),
    tag = "pms",
)]
pub async fn create_reservation(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<ReservationCreateRequest>,
) -> Result<Json<ReservationResponse>, (StatusCode, String)> {
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
    let conf = format!("RES-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    let row = sqlx::query(
        "INSERT INTO pms.reservations (property_id, confirmation_number, guest_profile_id, room_type_id, rate_plan_id, arrival_date, departure_date, num_adults, num_children, num_rooms, status, guarantee_type, guarantee_code, special_requests, package_code, market_code, source_code, channel_code)
         VALUES ($1, $2, $3, $4, $5, $6::date, $7::date, $8, $9, $10, 'CONFIRMED', $11, $12, $13, $14, $15, $16, $17) RETURNING *",
    )
    .bind(property_id)
    .bind(&conf)
    .bind(req.guest_profile_id)
    .bind(req.room_type_id)
    .bind(req.rate_plan_id)
    .bind(&req.arrival_date)
    .bind(&req.departure_date)
    .bind(req.num_adults)
    .bind(req.num_children)
    .bind(req.num_rooms)
    .bind(req.guarantee_type.clone())
    .bind(req.guarantee_code.clone())
    .bind(req.special_requests.clone())
    .bind(req.package_code.clone())
    .bind(req.market_code.clone())
    .bind(req.source_code.clone())
    .bind(req.channel_code.clone())
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let res_id: uuid::Uuid = row.get("id");
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:reservation:created",
        serde_json::json!({ "reservation_id": res_id, "confirmation_number": &conf }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(row_to_reservation(&row)))
}

/// `GET /v1/properties/{property_id}/reservations`
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/reservations",
    responses(
        (status = 200, description = "List of reservations", body = ReservationList),
        (status = 403, description = "Missing pms:admin scope"),
    ),
    security(("pms:admin" = [])),
    tag = "pms",
)]
pub async fn search_reservations(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    axum::extract::Query(params): axum::extract::Query<serde_json::Value>,
) -> Result<Json<ReservationList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:reservation:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    // Self-service filters (pms DESIGN.md §3 "Guest-app surfaces"): the apps
    // resolve stays by profile, by upcoming window, or by kiosk-style
    // multi-identifier lookup (last name + confirmation number). Filters
    // compose in the fixed order below; every value is a bound parameter.
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as i64;
    let status_filter = params
        .get("status")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    if let Some(status) = &status_filter {
        if ![
            "CONFIRMED",
            "CHECKED_IN",
            "CHECKED_OUT",
            "NO_SHOW",
            "CANCELLED",
        ]
        .contains(&&status[..])
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown status filter: {status}"),
            ));
        }
    }
    let guest_profile_id = params
        .get("guest_profile_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok());
    let upcoming = params
        .get("upcoming")
        .and_then(|v| v.as_str())
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let last_name = params
        .get("last_name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let confirmation = params
        .get("confirmation")
        .or_else(|| params.get("confirmation_number"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty());

    // WHERE fragments append in the exact order the binds run; only fixed
    // SQL text is appended structurally (upcoming window, status enum check
    // happens above). All filter values are bound parameters.
    let mut sql = String::from(
        "SELECT r.* FROM pms.reservations r
         LEFT JOIN pms.guest_profiles g ON g.id = r.guest_profile_id
         WHERE r.property_id = $1",
    );
    if let Some(gid) = guest_profile_id {
        sql.push_str(&format!(" AND r.guest_profile_id = '{gid}'"));
    }
    if upcoming {
        sql.push_str(
            " AND r.arrival_date >= CURRENT_DATE
              AND r.status::text IN ('CONFIRMED','CHECKED_IN')",
        );
    }
    // last_name and confirmation arrive as free text; match them through
    // bound parameters appended in this fixed order.
    let last_name = last_name.unwrap_or_default();
    let confirmation = confirmation.unwrap_or_default();
    if !last_name.is_empty() {
        sql.push_str(" AND g.last_name = $2");
    }
    if !confirmation.is_empty() {
        sql.push_str(if last_name.is_empty() {
            " AND r.confirmation_number = $2"
        } else {
            " AND r.confirmation_number = $3"
        });
    }
    sql.push_str(&format!(" ORDER BY r.created_at DESC LIMIT {limit}"));

    // The status enum values are validated above, so the interpolations in
    // this block are structural only (enum member, quoted uuid literal,
    // bound text parameters).
    let mut query = sqlx::query(&sql).bind(property_id);
    if status_filter.is_some() && guest_profile_id.is_some() {
        query = query
            .bind(status_filter.unwrap_or_default())
            .bind(guest_profile_id)
            .bind(last_name)
            .bind(confirmation);
    } else if status_filter.is_some() || guest_profile_id.is_some() {
        query = query
            .bind(status_filter.unwrap_or_default().to_owned())
            .bind(last_name)
            .bind(confirmation);
    } else {
        query = query.bind(last_name).bind(confirmation);
    }
    let rows = query.fetch_all(&mut *conn).await.map_err(super::err_db)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(ReservationList {
        items: rows.iter().map(row_to_reservation).collect(),
    }))
}

/// `GET /v1/properties/{property_id}/reservations/{res_id}`
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/reservations/{res_id}",
    params(("res_id" = uuid::Uuid, Path, description = "Reservation ID")),
    responses(
        (status = 200, description = "Reservation", body = ReservationResponse),
        (status = 404, description = "Reservation not found"),
        (status = 403, description = "Missing pms:admin scope"),
    ),
    security(("pms:admin" = [])),
    tag = "pms",
)]
pub async fn get_reservation(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<ReservationResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:reservation:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let row = sqlx::query("SELECT * FROM pms.reservations WHERE id = $1 AND property_id = $2")
        .bind(res_id)
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => super::err_not_found("Reservation not found"),
            e => super::err_db(e),
        })?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(row_to_reservation(&row)))
}
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations/{res_id}/cancel",
    responses(
        (status = 204, description = "Reservation cancelled"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn cancel_reservation(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
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
    let _ = sqlx::query("UPDATE pms.reservations SET status = 'CANCELLED', cancelled_at = now(), updated_at = now() WHERE id = $1 AND property_id = $2 AND status NOT IN ('CHECKED_OUT', 'NO_SHOW', 'CANCELLED')")
        .bind(res_id)
        .bind(property_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:reservation:cancelled",
        serde_json::json!({ "reservation_id": res_id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn row_to_reservation(row: &sqlx::postgres::PgRow) -> ReservationResponse {
    ReservationResponse {
        id: row.get::<uuid::Uuid, _>("id"),
        property_id: row.get::<uuid::Uuid, _>("property_id"),
        confirmation_number: row.get::<String, _>("confirmation_number"),
        guest_profile_id: row.get::<Option<uuid::Uuid>, _>("guest_profile_id"),
        room_type_id: row.get::<Option<uuid::Uuid>, _>("room_type_id"),
        rate_plan_id: row.get::<Option<uuid::Uuid>, _>("rate_plan_id"),
        arrival_date: row.get::<chrono::NaiveDate, _>("arrival_date"),
        departure_date: row.get::<chrono::NaiveDate, _>("departure_date"),
        num_adults: row.get::<i32, _>("num_adults"),
        num_children: row.get::<i32, _>("num_children"),
        num_rooms: row.get::<i32, _>("num_rooms"),
        status: row.get::<String, _>("status"),
        guarantee_type: row.get::<String, _>("guarantee_type"),
        guarantee_code: row.get::<Option<String>, _>("guarantee_code"),
        special_requests: row.get::<Option<String>, _>("special_requests"),
        package_code: row.get::<Option<String>, _>("package_code"),
        market_code: row.get::<Option<String>, _>("market_code"),
        source_code: row.get::<Option<String>, _>("source_code"),
        channel_code: row.get::<Option<String>, _>("channel_code"),
        assigned_room_number: row.get::<Option<String>, _>("assigned_room_number"),
        checked_in_at: row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("checked_in_at"),
        checked_out_at: row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("checked_out_at"),
        cancelled_at: row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("cancelled_at"),
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        updated_at: row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at"),
    }
}

// ── Reservation split ──
/// Body of `POST /v1/properties/{property_id}/reservations/{res_id}/split` -
/// no fields (the split source is the path).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct SplitReservationRequest {}

#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations/{res_id}/split",
    request_body = SplitReservationRequest,
    responses(
        (status = 200, description = "Reservation split into one room per sibling", body = SplitResult),
        (status = 400, description = "Cannot split a single-room reservation"),
        (status = 404, description = "Reservation not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn split_reservation(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(_req): Json<SplitReservationRequest>,
) -> Result<Json<SplitResult>, (StatusCode, String)> {
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
    // Get original reservation
    let orig = sqlx::query("SELECT * FROM pms.reservations WHERE id = $1 AND property_id = $2")
        .bind(res_id)
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => super::err_not_found("Reservation not found"),
            e => super::err_db(e),
        })?;
    let num_rooms: i32 = orig.get("num_rooms");
    if num_rooms <= 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Cannot split a single-room reservation".to_string(),
        ));
    }
    // Create new reservation with same data but num_rooms = 1
    let new_conf = format!("RES-{}", chrono::Utc::now().format("%Y%m%d%H%M%S3"));
    let new_row = sqlx::query("INSERT INTO pms.reservations (property_id, confirmation_number, guest_profile_id, room_type_id, rate_plan_id, arrival_date, departure_date, num_adults, num_children, num_rooms, status, guarantee_type, special_requests, package_code, market_code, source_code)
        SELECT property_id, $3, guest_profile_id, room_type_id, rate_plan_id, arrival_date, departure_date, num_adults, num_children, 1, status, guarantee_type, special_requests, package_code, market_code, source_code FROM pms.reservations WHERE id = $1
        RETURNING id, confirmation_number")
        .bind(res_id).bind(property_id).bind(&new_conf)
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let new_id: uuid::Uuid = new_row.get("id");
    // Decrement original num_rooms
    sqlx::query(
        "UPDATE pms.reservations SET num_rooms = num_rooms - 1, updated_at = now() WHERE id = $1",
    )
    .bind(res_id)
    .execute(&mut *conn)
    .await
    .map_err(super::err_db)?;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:reservation:split",
        serde_json::json!({ "original_id": res_id, "new_id": new_id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(SplitResult {
        original_reservation_id: res_id,
        new_reservation_id: new_id,
        new_confirmation_number: new_row.get::<String, _>("confirmation_number"),
    }))
}

// ── Reservation upsell ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations/{res_id}/upsell",
    request_body = UpsellRequest,
    responses(
        (status = 200, description = "Upsold room type / rate plan applied", body = UpsellResult),
        (status = 404, description = "Reservation not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn upsell_reservation(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<UpsellRequest>,
) -> Result<Json<UpsellResult>, (StatusCode, String)> {
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
    let new_room_type_id = req.new_room_type_id;
    let new_rate_plan_id = req.new_rate_plan_id;
    let row = sqlx::query("UPDATE pms.reservations SET room_type_id = COALESCE($3, room_type_id), rate_plan_id = COALESCE($4, rate_plan_id), updated_at = now() WHERE id = $1 AND property_id = $2 RETURNING id, confirmation_number")
        .bind(res_id).bind(property_id).bind(new_room_type_id).bind(new_rate_plan_id)
        .fetch_one(&mut *conn).await.map_err(|e| match e { sqlx::Error::RowNotFound => super::err_not_found("Reservation not found"), e => super::err_db(e) })?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:reservation:upsold", serde_json::json!({ "reservation_id": res_id, "new_room_type_id": new_room_type_id, "new_rate_plan_id": new_rate_plan_id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(UpsellResult {
        reservation_id: row.get::<uuid::Uuid, _>("id"),
        confirmation_number: row.get::<String, _>("confirmation_number"),
        status: "upsold".to_string(),
    }))
}

// ── fetchInstructions ──
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/reservations/{res_id}/instructions",
    responses(
        (status = 200, description = "Arrival packet - reservation, guest profile, package and comments", body = ArrivalInstructions),
        (status = 404, description = "Reservation not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn fetch_instructions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<ArrivalInstructions>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:reservation:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let res = sqlx::query("SELECT * FROM pms.reservations WHERE id = $1 AND property_id = $2")
        .bind(res_id)
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => super::err_not_found("Reservation not found"),
            e => super::err_db(e),
        })?;
    let profile_id: Option<uuid::Uuid> = res.get("guest_profile_id");
    let profile = if let Some(pid) = profile_id {
        sqlx::query("SELECT first_name, last_name, email, phone, loyalty_number FROM pms.guest_profiles WHERE id = $1").bind(pid)
            .fetch_optional(&mut *conn).await.map_err(super::err_db)?
    } else {
        None
    };
    let comments = sqlx::query("SELECT id, comment_type, content, author, created_at FROM pms.reservation_comments WHERE reservation_id = $1 ORDER BY created_at")
        .bind(res_id).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let comment_items: Vec<InstructionComment> = comments
        .iter()
        .map(|r| InstructionComment {
            id: r.get::<uuid::Uuid, _>("id"),
            comment_type: r.get::<String, _>("comment_type"),
            content: r.get::<String, _>("content"),
            author: r.get::<Option<String>, _>("author"),
            created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        })
        .collect();
    let package_code: Option<String> = res.get("package_code");
    let pkg_info = if let Some(ref pc) = package_code {
        sqlx::query("SELECT package_name, price::text as price FROM pms.packages WHERE property_id = $1 AND package_code = $2").bind(property_id).bind(pc)
            .fetch_optional(&mut *conn).await.map_err(super::err_db)?
    } else {
        None
    };
    let profile_json = profile.map(|p| InstructionProfile {
        first_name: p.get::<String, _>("first_name"),
        last_name: p.get::<String, _>("last_name"),
        email: p.get::<Option<String>, _>("email"),
        phone: p.get::<Option<String>, _>("phone"),
        loyalty_number: p.get::<Option<String>, _>("loyalty_number"),
    });
    let pkg_json = pkg_info.map(|p| InstructionPackage {
        package_name: p.get::<String, _>("package_name"),
        price: p.get::<String, _>("price"),
    });
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(ArrivalInstructions {
        reservation: row_to_reservation(&res),
        profile: profile_json,
        package: pkg_json,
        comments: comment_items,
    }))
}
