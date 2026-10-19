// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Admin data + form-submit endpoints - the live backends behind the RFW admin
//! pages (`/v1/admin/ui/{page}` declares `data_endpoint: /v1/admin/{resource}`).
//!
//! Contract: `services/pms/DESIGN.md` §4 "Admin/RFU" - table GETs return
//! RLS-filtered JSON for the RFW DataTable; submit aliases (POST create,
//! POST-alias updates/deletes) reuse the public domain handlers so admin and
//! staff paths share one business rule set. Scope enforcement (Shield step 5):
//! each resource carries its `read` (GET) / `write` (POST) action - the same
//! actions the scope-mirror set permits.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sqlx::Row;

use crate::auth;
use crate::handlers::AppState;
#[utoipa::path(
    get,
    path = "/v1/admin/{property_id}/{resource}",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms-admin",
)]

/// `GET /v1/admin/{resource}` - admin data for the RFW tables. Each resource
/// maps to its Shield `read` action; unknown resources 404.
pub async fn get_admin_data(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Path(resource): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    let action = action_for(&resource, false)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new(action),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    match resource.as_str() {
        "reservations" => admin_rows(
            &mut conn,
            "SELECT r.id::text, r.confirmation_number, COALESCE(g.first_name || ' ' || g.last_name, '') AS guest_name,
                    r.status::text AS status, r.arrival_date::text AS check_in, r.departure_date::text AS check_out, r.num_rooms::text AS num_rooms
             FROM pms.reservations r LEFT JOIN pms.guest_profiles g ON g.id = r.guest_profile_id
             WHERE r.property_id = $1 ORDER BY r.created_at DESC LIMIT 200",
            property_id,
            &["id", "confirmation_number", "guest_name", "status", "check_in", "check_out", "num_rooms"],
        )
        .await,
        "frontdesk" => admin_rows(
            &mut conn,
            "SELECT r.id::text, r.confirmation_number, COALESCE(g.first_name || ' ' || g.last_name, '') AS guest_name,
                    r.status::text AS status, COALESCE(r.assigned_room_number, '') AS room, COALESCE(r.checked_in_at::text, '') AS checked_in_at
             FROM pms.reservations r LEFT JOIN pms.guest_profiles g ON g.id = r.guest_profile_id
             WHERE r.property_id = $1 AND r.status IN ('CONFIRMED','CHECKED_IN','CHECKED_OUT')
             ORDER BY r.arrival_date LIMIT 200",
            property_id,
            &["id", "confirmation_number", "guest_name", "status", "room", "checked_in_at"],
        )
        .await,
        "housekeeping" => admin_rows(
            &mut conn,
            "SELECT room_number, front_office_status::text AS fo_status, housekeeping_status::text AS status, '' AS assigned_to
             FROM pms.rooms WHERE property_id = $1 ORDER BY room_number",
            property_id,
            &["room_number", "fo_status", "status", "assigned_to"],
        )
        .await,
        "rates" => admin_rows(
            &mut conn,
            "SELECT id::text, rate_plan_code, rate_plan_name, rate_category, currency_code,
                    is_active::text AS active, COALESCE(min_los::text, '') AS min_los, is_negotiated::text AS negotiated
             FROM pms.rate_plans WHERE property_id = $1 ORDER BY rate_plan_code",
            property_id,
            &["id", "rate_plan_code", "rate_plan_name", "rate_category", "currency_code", "active", "min_los", "negotiated"],
        )
        .await,
        "blocks" => admin_rows(
            &mut conn,
            "SELECT id::text, block_code, block_name, blocked_rooms::text AS blocked_rooms, status::text AS status, start_date::text AS start_date, end_date::text AS end_date
             FROM pms.blocks WHERE property_id = $1 ORDER BY created_at DESC LIMIT 100",
            property_id,
            &["id", "block_code", "block_name", "blocked_rooms", "status", "start_date", "end_date"],
        )
        .await,
        "events" => admin_rows(
            &mut conn,
            "SELECT id::text, event_code, event_name, event_type, status::text AS status,
                    start_date::text AS start_date, end_date::text AS end_date, expected_attendees::text AS expected_attendees
             FROM pms.events WHERE property_id = $1 ORDER BY start_date DESC LIMIT 100",
            property_id,
            &["id", "event_code", "event_name", "event_type", "status", "start_date", "end_date", "expected_attendees"],
        )
        .await,
        "profiles" => admin_rows(
            &mut conn,
            "SELECT id::text, profile_type::text AS profile_type,
                     TRIM(first_name || ' ' || last_name) AS guest_name, COALESCE(email, '') AS email,
                     COALESCE(company_name, '') AS company_name, COALESCE(loyalty_number, '') AS loyalty_number, vip_status::text AS vip_status
             FROM pms.guest_profiles WHERE property_id = $1 ORDER BY last_name, first_name LIMIT 200",
            property_id,
            &["id", "profile_type", "guest_name", "email", "company_name", "loyalty_number", "vip_status"],
        )
        .await,
        "reports" => {
            // Aggregate card data - occupancy by date for the reporting page.
            let rows = sqlx::query(
                "SELECT arrival_date::text AS date, COUNT(*)::int AS reservations,
                        COALESCE(SUM(num_adults + num_children), 0)::int AS guests
                 FROM pms.reservations WHERE property_id = $1 AND status NOT IN ('CANCELLED')
                 GROUP BY arrival_date ORDER BY arrival_date DESC LIMIT 60",
            )
            .bind(property_id)
            .fetch_all(&mut *conn)
            .await
            .map_err(super::err_db)?;
            conn.commit().await.map_err(super::err_db)?;
            Ok(Json(serde_json::Value::Array(
                rows.iter()
                    .map(|r| {
                        serde_json::json!({
                            "date": r.get::<String, _>("date"),
                            "reservations": r.get::<i32, _>("reservations"),
                            "guests": r.get::<i32, _>("guests"),
                        })
                    })
                    .collect(),
            )))
        }
        "settings" => {
            let row = sqlx::query("SELECT property_code, property_name, timezone, currency_code, languages FROM pms.properties WHERE id = $1")
                .bind(property_id)
                .fetch_one(&mut *conn)
                .await
                .map_err(|e| match e {
                    sqlx::Error::RowNotFound => super::err_not_found("Property not found"),
                    e => super::err_db(e),
                })?;
            conn.commit().await.map_err(super::err_db)?;
            Ok(Json(serde_json::json!({
                "property_code": row.get::<String, _>("property_code"),
                "property_name": row.get::<String, _>("property_name"),
                "timezone": row.get::<String, _>("timezone"),
                "currency_code": row.get::<String, _>("currency_code"),
                "languages": row.get::<serde_json::Value, _>("languages"),
            })))
        }
        "overview" => {
            let today = sqlx::query(
                "SELECT
                    (SELECT COUNT(*)::int FROM pms.reservations WHERE property_id = $1 AND status = 'CONFIRMED' AND arrival_date = CURRENT_DATE) AS arrivals_today,
                    (SELECT COUNT(*)::int FROM pms.reservations WHERE property_id = $1 AND status = 'CHECKED_IN' AND departure_date = CURRENT_DATE) AS departures_today,
                    (SELECT COUNT(*)::int FROM pms.reservations WHERE property_id = $1 AND status = 'CHECKED_IN') AS in_house,
                    (SELECT COUNT(*)::int FROM pms.rooms WHERE property_id = $1 AND housekeeping_status = 'DIRTY') AS dirty_rooms",
            )
            .bind(property_id)
            .fetch_one(&mut *conn)
            .await
            .map_err(super::err_db)?;
            conn.commit().await.map_err(super::err_db)?;
            Ok(Json(serde_json::json!({
                "arrivals_today": today.get::<i32, _>("arrivals_today"),
                "departures_today": today.get::<i32, _>("departures_today"),
                "in_house": today.get::<i32, _>("in_house"),
                "dirty_rooms": today.get::<i32, _>("dirty_rooms"),
            })))
        }
        "companies" => admin_rows(
            &mut conn,
            "SELECT id::text, COALESCE(company_name, '') AS company_name, COALESCE(email, '') AS email,\
                    COALESCE(preferences->>'sso_provider', '') AS sso_provider,
                    (SELECT COALESCE(string_agg(DISTINCT m.approval::text, ', '), '') FROM pms.company_payment_methods m
                      WHERE m.company_profile_id = pms.guest_profiles.id) AS credit_approvals
             FROM pms.guest_profiles WHERE property_id = $1 AND profile_type = 'COMPANY'
             ORDER BY company_name LIMIT 200",
            property_id,
            &["id", "company_name", "email", "sso_provider", "credit_approvals"],
        )
        .await,
        "company_users" => admin_rows(
            &mut conn,
            "SELECT cu.id::text, cu.role_at_company, cu.is_default::text AS is_default,\
                    COALESCE(tp.first_name || ' ' || tp.last_name, '') AS traveler_name, COALESCE(tp.email, '') AS email\
             FROM pms.company_users cu JOIN pms.guest_profiles tp ON tp.id = cu.traveler_profile_id\
             WHERE cu.property_id = $1 ORDER BY cu.created_at DESC LIMIT 200",
            property_id,
            &["id", "role_at_company", "is_default", "traveler_name", "email"],
        )
        .await,
        "negotiated_rates" => admin_rows(
            &mut conn,
            "SELECT rp.id::text, rp.rate_plan_code, rp.rate_plan_name, rp.rate_category, rp.currency_code,\
                    rp.is_active::text AS active,\
                    (SELECT COUNT(*)::text FROM pms.guest_profiles gp\
                      WHERE gp.property_id = rp.property_id AND gp.profile_type = 'COMPANY'\
                        AND gp.preferences->'negotiated_rate_plan_ids' ? rp.id::text) AS linked_companies\
             FROM pms.rate_plans rp WHERE rp.property_id = $1 AND rp.is_negotiated = true\
             ORDER BY rp.rate_plan_code",
            property_id,
            &["id", "rate_plan_code", "rate_plan_name", "rate_category", "currency_code", "active", "linked_companies"],
        )
        .await,
        _ => Err(super::err_not_found(&format!("Unknown admin resource: {resource}"))),
    }
}
#[utoipa::path(
    post,
    path = "/v1/admin/{property_id}/{resource}",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms-admin",
)]

/// `POST /v1/admin/{resource}` - form-submit aliases. The RFW renderer only
/// POSTs; each alias calls the SAME public domain handler (shared business
/// rules), so the admin surface can create/update/delete exactly what staff
/// can.
pub async fn submit_admin_data(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, resource)): Path<(uuid::Uuid, String)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    let action = action_for(&resource, true)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new(action),
    )
    .await?;
    match resource.as_str() {
        "reservations" => {
            super::reservations::create_reservation(
                State(state),
                headers,
                Path(property_id),
                Json(req),
            )
            .await
        }
        "blocks" => {
            super::blocks::create_block(State(state), headers, Path(property_id), Json(req)).await
        }
        "events" => {
            super::events::create_event(State(state), headers, Path(property_id), Json(req)).await
        }
        "profiles" => {
            super::profiles::create_profile(State(state), headers, Path(property_id), Json(req))
                .await
        }
        // Corporate admin page (ECRP-2): credit methods + user bindings via
        // the SAME staff handlers (shared business rules, DESIGN.md §4).
        "company_payment_methods" => {
            super::staff_corporate::create_company_payment_method(
                State(state),
                headers,
                Path(corporate_pair(property_id, &req)?),
                Json(req),
            )
            .await
        }
        "company_users" => {
            super::staff_corporate::create_company_user(
                State(state),
                headers,
                Path(corporate_pair(property_id, &req)?),
                Json(req),
            )
            .await
        }
        "rate_links" => {
            super::rate_plans::link_negotiated_rate_to_company(
                State(state),
                headers,
                Path(rate_link_pair(property_id, &req)?),
                Json(req),
            )
            .await
        }
        _ => Err(super::err_not_found(&format!(
            "No submit surface for admin resource: {resource}"
        ))),
    }
}

/// `(property_id, company_profile_id)` for the corporate admin aliases - the
/// RFW form posts the profile id as a body field, the route supplies the
/// property. 400 when the field is missing.
fn corporate_pair(
    property_id: uuid::Uuid,
    req: &serde_json::Value,
) -> Result<(uuid::Uuid, uuid::Uuid), (StatusCode, String)> {
    let pid = req
        .get("company_profile_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| super::err_bad_request("company_profile_id required"))?;
    Ok((property_id, pid))
}

/// `(property_id, rate_plan_id)` for the rate-link alias.
fn rate_link_pair(
    property_id: uuid::Uuid,
    req: &serde_json::Value,
) -> Result<(uuid::Uuid, uuid::Uuid), (StatusCode, String)> {
    let rid = req
        .get("rate_plan_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| super::err_bad_request("rate_plan_id required"))?;
    Ok((property_id, rid))
}

/// Shield action per admin resource - reads gate on the resource `read` scope,
/// writes on `write`. Unknown resources fail fast with 404 (never default).
fn action_for(resource: &str, write: bool) -> Result<&'static str, (StatusCode, String)> {
    match (resource, write) {
        ("reservations", false) => Ok("hotel8:pms:reservation:read"),
        ("reservations", true) => Ok("hotel8:pms:reservation:write"),
        ("frontdesk", false) => Ok("hotel8:pms:frontdesk:read"),
        ("frontdesk", true) => Ok("hotel8:pms:frontdesk:write"),
        ("housekeeping", false) => Ok("hotel8:pms:housekeeping:read"),
        ("housekeeping", true) => Ok("hotel8:pms:housekeeping:write"),
        ("rates", false) => Ok("hotel8:pms:rate:read"),
        ("rates", true) => Ok("hotel8:pms:rate:write"),
        ("blocks", false) => Ok("hotel8:pms:block:read"),
        ("blocks", true) => Ok("hotel8:pms:block:write"),
        ("events", false) => Ok("hotel8:pms:event:read"),
        ("events", true) => Ok("hotel8:pms:event:write"),
        ("profiles", false) => Ok("hotel8:pms:profile:read"),
        ("profiles", true) => Ok("hotel8:pms:profile:write"),
        // Corporate admin page (ECRP-2) - company roster + credit methods +
        // negotiated-rate links ride the profile/rate scopes like their
        // staff-facing counterparts (DESIGN.md §4).
        ("companies", false) => Ok("hotel8:pms:profile:read"),
        ("company_users", false) | ("company_payment_methods", false) => {
            Ok("hotel8:pms:profile:read")
        }
        ("company_users", true) | ("company_payment_methods", true) => {
            Ok("hotel8:pms:profile:write")
        }
        ("negotiated_rates", false) => Ok("hotel8:pms:rate:read"),
        ("rate_links", true) => Ok("hotel8:pms:rate:write"),
        ("reports", false) | ("overview", false) => Ok("hotel8:pms:report:read"),
        ("settings", false) => Ok("hotel8:pms:read"),
        ("settings", true) | ("overview", true) => Ok("hotel8:pms:admin"),
        _ => Err(super::err_not_found("Unknown admin resource")),
    }
}

/// Run a column-list query bound to the property and return `{"items": [...]}`
/// with the declared column names - the RFW DataTable contract (string cells;
/// `NULL` → empty string).
async fn admin_rows(
    conn: &mut sqlx::PgConnection,
    sql: &str,
    property_id: uuid::Uuid,
    columns: &[&str],
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let rows = sqlx::query(sql)
        .bind(property_id)
        .fetch_all(conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let mut obj = serde_json::Map::new();
            for c in columns {
                let v: Option<String> = r.try_get(*c).ok();
                obj.insert(
                    (*c).to_string(),
                    serde_json::Value::String(v.unwrap_or_default()),
                );
            }
            serde_json::Value::Object(obj)
        })
        .collect();
    Ok(Json(serde_json::json!({ "items": items })))
}
