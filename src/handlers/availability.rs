// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Availability search handlers.
//!
//! The availability/restriction math lives in pure functions below (see
//! `hotel8/design/sentin8-hotel8-rust-test-strategy.md` §2.3) so it can be
//! tested DB-free; the handlers only fetch rows and apply the pure filters.
use crate::auth;
use crate::handlers::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sqlx::Row;

// / available rooms for a rate/room-type over a stay.
///
/// `physical − out_of_order − out_of_service = sellable`, then clamped by the
/// sell limit: `min(sell_limit, sellable) − sold`. Mirrors the formula in
/// `sentin8-hotel8-pms-technical-design.md` §5.5.
pub fn available_rooms(
    physical: i32,
    out_of_order: i32,
    out_of_service: i32,
    sell_limit: i32,
    sold: i32,
) -> i32 {
    let sellable = (physical - out_of_order - out_of_service).max(0);
    let limit = sell_limit.min(sellable).max(0);
    (limit - sold).max(0)
}

// / does a rate plan's restrictions admit this stay?
///
/// `num_nights`/`advance_days` come from the handler; `min_los`/`max_los`/
/// `min_advance` are the DB's nullable restriction columns (`None` = unset).
pub fn restrictions_allow(
    num_nights: i64,
    advance_days: i64,
    min_los: Option<i32>,
    max_los: Option<i32>,
    min_advance: Option<i32>,
) -> bool {
    if let Some(ml) = min_los {
        if num_nights < ml as i64 {
            return false;
        }
    }
    if let Some(ml) = max_los {
        if num_nights > ml as i64 {
            return false;
        }
    }
    if let Some(ma) = min_advance {
        if advance_days < ma as i64 {
            return false;
        }
    }
    true
}

pub async fn search_availability(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    axum::extract::Query(params): axum::extract::Query<serde_json::Value>,
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

    let arrival = params
        .get("arrivalDate")
        .and_then(|v| v.as_str())
        .unwrap_or("2026-01-01");
    let departure = params
        .get("departureDate")
        .and_then(|v| v.as_str())
        .unwrap_or("2026-01-02");
    let num_adults: i32 = params
        .get("numberOfAdults")
        .and_then(|v| v.as_i64())
        .unwrap_or(2) as i32;

    // Availability calculation: physical − OOO − OOS = sellable; sell_limit − sold = available
    // Get room types with available inventory for the date range
    let room_types = sqlx::query(
        "SELECT rt.id, rt.room_type_code, rt.room_type_name, rt.max_occupancy, rt.bed_type,
         COALESCE((SELECT MIN(i.available_rooms) FROM pms.inventory i
                    WHERE i.property_id = rt.property_id AND i.room_type_id = rt.id
                      AND i.date >= $2 AND i.date < $3),
                  (SELECT COUNT(*)::int FROM pms.rooms r WHERE r.room_type_id = rt.id
                    AND r.housekeeping_status NOT IN ('OUT_OF_ORDER', 'OUT_OF_SERVICE'))) AS available
         FROM pms.room_types rt WHERE rt.property_id = $1 ORDER BY rt.room_type_code"
    )
    .bind(property_id).bind(arrival).bind(departure)
    .fetch_all(&mut *conn).await.map_err(super::err_db)?;

    // Get rate plans with restrictions applied (MinLOS, MaxLOS, MinAdvance)
    let num_nights = (chrono::NaiveDate::parse_from_str(departure, "%Y-%m-%d")
        .unwrap_or(chrono::NaiveDate::from_ymd_opt(2026, 1, 2).unwrap())
        - chrono::NaiveDate::parse_from_str(arrival, "%Y-%m-%d").unwrap_or(
            chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
                .unwrap_or(chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()),
        ))
    .num_days();
    let arrival_date = chrono::NaiveDate::parse_from_str(arrival, "%Y-%m-%d")
        .unwrap_or_else(|_| chrono::Utc::now().date_naive());
    let advance_days = (arrival_date - chrono::Utc::now().date_naive()).num_days();

    let rate_plans = sqlx::query(
        "SELECT rp.id, rp.rate_plan_code, rp.rate_plan_name, rp.currency_code, rp.min_los, rp.max_los, rp.min_advance_booking, rp.max_advance_booking,
         rs.rate_amount::text as rate_amount
         FROM pms.rate_plans rp
         LEFT JOIN pms.rate_schedules rs ON rs.rate_plan_id = rp.id AND rs.start_date <= $2 AND rs.end_date >= $2
         WHERE rp.property_id = $1 AND rp.is_active = true ORDER BY rp.rate_plan_code"
    )
    .bind(property_id).bind(arrival)
    .fetch_all(&mut *conn).await.map_err(super::err_db)?;

    let rt_items: Vec<serde_json::Value> = room_types
        .iter()
        .filter_map(|rt| {
            let available: i32 = rt.get("available");
            if available <= 0 {
                return None;
            }
            let max_occ: i32 = rt.get("max_occupancy");
            if num_adults > max_occ {
                return None;
            }
            // Get matching rate plans for this room type
            let rp_items: Vec<serde_json::Value> = rate_plans.iter().filter_map(|rp| {
            let min_los: Option<i32> = rp.get("min_los");
            let max_los: Option<i32> = rp.get("max_los");
            let min_adv: Option<i32> = rp.get("min_advance_booking");
            // Apply restrictions
            if !restrictions_allow(num_nights, advance_days, min_los, max_los, min_adv) {
                return None;
            }
            Some(serde_json::json!({
                "rate_plan_id": rp.get::<uuid::Uuid, _>("id"),
                "rate_plan_code": rp.get::<String, _>("rate_plan_code"),
                "rate_plan_name": rp.get::<String, _>("rate_plan_name"),
                "currency_code": rp.get::<String, _>("currency_code"),
                "rate_amount": rp.get::<Option<String>, _>("rate_amount").unwrap_or_default(),
            }))
        }).collect();
            if rp_items.is_empty() {
                return None;
            }
            Some(serde_json::json!({
                "room_type_id": rt.get::<uuid::Uuid, _>("id"),
                "room_type_code": rt.get::<String, _>("room_type_code"),
                "room_type_name": rt.get::<String, _>("room_type_name"),
                "max_occupancy": max_occ,
                "bed_type": rt.get::<Option<String>, _>("bed_type"),
                "available_rooms": available,
                "rate_plans": rp_items,
            }))
        })
        .collect();

    conn.commit().await.map_err(super::err_db)?;

    Ok(Json(serde_json::json!({
        "property_id": property_id,
        "arrival_date": arrival,
        "departure_date": departure,
        "number_of_nights": num_nights,
        "room_types": rt_items,
    })))
}

// ── Company-scoped rate-mix (corporate availability) ───────────────────────

/// `POST /v1/properties/{property_id}/corporate-availability` — availability
/// for a corporate session (company_profile_id). Rate-mix policy: when the
/// request carries a company context, ONLY the negotiated rate plans linked
/// to that company (via `preferences.negotiated_rate_plan_ids`) are returned;
/// public plans are withheld so negotiated rates never leak to non-members
/// and members never book public rates against their contract. Companies
/// with no linked plans get an explicit empty result, not a public fallback.
pub async fn corporate_availability(
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
        sentin8::shield::EvalTarget::new("hotel8:pms:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;

    let company_profile_id: uuid::Uuid = req
        .get("company_profile_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| super::err_bad_request("company_profile_id required"))?;
    let arrival = req
        .get("arrival_date")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let departure = req
        .get("departure_date")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if arrival.is_empty() || departure.is_empty() {
        return Err(super::err_bad_request(
            "arrival_date and departure_date required",
        ));
    }
    let num_adults: i32 = req
        .get("number_of_guests")
        .and_then(|v| v.as_i64())
        .unwrap_or(1) as i32;
    let num_rooms: i32 = req
        .get("number_of_rooms")
        .and_then(|v| v.as_i64())
        .unwrap_or(1) as i32;

    // The company profile must exist on this property (RLS filters the env).
    let _cp = sqlx::query("SELECT id FROM pms.guest_profiles WHERE id = $1 AND property_id = $2 AND profile_type = 'COMPANY'")
        .bind(company_profile_id)
        .bind(property_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(super::err_db)?
        .ok_or_else(|| super::err_not_found("Company profile not found"))?;

    // Linked negotiated plans only (rate-mix policy). Room types keep the
    // same availability math as the public search; plans are filtered by
    // the company link.
    let room_types = sqlx::query(
        "SELECT rt.id, rt.room_type_code, rt.room_type_name, rt.max_occupancy, rt.bed_type,\
         COALESCE((SELECT MIN(i.available_rooms) FROM pms.inventory i\
                    WHERE i.property_id = rt.property_id AND i.room_type_id = rt.id\
                      AND i.date >= $2 AND i.date < $3),\
                  (SELECT COUNT(*)::int FROM pms.rooms r WHERE r.room_type_id = rt.id\
                    AND r.housekeeping_status NOT IN ('OUT_OF_ORDER', 'OUT_OF_SERVICE'))) AS available\
         FROM pms.room_types rt WHERE rt.property_id = $1 ORDER BY rt.room_type_code",
    )
    .bind(property_id).bind(arrival).bind(departure)
    .fetch_all(&mut *conn).await.map_err(super::err_db)?;

    let rate_plans = sqlx::query(
        "SELECT rp.id, rp.rate_plan_code, rp.rate_plan_name, rp.currency_code, rp.min_los, rp.max_los, rp.min_advance_booking, rp.max_advance_booking,\
         rs.rate_amount::text as rate_amount\
         FROM pms.rate_plans rp\
         LEFT JOIN pms.rate_schedules rs ON rs.rate_plan_id = rp.id AND rs.start_date <= $2 AND rs.end_date >= $2\
         WHERE rp.property_id = $1 AND rp.is_active = true AND rp.is_negotiated = true\
           AND EXISTS (SELECT 1 FROM pms.guest_profiles gp\
                        WHERE gp.id = $4 AND gp.profile_type = 'COMPANY'\
                          AND gp.preferences->'negotiated_rate_plan_ids' ? rp.id::text)\
         ORDER BY rp.rate_plan_code",
    )
    .bind(property_id).bind(arrival).bind(company_profile_id)
    .fetch_all(&mut *conn).await.map_err(super::err_db)?;

    let num_nights = (chrono::NaiveDate::parse_from_str(departure, "%Y-%m-%d")
        .unwrap_or(chrono::NaiveDate::from_ymd_opt(2026, 1, 2).unwrap())
        - chrono::NaiveDate::parse_from_str(arrival, "%Y-%m-%d")
            .unwrap_or(chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap()))
    .num_days();
    let arrival_date = chrono::NaiveDate::parse_from_str(arrival, "%Y-%m-%d")
        .unwrap_or_else(|_| chrono::Utc::now().date_naive());
    let advance_days = (arrival_date - chrono::Utc::now().date_naive()).num_days();

    let rt_items: Vec<serde_json::Value> = room_types
        .iter()
        .filter_map(|rt| {
            let available: i32 = rt.get("available");
            if available < num_rooms {
                return None;
            }
            let max_occ: i32 = rt.get("max_occupancy");
            if num_adults > max_occ {
                return None;
            }
            let rp_items: Vec<serde_json::Value> = rate_plans.iter().filter_map(|rp| {
            let min_los: Option<i32> = rp.get("min_los");
            let max_los: Option<i32> = rp.get("max_los");
            let min_adv: Option<i32> = rp.get("min_advance_booking");
            if !restrictions_allow(num_nights, advance_days, min_los, max_los, min_adv) {
                return None;
            }
            Some(serde_json::json!({
                "rate_plan_id": rp.get::<uuid::Uuid, _>("id"),
                "rate_plan_code": rp.get::<String, _>("rate_plan_code"),
                "rate_plan_name": rp.get::<String, _>("rate_plan_name"),
                "currency_code": rp.get::<String, _>("currency_code"),
                "rate_amount": rp.get::<Option<String>, _>("rate_amount").unwrap_or_default(),
                "negotiated": true,
            }))
        }).collect();
            if rp_items.is_empty() {
                return None;
            }
            Some(serde_json::json!({
                "room_type_id": rt.get::<uuid::Uuid, _>("id"),
                "room_type_code": rt.get::<String, _>("room_type_code"),
                "room_type_name": rt.get::<String, _>("room_type_name"),
                "max_occupancy": max_occ,
                "bed_type": rt.get::<Option<String>, _>("bed_type"),
                "available_rooms": available,
                "rate_plans": rp_items,
            }))
        })
        .collect();

    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "property_id": property_id,
        "company_profile_id": company_profile_id,
        "arrival_date": arrival,
        "departure_date": departure,
        "number_of_nights": num_nights,
        "room_types": rt_items,
    })))
}

#[allow(dead_code)]
pub async fn get_packages(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(_property_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&_a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT DISTINCT package_code, package_name FROM pms.packages WHERE property_id = $1 ORDER BY package_code")
        .bind(_property_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let packages: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "package_code": r.get::<String, _>("package_code"),
                "package_name": r.get::<String, _>("package_name"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": packages })))
}

pub async fn get_guarantee_policies(
    State(_state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(_property_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&_state.config, &headers).await?;
    crate::policy::require(
        &_state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:read"),
    )
    .await?;
    Ok(Json(serde_json::json!({
        "items": [
            { "code": "CCG", "description": "Credit Card Guarantee", "is_active": true },
            { "code": "6PM", "description": "6PM Hold", "is_active": true },
        ]
    })))
}

// ── Multi-property availability search (org-wide) ──

pub async fn search_availability_org(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<serde_json::Value>,
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
    let arrival = params
        .get("arrivalDate")
        .and_then(|v| v.as_str())
        .unwrap_or("2026-01-01");
    let departure = params
        .get("departureDate")
        .and_then(|v| v.as_str())
        .unwrap_or("2026-01-02");
    // Get all properties in the org
    let props = sqlx::query(
        "SELECT id, property_code, property_name, city FROM pms.properties ORDER BY property_code",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let mut results: Vec<serde_json::Value> = Vec::new();
    for p in &props {
        let property_id: uuid::Uuid = p.get("id");
        // Get available room types for this property
        let rts = sqlx::query(
            "SELECT rt.id, rt.room_type_code, rt.room_type_name, rt.max_occupancy,
             COALESCE((SELECT MIN(i.available_rooms) FROM pms.inventory i
                        WHERE i.property_id = rt.property_id AND i.room_type_id = rt.id
                          AND i.date >= $2 AND i.date < $3),
                      (SELECT COUNT(*)::int FROM pms.rooms r WHERE r.room_type_id = rt.id
                        AND r.housekeeping_status NOT IN ('OUT_OF_ORDER', 'OUT_OF_SERVICE'))) AS available
             FROM pms.room_types rt WHERE rt.property_id = $1 ORDER BY rt.room_type_code",
        )
        .bind(property_id).bind(arrival).bind(departure)
        .fetch_all(&mut *conn).await.map_err(super::err_db)?;
        let rt_items: Vec<serde_json::Value> = rts
            .iter()
            .filter(|r| r.get::<Option<i32>, _>("available").unwrap_or(0) > 0)
            .map(|r| {
                serde_json::json!({
                    "room_type_code": r.get::<String, _>("room_type_code"),
                    "room_type_name": r.get::<String, _>("room_type_name"),
                    "available_rooms": r.get::<Option<i32>, _>("available").unwrap_or(0),
                })
            })
            .collect();
        if !rt_items.is_empty() {
            results.push(serde_json::json!({
                "property_id": property_id,
                "property_code": p.get::<String, _>("property_code"),
                "property_name": p.get::<String, _>("property_name"),
                "city": p.get::<Option<String>, _>("city"),
                "room_types": rt_items,
            }));
        }
    }
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "env_id": env_id,
        "arrival_date": arrival,
        "departure_date": departure,
        "properties": results,
    })))
}
// ═══════════════════════════════════════════════════════════════════════════
// Tests — pure availability math (H8T-5)

// The formulas mirror `sentin8-hotel8-pms-technical-design.md` §5.5 and the
// / handler comments; they are exercised DB-free via the service
// integration test binary as well (see tests/integration_test.rs).
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::{available_rooms, restrictions_allow};

    #[test]
    fn available_rooms_subtracts_ooo_oos_then_sell_limit() {
        // 100 physical, 3 OOO, 2 OOS → 95 sellable; limit 95 → 95 − 20 = 75.
        assert_eq!(available_rooms(100, 3, 2, 95, 20), 75);
        // Sell limit below sellable caps availability: limit 90 → 90 − 20 = 70.
        assert_eq!(available_rooms(100, 3, 2, 90, 20), 70);
    }

    #[test]
    fn available_rooms_never_goes_negative() {
        // Oversold: 0, not negative.
        assert_eq!(available_rooms(10, 0, 0, 10, 12), 0);
        // More OOO/OOS than physical: sellable clamps to 0.
        assert_eq!(available_rooms(10, 8, 8, 10, 0), 0);
        // Negative sell limit treated as no inventory.
        assert_eq!(available_rooms(10, 0, 0, -5, 0), 0);
    }

    #[test]
    fn available_rooms_unlimited_sold_is_zero_not_panic() {
        assert_eq!(available_rooms(0, 0, 0, 0, 0), 0);
    }

    // ── Restriction gating ──

    #[test]
    fn restrictions_unset_means_everything_allowed() {
        assert!(restrictions_allow(1, 0, None, None, None));
        assert!(restrictions_allow(30, 365, None, None, None));
    }

    #[test]
    fn min_los_rejects_short_stays() {
        // 3-night minimum: a 2-night stay is refused, 3 nights allowed.
        assert!(!restrictions_allow(2, 10, Some(3), None, None));
        assert!(restrictions_allow(3, 10, Some(3), None, None));
        assert!(restrictions_allow(7, 10, Some(3), None, None));
    }

    #[test]
    fn max_los_rejects_long_stays() {
        // 7-night maximum: 8 nights refused, 7 allowed.
        assert!(!restrictions_allow(8, 10, None, Some(7), None));
        assert!(restrictions_allow(7, 10, None, Some(7), None));
    }

    #[test]
    fn min_advance_rejects_late_bookings() {
        // Book ≥ 3 days ahead: same-day (0) refused, 3 days allowed.
        assert!(!restrictions_allow(1, 2, None, None, Some(3)));
        assert!(restrictions_allow(1, 3, None, None, Some(3)));
    }

    #[test]
    fn combined_restrictions_all_must_pass() {
        // MinLOS 2 + maxLOS 5 + min-advance 1: only the middle band survives.
        assert!(!restrictions_allow(1, 5, Some(2), Some(5), Some(1)));
        assert!(restrictions_allow(3, 5, Some(2), Some(5), Some(1)));
        assert!(!restrictions_allow(6, 5, Some(2), Some(5), Some(1)));
        assert!(!restrictions_allow(3, 0, Some(2), Some(5), Some(1)));
    }
}
