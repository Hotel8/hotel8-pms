// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Rate plan management handlers.
use crate::auth;
use crate::handlers::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use hotel8::pms::contracts::{
    LinkCompanyRequest, LinkCompanyResult, NegotiatedRatePlan, NegotiatedRatePlanList,
    PackageCreateRequest, PackageCreated, PackageDetailList, PackageDetailView,
    PromoValidateRequest, PromoValidation, RatePlan, RatePlanCreate, ScheduleCreateRequest,
    ScheduleCreated, ScheduleList, ScheduleView,
};
use sqlx::Row;

/// `POST /v1/properties/{property_id}/rate-plans`
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/rate-plans",
    request_body = RatePlanCreate,
    responses(
        (status = 200, description = "Rate plan created", body = RatePlan),
        (status = 403, description = "Missing pms:admin scope"),
    ),
    security(("pms:admin" = [])),
    tag = "pms",
)]
pub async fn create_rate_plan(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<RatePlanCreate>,
) -> Result<Json<RatePlan>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:rate:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let row = sqlx::query(
        "INSERT INTO pms.rate_plans (property_id, rate_plan_code, rate_plan_name, rate_category, rate_class, description, currency_code, market_code, source_code, is_active, is_negotiated, min_los, max_los, min_advance_booking, max_advance_booking, cancellation_policy, deposit_policy, guarantee_policy)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) RETURNING *",
    )
    .bind(property_id)
    .bind(&req.rate_plan_code)
    .bind(&req.rate_plan_name)
    .bind(&req.rate_category)
    .bind(&req.rate_class)
    .bind(&req.description)
    .bind(&req.currency_code)
    .bind(&req.market_code)
    .bind(&req.source_code)
    .bind(req.is_active.unwrap_or(true))
    .bind(req.is_negotiated.unwrap_or(false))
    .bind(req.min_los)
    .bind(req.max_los)
    .bind(req.min_advance_booking)
    .bind(req.max_advance_booking)
    .bind(&req.cancellation_policy)
    .bind(&req.deposit_policy)
    .bind(&req.guarantee_policy)
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:rate_plan:created",
        serde_json::json!({ "property_id": property_id, "rate_plan_code": &req.rate_plan_code }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(row_to_rate_plan(&row)))
}

/// `GET /v1/properties/{property_id}/rate-plans`
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/rate-plans",
    responses(
        (status = 200, description = "List of rate plans", body = [RatePlan]),
        (status = 403, description = "Missing pms:admin scope"),
    ),
    security(("pms:admin" = [])),
    tag = "pms",
)]
pub async fn list_rate_plans(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<Vec<RatePlan>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:rate:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows =
        sqlx::query("SELECT * FROM pms.rate_plans WHERE property_id = $1 ORDER BY rate_plan_code")
            .bind(property_id)
            .fetch_all(&mut *conn)
            .await
            .map_err(super::err_db)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(rows.iter().map(row_to_rate_plan).collect()))
}
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/rate-plans/{plan_id}",
    responses(
        (status = 200, description = "OK", body = RatePlan),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Rate plan not found"),
    ),
    security(),
    tag = "pms",
)]

pub async fn get_rate_plan(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, plan_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<RatePlan>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:rate:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let row = sqlx::query("SELECT * FROM pms.rate_plans WHERE id = $1 AND property_id = $2")
        .bind(plan_id)
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => super::err_not_found("Rate plan not found"),
            e => super::err_db(e),
        })?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(row_to_rate_plan(&row)))
}

fn row_to_rate_plan(row: &sqlx::postgres::PgRow) -> RatePlan {
    RatePlan {
        id: row.get("id"),
        property_id: row.get("property_id"),
        rate_plan_code: row.get("rate_plan_code"),
        rate_plan_name: row.get("rate_plan_name"),
        rate_category: row.get("rate_category"),
        rate_class: row.get("rate_class"),
        description: row.get("description"),
        currency_code: row.get("currency_code"),
        market_code: row.get("market_code"),
        source_code: row.get("source_code"),
        is_active: row.get("is_active"),
        is_negotiated: row.get("is_negotiated"),
        min_los: row.get("min_los"),
        max_los: row.get("max_los"),
        min_advance_booking: row.get("min_advance_booking"),
        max_advance_booking: row.get("max_advance_booking"),
        cancellation_policy: row.get("cancellation_policy"),
        deposit_policy: row.get("deposit_policy"),
        guarantee_policy: row.get("guarantee_policy"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

// ── -Rate Schedule CRUD ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/rate-plans/{plan_id}/schedules",
    request_body = ScheduleCreateRequest,
    responses(
        (status = 200, description = "OK - schedule created (deduped per plan/room-type/window)", body = ScheduleCreated),
        (status = 400, description = "room_type_id required"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn create_rate_schedule(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, plan_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<ScheduleCreateRequest>,
) -> Result<Json<ScheduleCreated>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:rate:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let room_type_id: uuid::Uuid = req.room_type_id;
    // Dates bind as chrono::NaiveDate (never text) - a "date = text"
    // operator error came from untyped string binds reaching a date comparison.
    let parse_date = |raw: &str, fallback: &'static str| -> chrono::NaiveDate {
        chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d")
            .unwrap_or_else(|_| chrono::NaiveDate::parse_from_str(fallback, "%Y-%m-%d").unwrap())
    };
    let start_date = parse_date(&req.start_date, "2020-01-01");
    let end_date = parse_date(&req.end_date, "2030-12-31");
    let days_of_week = serde_json::to_value(if req.days_of_week.is_empty() {
        vec![
            "MON".to_string(),
            "TUE".to_string(),
            "WED".to_string(),
            "THU".to_string(),
            "FRI".to_string(),
            "SAT".to_string(),
            "SUN".to_string(),
        ]
    } else {
        req.days_of_week.clone()
    })
    .unwrap_or(serde_json::json!([
        "MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"
    ]));
    let row = sqlx::query("INSERT INTO pms.rate_schedules (property_id, rate_plan_id, room_type_id, start_date, end_date, days_of_week, rate_amount, rate_amount_single, rate_amount_double, rate_amount_extra_adult, rate_amount_extra_child, package_code)
        SELECT $1, $2, $3, $4::date, $5::date, $6, $7::numeric, $8::numeric, $9::numeric, $10::numeric, $11::numeric, $12 WHERE NOT EXISTS (SELECT 1 FROM pms.rate_schedules WHERE rate_plan_id = $2 AND room_type_id = $3 AND start_date = $4::date AND end_date = $5::date)
        RETURNING id, start_date, end_date, rate_amount::text as rate_amount")
        .bind(sqlx::query("SELECT property_id FROM pms.rate_plans WHERE id = $1").bind(plan_id).fetch_one(&mut *conn).await.map_err(super::err_db)?.get::<uuid::Uuid, _>("property_id"))
        .bind(plan_id).bind(room_type_id).bind(start_date).bind(end_date).bind(&days_of_week).bind(&req.rate_amount)
        .bind(req.rate_amount_single.as_deref())
        .bind(req.rate_amount_double.as_deref())
        .bind(req.rate_amount_extra_adult.as_deref())
        .bind(req.rate_amount_extra_child.as_deref())
        .bind(req.package_code.as_deref())
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let id: uuid::Uuid = row.get("id");
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:rate_schedule:created",
        serde_json::json!({ "schedule_id": id, "rate_plan_id": plan_id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(ScheduleCreated {
        id,
        rate_plan_id: plan_id,
        room_type_id,
        start_date: row.get::<chrono::NaiveDate, _>("start_date"),
        end_date: row.get::<chrono::NaiveDate, _>("end_date"),
        rate_amount: row.get::<String, _>("rate_amount"),
    }))
}
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/rate-plans/{plan_id}/schedules",
    responses(
        (status = 200, description = "OK - schedules ordered by start_date", body = ScheduleList),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn list_rate_schedules(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, plan_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<ScheduleList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:rate:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, room_type_id, start_date, end_date, days_of_week, rate_amount::text as rate_amount, rate_amount_single::text as rate_amount_single, rate_amount_double::text as rate_amount_double, package_code FROM pms.rate_schedules WHERE rate_plan_id = $1 ORDER BY start_date")
        .bind(plan_id).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let items: Vec<ScheduleView> = rows
        .iter()
        .map(|r| ScheduleView {
            id: r.get::<uuid::Uuid, _>("id"),
            room_type_id: r.get::<uuid::Uuid, _>("room_type_id"),
            start_date: r.get::<chrono::NaiveDate, _>("start_date"),
            end_date: r.get::<chrono::NaiveDate, _>("end_date"),
            days_of_week: serde_json::from_value(r.get::<serde_json::Value, _>("days_of_week"))
                .unwrap_or_default(),
            rate_amount: r.get::<String, _>("rate_amount"),
            rate_amount_single: r.get::<Option<String>, _>("rate_amount_single"),
            rate_amount_double: r.get::<Option<String>, _>("rate_amount_double"),
            package_code: r.get::<Option<String>, _>("package_code"),
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(ScheduleList { items }))
}
#[utoipa::path(
    delete,
    path = "/v1/properties/{property_id}/rate-plans/{plan_id}/schedules/{schedule_id}",
    responses(
        (status = 204, description = "Schedule deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn delete_rate_schedule(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, _plan_id, schedule_id)): Path<(uuid::Uuid, uuid::Uuid, uuid::Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:rate:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    sqlx::query("DELETE FROM pms.rate_schedules WHERE id = $1")
        .bind(schedule_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Package CRUD ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/packages",
    request_body = PackageCreateRequest,
    responses(
        (status = 200, description = "OK", body = PackageCreated),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn create_package(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<PackageCreateRequest>,
) -> Result<Json<PackageCreated>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:rate:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let package_code = req.package_code.as_str();
    let package_name = req.package_name.as_str();
    let quantity: i32 = req.quantity;
    let price = req.price.as_str();
    let per_stay = req.per_stay;
    let row = sqlx::query("INSERT INTO pms.packages (property_id, package_code, package_name, quantity, price, per_stay) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, package_code, package_name, quantity, price::text as price, per_stay")
        .bind(property_id).bind(package_code).bind(package_name).bind(quantity).bind(price).bind(per_stay)
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let id: uuid::Uuid = row.get("id");
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:package:created",
        serde_json::json!({ "package_id": id, "package_code": package_code }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(PackageCreated {
        id,
        package_code: row.get::<String, _>("package_code"),
        package_name: row.get::<String, _>("package_name"),
        quantity: row.get::<i32, _>("quantity"),
        price: row.get::<String, _>("price"),
        per_stay: row.get::<bool, _>("per_stay"),
    }))
}
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/packages",
    responses(
        (status = 200, description = "OK", body = PackageDetailList),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn list_packages(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<PackageDetailList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:rate:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query("SELECT id, package_code, package_name, quantity, price::text as price, per_stay, is_active FROM pms.packages WHERE property_id = $1 ORDER BY package_code")
        .bind(property_id).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let items: Vec<PackageDetailView> = rows
        .iter()
        .map(|r| PackageDetailView {
            id: r.get::<uuid::Uuid, _>("id"),
            package_code: r.get::<String, _>("package_code"),
            package_name: r.get::<String, _>("package_name"),
            quantity: r.get::<i32, _>("quantity"),
            price: r.get::<String, _>("price"),
            per_stay: r.get::<bool, _>("per_stay"),
            is_active: r.get::<bool, _>("is_active"),
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(PackageDetailList { items }))
}

// ── Negotiated Rate Plans (corporate, government, AAA) with company profile linking ──
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/negotiated-rate-plans",
    responses(
        (status = 200, description = "OK - negotiated (corporate / government / AAA) rate plans", body = NegotiatedRatePlanList),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn list_negotiated_rate_plans(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<NegotiatedRatePlanList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:rate:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query(
        "SELECT rp.id, rp.rate_plan_code, rp.rate_plan_name, rp.rate_category, rp.currency_code, rp.is_active,
                rp.market_code, rp.source_code, rp.description
         FROM pms.rate_plans rp
         WHERE rp.property_id = $1 AND rp.is_negotiated = true
         ORDER BY rp.rate_plan_code",
    )
    .bind(property_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let items: Vec<NegotiatedRatePlan> = rows
        .iter()
        .map(|r| NegotiatedRatePlan {
            id: r.get::<uuid::Uuid, _>("id"),
            rate_plan_code: r.get::<String, _>("rate_plan_code"),
            rate_plan_name: r.get::<String, _>("rate_plan_name"),
            rate_category: r.get::<String, _>("rate_category"),
            currency_code: r.get::<String, _>("currency_code"),
            is_active: r.get::<bool, _>("is_active"),
            market_code: r.get::<Option<String>, _>("market_code"),
            source_code: r.get::<Option<String>, _>("source_code"),
            description: r.get::<Option<String>, _>("description"),
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(NegotiatedRatePlanList { items }))
}
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/negotiated-rate-plans/{rate_plan_id}/link-company",
    request_body = LinkCompanyRequest,
    responses(
        (status = 200, description = "OK - link stored on the company profile preferences", body = LinkCompanyResult),
        (status = 400, description = "rate plan is not negotiated"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Rate plan or company profile not found"),
    ),
    security(),
    tag = "pms",
)]

pub async fn link_negotiated_rate_to_company(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, rate_plan_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<LinkCompanyRequest>,
) -> Result<Json<LinkCompanyResult>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:rate:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let company_uuid = req.company_profile_id;
    // Verify the rate plan is negotiated and belongs to this property
    let rp = sqlx::query(
        "SELECT id, is_negotiated FROM pms.rate_plans WHERE id = $1 AND property_id = $2",
    )
    .bind(rate_plan_id)
    .bind(property_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(super::err_db)?
    .ok_or_else(|| super::err_not_found("rate plan not found"))?;
    if !rp.get::<bool, _>("is_negotiated") {
        return Err(super::err_bad_request("rate plan is not a negotiated plan"));
    }
    // Verify the company profile exists and is a COMPANY type
    let cp = sqlx::query("SELECT id FROM pms.guest_profiles WHERE id = $1 AND property_id = $2 AND profile_type = 'COMPANY'")
        .bind(company_uuid).bind(property_id)
        .fetch_optional(&mut *conn).await.map_err(super::err_db)?
        .ok_or_else(|| super::err_not_found("company profile not found"))?;
    let _ = cp;
    // Store the link as a preference on the company profile (JSONB preferences field)
    sqlx::query("UPDATE pms.guest_profiles SET preferences = preferences || jsonb_build_object('negotiated_rate_plan_ids', COALESCE(preferences->'negotiated_rate_plan_ids', '[]'::jsonb) || to_jsonb($3::uuid)) WHERE id = $1")
        .bind(company_uuid).bind(property_id).bind(rate_plan_id)
        .execute(&mut *conn).await.map_err(super::err_db)?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:negotiated_rate:linked", serde_json::json!({ "property_id": property_id, "rate_plan_id": rate_plan_id, "company_profile_id": company_uuid }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(LinkCompanyResult {
        linked: true,
        rate_plan_id,
        company_profile_id: company_uuid,
    }))
}

// ── Promo Code validation ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/promo/validate",
    request_body = PromoValidateRequest,
    responses(
        (status = 200, description = "OK - validation result; not-found carries only `reason`, a valid plan carries the plan ref + warnings", body = PromoValidation),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn validate_promo_code(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<PromoValidateRequest>,
) -> Result<Json<PromoValidation>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:rate:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let promo_code = req.promo_code.as_str();
    let check_in = req.check_in.as_deref();
    let check_out = req.check_out.as_deref();
    // Look up the rate plan with RATE_CATEGORY = 'PROMO' and matching code
    let row = sqlx::query(
        "SELECT id, rate_plan_code, rate_plan_name, rate_category, currency_code, is_active, min_los, max_los, min_advance_booking
         FROM pms.rate_plans
         WHERE property_id = $1 AND rate_category = 'PROMO' AND rate_plan_code = $2 AND is_active = true",
    )
    .bind(property_id).bind(promo_code)
    .fetch_optional(&mut *conn).await.map_err(super::err_db)?;
    let rp = match row {
        Some(r) => r,
        None => {
            return Ok(Json(PromoValidation {
                valid: false,
                reason: Some("promo code not found or inactive".into()),
                rate_plan_id: None,
                rate_plan_code: None,
                rate_plan_name: None,
                currency_code: None,
                warnings: None,
            }))
        }
    };
    // Check MinLOS / MinAdvanceBooking if dates provided
    let min_los: Option<i32> = rp.get("min_los");
    let max_los: Option<i32> = rp.get("max_los");
    let min_advance: Option<i32> = rp.get("min_advance_booking");
    let mut warnings: Vec<String> = Vec::new();
    if let (Some(ci), Some(co)) = (check_in, check_out) {
        let ci_date = chrono::NaiveDate::parse_from_str(ci, "%Y-%m-%d").ok();
        let co_date = chrono::NaiveDate::parse_from_str(co, "%Y-%m-%d").ok();
        if let (Some(ci_d), Some(co_d)) = (ci_date, co_date) {
            let nights = (co_d - ci_d).num_days();
            if let Some(min) = min_los {
                if nights < min.into() {
                    warnings.push(format!("minimum length of stay is {} nights", min));
                }
            }
            if let Some(max) = max_los {
                if nights > max.into() {
                    warnings.push(format!("maximum length of stay is {} nights", max));
                }
            }
            if let Some(min_adv) = min_advance {
                let today = chrono::Utc::now().date_naive();
                let advance = (ci_d - today).num_days();
                if advance < min_adv.into() {
                    warnings.push(format!("minimum advance booking is {} days", min_adv));
                }
            }
        }
    }
    let valid = warnings.is_empty();
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:promo:validated",
        serde_json::json!({ "property_id": property_id, "promo_code": promo_code, "valid": valid }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(PromoValidation {
        valid,
        reason: None,
        rate_plan_id: Some(rp.get::<uuid::Uuid, _>("id")),
        rate_plan_code: Some(rp.get::<String, _>("rate_plan_code")),
        rate_plan_name: Some(rp.get::<String, _>("rate_plan_name")),
        currency_code: Some(rp.get::<String, _>("currency_code")),
        warnings: Some(warnings),
    }))
}
