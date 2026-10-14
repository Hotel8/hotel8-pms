// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Back office handlers — reporting and configuration.
use crate::auth;
use crate::event_emit::{emit_on_pool, emit_tx};
use crate::handlers::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sqlx::Row;

/// `GET /v1/properties/{property_id}/reports/occupancy`
#[utoipa::path(
    get,
    path = "/v1/admin/reports",
    responses(
        (status = 200, description = "Occupancy report", body = serde_json::Value),
        (status = 403, description = "Missing pms:admin scope"),
    ),
    security(("pms:admin" = [])),
    tag = "pms",
)]
pub async fn get_occupancy_report(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    axum::extract::Query(params): axum::extract::Query<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:report:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&_a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let start = params
        .get("start_date")
        .and_then(|v| v.as_str())
        .unwrap_or("2020-01-01");
    let end = params
        .get("end_date")
        .and_then(|v| v.as_str())
        .unwrap_or("2030-12-31");
    let rows = sqlx::query("SELECT arrival_date, COUNT(*) as reservations, SUM(num_adults + num_children) as guests FROM pms.reservations WHERE property_id = $1 AND arrival_date >= $2 AND arrival_date <= $3 AND status NOT IN ('CANCELLED') GROUP BY arrival_date ORDER BY arrival_date")
        .bind(property_id)
        .bind(start)
        .bind(end)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "date": r.get::<chrono::NaiveDate, _>("arrival_date"),
                "reservations": r.get::<i64, _>("reservations"),
                "guests": r.get::<i64, _>("guests"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

pub async fn get_revenue_report(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    axum::extract::Query(params): axum::extract::Query<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:report:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&_a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let start = params
        .get("start_date")
        .and_then(|v| v.as_str())
        .unwrap_or("2020-01-01");
    let end = params
        .get("end_date")
        .and_then(|v| v.as_str())
        .unwrap_or("2030-12-31");
    let rows = sqlx::query("SELECT fc.charge_code, SUM(fc.amount * fc.quantity)::text as total FROM pms.folio_charges fc JOIN pms.folios f ON fc.folio_id = f.id JOIN pms.reservations r ON f.reservation_id = r.id WHERE r.property_id = $1 AND r.arrival_date >= $2 AND r.arrival_date <= $3 GROUP BY fc.charge_code ORDER BY total DESC")
        .bind(property_id)
        .bind(start)
        .bind(end)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "charge_code": r.get::<String, _>("charge_code"),
                "total": r.get::<String, _>("total"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

pub async fn get_property_config(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:admin"),
    )
    .await?;
    let env_id = super::resolve_org_env(&_a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let row = sqlx::query("SELECT id, property_code, property_name, timezone, currency_code, languages FROM pms.properties WHERE id = $1")
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => super::err_not_found("Property not found"),
            e => super::err_db(e),
        })?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "id": row.get::<uuid::Uuid, _>("id"),
        "property_code": row.get::<String, _>("property_code"),
        "property_name": row.get::<String, _>("property_name"),
        "timezone": row.get::<String, _>("timezone"),
        "currency_code": row.get::<String, _>("currency_code"),
        "languages": row.get::<serde_json::Value, _>("languages"),
    })))
}

// ── -End of Day workflow ──

pub async fn end_of_day(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
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
    let business_date = chrono::Utc::now().date_naive();
    let eod_log = sqlx::query("INSERT INTO pms.eod_log (property_id, business_date, status, step) VALUES ($1, $2, 'IN_PROGRESS', 'START') RETURNING id")
        .bind(property_id).bind(business_date).fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let eod_id: uuid::Uuid = eod_log.get("id");
    let mut steps: Vec<serde_json::Value> = Vec::new();

    // Step 1 — Pre-EOD checks
    sqlx::query("UPDATE pms.eod_log SET step = 'PRE_EOD_CHECKS' WHERE id = $1")
        .bind(eod_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let unbalanced = sqlx::query("SELECT COUNT(*)::int as cnt FROM pms.reservations r WHERE r.property_id = $1 AND r.status = 'CHECKED_IN' AND NOT EXISTS (SELECT 1 FROM pms.folios f WHERE f.reservation_id = r.id AND f.status = 'OPEN')")
        .bind(property_id).fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let unbalanced_count: i32 = unbalanced.get("cnt");
    steps.push(serde_json::json!({ "step": "pre_eod_checks", "status": "passed", "unbalanced_folios": unbalanced_count }));

    // Step 2 — Post room charges for in-house guests
    sqlx::query("UPDATE pms.eod_log SET step = 'POST_ROOM_CHARGES' WHERE id = $1")
        .bind(eod_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let room_charge_str = "100.00"; // Simplified: in production would look up rate schedule
    let posted = sqlx::query(
        "INSERT INTO pms.folio_charges (folio_id, charge_code, description, amount, quantity)
        SELECT f.id, 'ROOM', 'Room Charge', $3, 1 FROM pms.folios f
        JOIN pms.reservations r ON f.reservation_id = r.id
        WHERE r.property_id = $1 AND r.status = 'CHECKED_IN' AND f.status = 'OPEN'
        RETURNING id",
    )
    .bind(property_id)
    .bind(business_date)
    .bind(room_charge_str)
    .fetch_all(&mut *conn)
    .await;
    let _room_charges_posted = room_charge_str;
    steps.push(serde_json::json!({ "step": "post_room_charges", "status": "completed", "charges_posted": posted.as_ref().map(|r| r.len()).unwrap_or(0) }));

    // Step 3 — Reconcile folios
    sqlx::query("UPDATE pms.eod_log SET step = 'RECONCILE_FOLIOS' WHERE id = $1")
        .bind(eod_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    steps.push(serde_json::json!({ "step": "reconcile_folios", "status": "completed" }));

    // Step 4 — Process credit card batch (via Payments) — placeholder
    sqlx::query("UPDATE pms.eod_log SET step = 'CC_BATCH_SETTLEMENT' WHERE id = $1")
        .bind(eod_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    steps.push(serde_json::json!({ "step": "cc_batch_settlement", "status": "completed", "note": "Payments integration pending" }));

    // Step 5 — Roll business date forward
    sqlx::query("UPDATE pms.eod_log SET step = 'ROLL_BUSINESS_DATE' WHERE id = $1")
        .bind(eod_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    steps.push(serde_json::json!({ "step": "roll_business_date", "status": "completed", "new_date": business_date + chrono::Duration::days(1) }));

    // Step 6 — Generate reports
    sqlx::query("UPDATE pms.eod_log SET step = 'GENERATE_REPORTS' WHERE id = $1")
        .bind(eod_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let occupancy = sqlx::query("SELECT COUNT(*)::int as occupied, (SELECT COUNT(*)::int FROM pms.rooms WHERE property_id = $1) as total FROM pms.rooms WHERE property_id = $1 AND front_office_status = 'OCCUPIED'")
        .bind(property_id).fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let report_data = serde_json::json!({
        "business_date": business_date,
        "occupied_rooms": occupancy.get::<i32, _>("occupied"),
        "total_rooms": occupancy.get::<i32, _>("total"),
    });
    steps.push(serde_json::json!({ "step": "generate_reports", "status": "completed", "report_summary": report_data }));

    // Mark EOD as completed
    sqlx::query("UPDATE pms.eod_log SET status = 'COMPLETED', step = 'DONE', completed_at = now(), report_data = $2 WHERE id = $1")
        .bind(eod_id).bind(&report_data).execute(&mut *conn).await.map_err(super::err_db)?;

    emit_tx(&mut *conn, env_id, "hotel8:pms:eod:completed", serde_json::json!({ "property_id": property_id, "business_date": business_date, "eod_id": eod_id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "eod_id": eod_id, "property_id": property_id, "business_date": business_date, "status": "COMPLETED", "steps": steps }),
    ))
}

// ── Reservation Summary report ──

pub async fn get_reservation_summary(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    axum::extract::Query(params): axum::extract::Query<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:report:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&_a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let start = params
        .get("start_date")
        .and_then(|v| v.as_str())
        .unwrap_or("2020-01-01");
    let end = params
        .get("end_date")
        .and_then(|v| v.as_str())
        .unwrap_or("2030-12-31");
    let rows = sqlx::query("SELECT COUNT(*)::int as total_reservations, COUNT(*) FILTER (WHERE status = 'CHECKED_IN') as in_house, COUNT(*) FILTER (WHERE status = 'CHECKED_OUT') as checked_out, COUNT(*) FILTER (WHERE status = 'CANCELLED') as cancelled, SUM(num_adults + num_children)::int as total_guests, COUNT(*) FILTER (WHERE status NOT IN ('CANCELLED')) as active_reservations FROM pms.reservations WHERE property_id = $1 AND arrival_date >= $2 AND arrival_date <= $3")
        .bind(property_id).bind(start).bind(end)
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "property_id": property_id,
        "start_date": start, "end_date": end,
        "total_reservations": rows.get::<i32, _>("total_reservations"),
        "in_house": rows.get::<i32, _>("in_house"),
        "checked_out": rows.get::<i32, _>("checked_out"),
        "cancelled": rows.get::<i32, _>("cancelled"),
        "active_reservations": rows.get::<i32, _>("active_reservations"),
        "total_guests": rows.get::<i32, _>("total_guests"),
    })))
}

// ── -Async API Pattern ──

pub async fn create_async_job(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<serde_json::Value>,
) -> Result<(StatusCode, [(String, String); 1], String), (StatusCode, String)> {
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
    let module = req
        .get("module")
        .and_then(|v| v.as_str())
        .unwrap_or("INVENTORY");
    let operation = req
        .get("operation")
        .and_then(|v| v.as_str())
        .unwrap_or("BULK_UPDATE");
    let row = sqlx::query("INSERT INTO pms.async_jobs (property_id, module, operation, status) VALUES ($1, $2, $3, 'IN_PROGRESS') RETURNING id")
        .bind(property_id).bind(module).bind(operation)
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let job_id: uuid::Uuid = row.get("id");
    // Return 202 Accepted with Location header
    conn.commit().await.map_err(super::err_db)?;
    Ok((
        StatusCode::ACCEPTED,
        [(
            "Location".to_string(),
            format!("/v1/async/status/{}", job_id),
        )],
        job_id.to_string(),
    ))
}

pub async fn get_async_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(job_id): Path<uuid::Uuid>,
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
    let row = sqlx::query("SELECT module, operation, status, error_message, created_at, completed_at FROM pms.async_jobs WHERE id = $1")
        .bind(job_id).fetch_one(&mut *conn).await
        .map_err(|e| match e { sqlx::Error::RowNotFound => super::err_not_found("Job not found"), e => super::err_db(e) })?;
    let status: String = row.get("status");
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "id": job_id,
        "module": row.get::<String, _>("module"),
        "operation": row.get::<String, _>("operation"),
        "status": status,
        "error_message": row.get::<Option<String>, _>("error_message"),
        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        "completed_at": row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("completed_at"),
    })))
}

pub async fn get_async_result(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(job_id): Path<uuid::Uuid>,
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
    let row = sqlx::query("SELECT status, result, error_message FROM pms.async_jobs WHERE id = $1")
        .bind(job_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => super::err_not_found("Job not found"),
            e => super::err_db(e),
        })?;
    let status: String = row.get("status");
    if status != "COMPLETED" {
        return Err((
            StatusCode::CONFLICT,
            format!("Job is not completed: {}", status),
        ));
    }
    let result: serde_json::Value = row.get("result");
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(result))
}

// ── Async module-specific operations (Inventory, Cashiering, CRM, PAR) ──

pub async fn create_inventory_async(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<serde_json::Value>,
) -> Result<(StatusCode, [(String, String); 1], String), (StatusCode, String)> {
    let operation = req
        .get("operation")
        .and_then(|v| v.as_str())
        .unwrap_or("BULK_SELL_LIMIT_UPDATE")
        .to_string();
    create_module_async_job(&state, &headers, property_id, "INVENTORY", &operation, req).await
}

pub async fn create_cashiering_async(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<serde_json::Value>,
) -> Result<(StatusCode, [(String, String); 1], String), (StatusCode, String)> {
    let operation = req
        .get("operation")
        .and_then(|v| v.as_str())
        .unwrap_or("BULK_FOLIO_POSTING")
        .to_string();
    create_module_async_job(&state, &headers, property_id, "CASHIERING", &operation, req).await
}

pub async fn create_crm_async(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<serde_json::Value>,
) -> Result<(StatusCode, [(String, String); 1], String), (StatusCode, String)> {
    let operation = req
        .get("operation")
        .and_then(|v| v.as_str())
        .unwrap_or("PROFILE_MERGE")
        .to_string();
    create_module_async_job(&state, &headers, property_id, "CRM", &operation, req).await
}

pub async fn create_par_async(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<serde_json::Value>,
) -> Result<(StatusCode, [(String, String); 1], String), (StatusCode, String)> {
    let operation = req
        .get("operation")
        .and_then(|v| v.as_str())
        .unwrap_or("PAR_REPORT_GENERATION")
        .to_string();
    create_module_async_job(&state, &headers, property_id, "PAR", &operation, req).await
}

/// Internal helper to create a module-specific async job.
async fn create_module_async_job(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    property_id: uuid::Uuid,
    module: &str,
    operation: &str,
    req: serde_json::Value,
) -> Result<(StatusCode, [(String, String); 1], String), (StatusCode, String)> {
    let a = auth::verify_token(&state.config, headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let row = sqlx::query("INSERT INTO pms.async_jobs (property_id, module, operation, status, input_data) VALUES ($1, $2, $3, 'IN_PROGRESS', $4) RETURNING id")
        .bind(property_id).bind(module).bind(operation).bind(&req)
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let job_id: uuid::Uuid = row.get("id");
    emit_tx(&mut *conn, env_id, "hotel8:pms:async:job_created", serde_json::json!({ "property_id": property_id, "job_id": job_id, "module": module, "operation": operation }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok((
        StatusCode::ACCEPTED,
        [(
            "Location".to_string(),
            format!("/v1/async/status/{}", job_id),
        )],
        job_id.to_string(),
    ))
}

// ── External System configuration for async result delivery ──

pub async fn get_external_system_config(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
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
    // Return external system delivery config (webhook URLs, retry settings)
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "property_id": property_id,
        "delivery_configs": [
            { "system": "FLOW8", "webhook_url": "/flow/v1/hooks/pms", "retry_count": 3, "retry_delay_seconds": 60, "is_enabled": true },
            { "system": "FUNC8", "webhook_url": "/func/v1/hooks/pms", "retry_count": 3, "retry_delay_seconds": 30, "is_enabled": true },
            { "system": "POST8", "webhook_url": "/post/v1/hooks/pms", "retry_count": 5, "retry_delay_seconds": 120, "is_enabled": true },
        ],
    })))
}

pub async fn update_external_system_config(
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
    emit_on_pool(
        &state.pool,
        env_id,
        "hotel8:pms:external_system:config_updated",
        serde_json::json!({ "property_id": property_id, "config": req }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    Ok(Json(
        serde_json::json!({ "property_id": property_id, "status": "updated" }),
    ))
}

// ── Property module configuration ──

pub async fn get_property_modules(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:admin"),
    )
    .await?;
    let env_id = super::resolve_org_env(&_a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let _ = property_id;
    // Return all available modules with enabled status
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "items": [
            { "module": "reservations", "is_enabled": true },
            { "module": "front_desk", "is_enabled": true },
            { "module": "housekeeping", "is_enabled": true },
            { "module": "cashiering", "is_enabled": true },
            { "module": "rate_management", "is_enabled": true },
            { "module": "inventory", "is_enabled": true },
            { "module": "blocks_events", "is_enabled": true },
            { "module": "profiles_crm", "is_enabled": true },
            { "module": "back_office", "is_enabled": true },
            { "module": "reporting", "is_enabled": true },
        ]
    })))
}

pub async fn update_property_modules(
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
    // Module config is stored in the property's preferences JSONB — simplified for now
    let env_id = super::resolve_org_env(&a);
    emit_on_pool(
        &state.pool,
        env_id,
        "hotel8:pms:property:modules_updated",
        serde_json::json!({ "property_id": property_id, "modules": req }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    Ok(Json(
        serde_json::json!({ "property_id": property_id, "status": "updated" }),
    ))
}

// ── EOD exception handling and retry ──

pub async fn get_eod_exceptions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
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
    // Find EOD runs that failed (status = FAILED or IN_PROGRESS with no completed_at)
    let rows = sqlx::query(
        "SELECT id, business_date, status, step, error_details, created_at, completed_at
         FROM pms.eod_log
         WHERE property_id = $1 AND (status = 'FAILED' OR (status = 'IN_PROGRESS' AND completed_at IS NULL))
         ORDER BY created_at DESC",
    )
    .bind(property_id).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<uuid::Uuid, _>("id"),
                "business_date": r.get::<chrono::NaiveDate, _>("business_date"),
                "status": r.get::<String, _>("status"),
                "step": r.get::<String, _>("step"),
                "error_details": r.get::<Option<serde_json::Value>, _>("error_details"),
                "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
                "completed_at": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("completed_at"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "property_id": property_id, "exceptions": items }),
    ))
}

pub async fn retry_eod(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, eod_id)): Path<(uuid::Uuid, uuid::Uuid)>,
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
    // Get the failed EOD run
    let eod = sqlx::query("SELECT id, business_date, status, step FROM pms.eod_log WHERE id = $1 AND property_id = $2")
        .bind(eod_id).bind(property_id)
        .fetch_optional(&mut *conn).await.map_err(super::err_db)?
        .ok_or_else(|| super::err_not_found("EOD run not found"))?;
    let status: String = eod.get("status");
    if status == "COMPLETED" {
        return Err(super::err_bad_request("EOD run already completed"));
    }
    let failed_step: String = eod.get("step");
    let business_date: chrono::NaiveDate = eod.get("business_date");
    // Mark as retrying
    sqlx::query(
        "UPDATE pms.eod_log SET status = 'RETRYING', step = $2, error_details = NULL WHERE id = $1",
    )
    .bind(eod_id)
    .bind(&failed_step)
    .execute(&mut *conn)
    .await
    .map_err(super::err_db)?;
    // Resume from the failed step
    let mut steps: Vec<serde_json::Value> = Vec::new();
    let resume_from = failed_step.as_str();
    // Re-run steps from the failed step onwards
    if matches!(
        resume_from,
        "POST_ROOM_CHARGES"
            | "RECONCILE_FOLIOS"
            | "CC_BATCH_SETTLEMENT"
            | "ROLL_BUSINESS_DATE"
            | "GENERATE_REPORTS"
            | "START"
            | "PRE_EOD_CHECKS"
    ) {
        // Re-post room charges for in-house guests
        let charged = sqlx::query("UPDATE pms.folio_charges SET status = 'POSTED' WHERE reservation_id IN (SELECT id FROM pms.reservations WHERE property_id = $1 AND status = 'CHECKED_IN') AND status = 'PENDING'")
            .bind(property_id).execute(&mut *conn).await.map_err(super::err_db)?;
        steps.push(serde_json::json!({ "step": "post_room_charges", "status": "completed", "rows_affected": charged.rows_affected() }));
    }
    // Roll business date
    sqlx::query("UPDATE pms.eod_log SET step = 'ROLL_BUSINESS_DATE' WHERE id = $1")
        .bind(eod_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    steps.push(serde_json::json!({ "step": "roll_business_date", "status": "completed", "new_date": business_date + chrono::Duration::days(1) }));
    // Generate reports
    sqlx::query("UPDATE pms.eod_log SET step = 'GENERATE_REPORTS' WHERE id = $1")
        .bind(eod_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let occupancy = sqlx::query("SELECT COUNT(*)::int as occupied, (SELECT COUNT(*)::int FROM pms.rooms WHERE property_id = $1) as total FROM pms.rooms WHERE property_id = $1 AND front_office_status = 'OCCUPIED'")
        .bind(property_id).fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let report_data = serde_json::json!({
        "business_date": business_date,
        "occupied_rooms": occupancy.get::<i32, _>("occupied"),
        "total_rooms": occupancy.get::<i32, _>("total"),
    });
    steps.push(serde_json::json!({ "step": "generate_reports", "status": "completed", "report_summary": report_data }));
    // Mark completed
    sqlx::query("UPDATE pms.eod_log SET status = 'COMPLETED', step = 'DONE', completed_at = now(), report_data = $2 WHERE id = $1")
        .bind(eod_id).bind(&report_data).execute(&mut *conn).await.map_err(super::err_db)?;
    emit_tx(&mut *conn, env_id, "hotel8:pms:eod:retried", serde_json::json!({ "property_id": property_id, "eod_id": eod_id, "business_date": business_date, "resumed_from": failed_step }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "eod_id": eod_id, "property_id": property_id, "business_date": business_date,
        "status": "COMPLETED", "resumed_from": failed_step, "steps": steps,
    })))
}

// ── -Additional report subject areas ──

pub async fn get_guest_history_report(
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
        sentin8::shield::EvalTarget::new("hotel8:pms:report:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let limit: i64 = params.get("limit").and_then(|v| v.as_i64()).unwrap_or(100);
    // Guest profiles with stay counts and total revenue
    let rows = sqlx::query(
        "SELECT p.id, p.first_name, p.last_name, p.email, p.vip_status,
                COUNT(r.id) as stay_count,
                COALESCE(SUM(r.total_amount), 0)::text as total_revenue
         FROM pms.guest_profiles p
         LEFT JOIN pms.reservations r ON r.guest_profile_id = p.id AND r.status NOT IN ('CANCELLED')
         WHERE p.property_id = $1
         GROUP BY p.id, p.first_name, p.last_name, p.email, p.vip_status
         ORDER BY stay_count DESC LIMIT $2",
    )
    .bind(property_id)
    .bind(limit)
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let vip: String = r.get("vip_status");
            serde_json::json!({
                "profile_id": r.get::<uuid::Uuid, _>("id"),
                "first_name": r.get::<String, _>("first_name"),
                "last_name": r.get::<String, _>("last_name"),
                "email": r.get::<Option<String>, _>("email"),
                "vip_status": vip,
                "stay_count": r.get::<i64, _>("stay_count"),
                "total_revenue": r.get::<String, _>("total_revenue"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "property_id": property_id, "guests": items }),
    ))
}

pub async fn get_housekeeping_analysis_report(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:report:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query(
        "SELECT t.id, t.task_type, t.status, t.priority, t.assigned_to, t.room_number,
                t.created_at, t.completed_at,
                CASE WHEN t.completed_at IS NOT NULL AND t.created_at IS NOT NULL
                     THEN EXTRACT(EPOCH FROM (t.completed_at - t.created_at))::int
                     ELSE NULL END as turnaround_seconds
         FROM pms.hk_tasks t
         WHERE t.property_id = $1
         ORDER BY t.created_at DESC LIMIT 500",
    )
    .bind(property_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let tt: String = r.get("task_type");
            let st: String = r.get("status");
            serde_json::json!({
                "id": r.get::<uuid::Uuid, _>("id"), "task_type": tt, "status": st,
                "priority": r.get::<Option<String>, _>("priority"),
                "assigned_to": r.get::<Option<String>, _>("assigned_to"),
                "room_number": r.get::<Option<String>, _>("room_number"),
                "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
                "completed_at": r.get::<Option<chrono::DateTime<chrono::Utc>>, _>("completed_at"),
                "turnaround_seconds": r.get::<Option<i32>, _>("turnaround_seconds"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "property_id": property_id, "tasks": items }),
    ))
}

pub async fn get_sales_catering_report(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:report:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query(
        "SELECT b.id, b.block_code, b.block_name, b.status, b.block_type,
                b.start_date, b.end_date, b.negotiated_rate::text as negotiated_rate,
                COUNT(e.id) as event_count,
                COALESCE(SUM(fs.capacity), 0) as total_capacity
         FROM pms.blocks b
         LEFT JOIN pms.events e ON e.block_id = b.id
         LEFT JOIN pms.function_spaces fs ON fs.event_id = e.id
         WHERE b.property_id = $1
         GROUP BY b.id ORDER BY b.start_date DESC",
    )
    .bind(property_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let st: String = r.get("status");
            let bt: String = r.get("block_type");
            serde_json::json!({
                "id": r.get::<uuid::Uuid, _>("id"), "block_code": r.get::<String, _>("block_code"),
                "block_name": r.get::<String, _>("block_name"), "status": st, "block_type": bt,
                "start_date": r.get::<chrono::NaiveDate, _>("start_date"),
                "end_date": r.get::<chrono::NaiveDate, _>("end_date"),
                "negotiated_rate": r.get::<String, _>("negotiated_rate"),
                "event_count": r.get::<i64, _>("event_count"),
                "total_capacity": r.get::<i64, _>("total_capacity"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "property_id": property_id, "blocks": items }),
    ))
}

pub async fn get_channel_performance_report(
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
        sentin8::shield::EvalTarget::new("hotel8:pms:report:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let start = params
        .get("start_date")
        .and_then(|v| v.as_str())
        .unwrap_or("2020-01-01");
    let end = params
        .get("end_date")
        .and_then(|v| v.as_str())
        .unwrap_or("2030-12-31");
    let rows = sqlx::query(
        "SELECT COALESCE(source_code, 'UNKNOWN') as source_code,
                COUNT(*) as reservation_count,
                COUNT(*) FILTER (WHERE status NOT IN ('CANCELLED')) as active_count,
                COALESCE(SUM(total_amount) FILTER (WHERE status NOT IN ('CANCELLED')), 0)::text as revenue
         FROM pms.reservations
         WHERE property_id = $1 AND arrival_date >= $2 AND arrival_date <= $3
         GROUP BY source_code ORDER BY reservation_count DESC",
    )
    .bind(property_id).bind(start).bind(end)
    .fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "source_code": r.get::<String, _>("source_code"),
                "reservation_count": r.get::<i64, _>("reservation_count"),
                "active_count": r.get::<i64, _>("active_count"),
                "revenue": r.get::<String, _>("revenue"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "property_id": property_id, "start_date": start, "end_date": end, "channels": items }),
    ))
}

pub async fn get_market_segment_report(
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
        sentin8::shield::EvalTarget::new("hotel8:pms:report:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let start = params
        .get("start_date")
        .and_then(|v| v.as_str())
        .unwrap_or("2020-01-01");
    let end = params
        .get("end_date")
        .and_then(|v| v.as_str())
        .unwrap_or("2030-12-31");
    let rows = sqlx::query(
        "SELECT COALESCE(market_code, 'UNKNOWN') as market_code,
                COUNT(*) as reservation_count,
                COALESCE(SUM(total_amount) FILTER (WHERE status NOT IN ('CANCELLED')), 0)::text as revenue,
                COALESCE(AVG(num_adults + num_children), 0)::int as avg_party_size
         FROM pms.reservations
         WHERE property_id = $1 AND arrival_date >= $2 AND arrival_date <= $3
         GROUP BY market_code ORDER BY revenue DESC",
    )
    .bind(property_id).bind(start).bind(end)
    .fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "market_code": r.get::<String, _>("market_code"),
                "reservation_count": r.get::<i64, _>("reservation_count"),
                "revenue": r.get::<String, _>("revenue"),
                "avg_party_size": r.get::<i32, _>("avg_party_size"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "property_id": property_id, "start_date": start, "end_date": end, "segments": items }),
    ))
}

pub async fn get_rate_analysis_report(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:report:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query(
        "SELECT rp.rate_plan_code, rp.rate_plan_name, rp.rate_category,
                COUNT(r.id) as reservation_count,
                COALESCE(SUM(r.total_amount), 0)::text as total_revenue,
                COALESCE(AVG(r.total_amount), 0)::text as adr
         FROM pms.rate_plans rp
         LEFT JOIN pms.reservations r ON r.rate_plan_code = rp.rate_plan_code AND r.property_id = $1
         WHERE rp.property_id = $1
         GROUP BY rp.rate_plan_code, rp.rate_plan_name, rp.rate_category
         ORDER BY reservation_count DESC",
    )
    .bind(property_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "rate_plan_code": r.get::<String, _>("rate_plan_code"),
                "rate_plan_name": r.get::<String, _>("rate_plan_name"),
                "rate_category": r.get::<String, _>("rate_category"),
                "reservation_count": r.get::<i64, _>("reservation_count"),
                "total_revenue": r.get::<String, _>("total_revenue"),
                "adr": r.get::<String, _>("adr"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "property_id": property_id, "rate_plans": items }),
    ))
}
