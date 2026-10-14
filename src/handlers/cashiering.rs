// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Cashiering / Folio handlers.
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sqlx::Row;
use crate::handlers::AppState;
use crate::auth;

pub async fn get_folio(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:read")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let folio = sqlx::query("SELECT * FROM pms.folios WHERE reservation_id = $1 AND property_id = $2 ORDER BY created_at DESC LIMIT 1")
        .bind(res_id)
        .bind(property_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let folio = match folio {
        Some(f) => f,
        None => return Err(super::err_not_found("Folio not found")),
    };
    let folio_id: uuid::Uuid = folio.get("id");
    let charges = sqlx::query("SELECT id, charge_code, description, amount::text as amount, quantity, created_at FROM pms.folio_charges WHERE folio_id = $1 ORDER BY created_at")
        .bind(folio_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let payments = sqlx::query("SELECT id, payment_code, amount::text as amount, reference, created_at FROM pms.folio_payments WHERE folio_id = $1 ORDER BY created_at")
        .bind(folio_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let status: String = folio.get("status");
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "id": folio_id,
        "reservation_id": res_id,
        "property_id": property_id,
        "status": status,
        "closed_at": folio.get::<Option<chrono::DateTime<chrono::Utc>>, _>("closed_at"),
        "payment_method": folio.get::<Option<String>, _>("payment_method"),
        "charges": charges.iter().map(|r| serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id"),
            "charge_code": r.get::<String, _>("charge_code"),
            "description": r.get::<String, _>("description"),
            "amount": r.get::<String, _>("amount"),
            "quantity": r.get::<i32, _>("quantity"),
            "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        })).collect::<Vec<_>>(),
        "payments": payments.iter().map(|r| serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id"),
            "payment_code": r.get::<String, _>("payment_code"),
            "amount": r.get::<String, _>("amount"),
            "reference": r.get::<Option<String>, _>("reference"),
            "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        })).collect::<Vec<_>>(),
    })))
}

pub async fn post_charge(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:write")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let folio = sqlx::query("SELECT id FROM pms.folios WHERE reservation_id = $1 AND property_id = $2 AND status = 'OPEN' ORDER BY created_at DESC LIMIT 1")
        .bind(res_id)
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "No open folio for reservation".to_string()),
            e => super::err_db(e),
        })?;
    let folio_id: uuid::Uuid = folio.get("id");
    let charge_code = req.get("charge_code").and_then(|v| v.as_str()).unwrap_or("ROOM");
    let description = req.get("description").and_then(|v| v.as_str()).unwrap_or("");
    let amount: rust_decimal::Decimal = req.get("amount")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or_default();
    let quantity: i32 = req.get("quantity").and_then(|v| v.as_u64()).unwrap_or(1) as i32;
    let row = sqlx::query("INSERT INTO pms.folio_charges (folio_id, charge_code, description, amount, quantity) VALUES ($1, $2, $3, $4::numeric, $5) RETURNING id, charge_code, description, amount::text as amount, quantity, created_at")
        .bind(folio_id)
        .bind(charge_code)
        .bind(description)
        .bind(amount.to_string())
        .bind(quantity)
        .fetch_one(&mut *conn)
        .await
        .map_err(super::err_db)?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:folio:charge_posted", serde_json::json!({ "folio_id": folio_id, "charge_code": charge_code, "amount": amount }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    let amount_str: String = row.get("amount");
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "id": row.get::<uuid::Uuid, _>("id"),
        "folio_id": folio_id,
        "charge_code": row.get::<String, _>("charge_code"),
        "description": row.get::<String, _>("description"),
        "amount": amount_str,
        "quantity": row.get::<i32, _>("quantity"),
        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    })))
}

pub async fn post_payment(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:write")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let folio = sqlx::query("SELECT id FROM pms.folios WHERE reservation_id = $1 AND property_id = $2 AND status = 'OPEN' ORDER BY created_at DESC LIMIT 1")
        .bind(res_id)
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "No open folio for reservation".to_string()),
            e => super::err_db(e),
        })?;
    let folio_id: uuid::Uuid = folio.get("id");
    let payment_code = req.get("payment_code").and_then(|v| v.as_str()).unwrap_or("CASH");
    let amount: rust_decimal::Decimal = req.get("amount")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or_default();
    let reference = req.get("reference").and_then(|v| v.as_str());
    let row = sqlx::query("INSERT INTO pms.folio_payments (folio_id, payment_code, amount, reference) VALUES ($1, $2, $3::numeric, $4) RETURNING id, payment_code, amount::text as amount, reference, created_at")
        .bind(folio_id)
        .bind(payment_code)
        .bind(amount.to_string())
        .bind(reference)
        .fetch_one(&mut *conn)
        .await
        .map_err(super::err_db)?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:folio:payment_posted", serde_json::json!({ "folio_id": folio_id, "payment_code": payment_code, "amount": amount }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    let amount_str: String = row.get("amount");
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "id": row.get::<uuid::Uuid, _>("id"),
        "folio_id": folio_id,
        "payment_code": row.get::<String, _>("payment_code"),
        "amount": amount_str,
        "reference": row.get::<Option<String>, _>("reference"),
        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    })))
}

// ── Folio Generation ──

pub async fn generate_folio(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:write")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let folio_number = format!("FOL-{}/{}", chrono::Utc::now().format("%Y%m%d"), res_id);
    let _ = sqlx::query("UPDATE pms.folios SET payment_method = COALESCE(payment_method, 'GENERATED'), updated_at = now() WHERE reservation_id = $1 AND property_id = $2 AND status = 'OPEN'")
        .bind(res_id).bind(property_id).execute(&mut *conn).await.map_err(super::err_db)?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:folio:generated", serde_json::json!({ "reservation_id": res_id, "folio_number": &folio_number }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "reservation_id": res_id, "folio_number": folio_number, "status": "generated" })))
}

// ── Folio dispute handling ──

pub async fn dispute_charge(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:write")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let charge_id: uuid::Uuid = req.get("charge_id").and_then(|v| v.as_str()).and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "charge_id required".to_string()))?;
    let reason = req.get("reason").and_then(|v| v.as_str()).unwrap_or("");
    let rebate_amount_str = req.get("rebate_amount").and_then(|v| v.as_str()).unwrap_or("0");
    // Post a rebate charge
    let folio = sqlx::query("SELECT id FROM pms.folios WHERE reservation_id = $1 AND property_id = $2 AND status = 'OPEN' ORDER BY created_at DESC LIMIT 1")
        .bind(res_id).bind(property_id).fetch_one(&mut *conn).await.map_err(|e| match e { sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "No open folio".to_string()), e => super::err_db(e) })?;
    let folio_id: uuid::Uuid = folio.get("id");
    let row = sqlx::query("INSERT INTO pms.folio_charges (folio_id, charge_code, description, amount, quantity) VALUES ($1, 'REBATE', $2, $3::numeric, 1) RETURNING id, charge_code, description, amount::text as amount")
        .bind(folio_id).bind(format!("Rebate for dispute: {}", reason)).bind(format!("-{}", rebate_amount_str))
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:folio:disputed", serde_json::json!({ "charge_id": charge_id, "reason": reason, "rebate_amount": rebate_amount_str }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "rebate_id": row.get::<uuid::Uuid, _>("id"), "original_charge_id": charge_id, "reason": reason, "rebate_amount": row.get::<String, _>("amount") })))
}

// ── Transaction Code management ──

pub async fn list_transaction_codes(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:read")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    // Check if property has specific transaction codes; if not, return system defaults
    let rows = sqlx::query("SELECT id, code, description, category, is_active FROM pms.transaction_codes WHERE property_id = $1 ORDER BY sort_order, code")
        .bind(property_id).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    if rows.is_empty() {
        let defaults = sqlx::query("SELECT lov_code as code, lov_value as description FROM pms.lov_defaults WHERE lov_type = 'TRANSACTION_CODE' ORDER BY sort_order")
            .fetch_all(&mut *conn).await.map_err(super::err_db)?;
        let items: Vec<serde_json::Value> = defaults.iter().map(|r| serde_json::json!({
            "code": r.get::<String, _>("code"), "description": r.get::<String, _>("description"),
            "category": "GENERAL", "is_active": true,
        })).collect();
        return Ok(Json(serde_json::json!({ "items": items, "source": "defaults" })));
    }
    let items: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "id": r.get::<uuid::Uuid, _>("id"), "code": r.get::<String, _>("code"),
        "description": r.get::<String, _>("description"), "category": r.get::<String, _>("category"),
        "is_active": r.get::<bool, _>("is_active"),
    })).collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items, "source": "property" })))
}

// ── -Gift Voucher validation and redemption ──

pub async fn validate_voucher(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:read")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let voucher_number = req.get("voucher_number").and_then(|v| v.as_str()).unwrap_or("");
    let row = sqlx::query("SELECT id, balance::text as balance, currency_code, status, expires_at FROM pms.gift_vouchers WHERE property_id = $1 AND voucher_number = $2")
        .bind(property_id).bind(voucher_number).fetch_optional(&mut *conn).await.map_err(super::err_db)?;
    match row {
        Some(r) => {
            let status: String = r.get("status");
            let expires_at: Option<chrono::DateTime<chrono::Utc>> = r.get("expires_at");
            let is_expired = expires_at.map(|d| d < chrono::Utc::now()).unwrap_or(false);
            conn.commit().await.map_err(super::err_db)?;
            Ok(Json(serde_json::json!({ "valid": status == "ACTIVE" && !is_expired, "voucher_number": voucher_number, "balance": r.get::<String, _>("balance"), "currency_code": r.get::<String, _>("currency_code"), "status": status, "expires_at": expires_at })))
        }
        None => Ok(Json(serde_json::json!({ "valid": false, "voucher_number": voucher_number, "error": "Voucher not found" }))),
    }
}

pub async fn redeem_voucher(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:write")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let voucher_number = req.get("voucher_number").and_then(|v| v.as_str()).unwrap_or("");
    let amount_str = req.get("amount").and_then(|v| v.as_str()).unwrap_or("0");
    let row = sqlx::query("UPDATE pms.gift_vouchers SET balance = balance - $3 WHERE property_id = $1 AND voucher_number = $2 AND status = 'ACTIVE' AND balance >= $3 RETURNING id, balance::text as balance, voucher_number")
        .bind(property_id).bind(voucher_number).bind(amount_str)
        .fetch_one(&mut *conn).await.map_err(|e| match e {
            sqlx::Error::RowNotFound => (StatusCode::BAD_REQUEST, "Voucher not found, inactive, or insufficient balance".to_string()),
            e => super::err_db(e),
        })?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:voucher:redeemed", serde_json::json!({ "voucher_number": voucher_number, "amount": amount_str }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "voucher_number": row.get::<String, _>("voucher_number"), "redeemed_amount": amount_str, "remaining_balance": row.get::<String, _>("balance") })))
}