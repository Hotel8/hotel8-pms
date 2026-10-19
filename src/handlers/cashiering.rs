// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Cashiering / Folio handlers.
use crate::auth;
use crate::handlers::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use hotel8::pms::contracts::{
    ChargePostRequest, DisputeChargeRequest, DisputeResult, FolioChargeView, FolioGenerated,
    FolioPaymentView, FolioResponse, PaymentPostRequest, PostedCharge, PostedPayment,
    TransactionCode, TransactionCodeList, VoucherRedeemRequest, VoucherRedeemResult,
    VoucherValidateRequest, VoucherValidation,
};
use sqlx::Row;
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/reservations/{res_id}/folio",
    responses(
        (status = 200, description = "Guest folio with charges and payments", body = FolioResponse),
        (status = 404, description = "Folio not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn get_folio(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<FolioResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:read"),
    )
    .await?;
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
    let charges: Vec<FolioChargeView> = charges
        .iter()
        .map(|r| FolioChargeView {
            id: r.get::<uuid::Uuid, _>("id"),
            charge_code: r.get::<String, _>("charge_code"),
            description: r.get::<String, _>("description"),
            amount: r.get::<String, _>("amount"),
            quantity: r.get::<i32, _>("quantity"),
            created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        })
        .collect();
    let payments: Vec<FolioPaymentView> = payments
        .iter()
        .map(|r| FolioPaymentView {
            id: r.get::<uuid::Uuid, _>("id"),
            payment_code: r.get::<String, _>("payment_code"),
            amount: r.get::<String, _>("amount"),
            reference: r.get::<Option<String>, _>("reference"),
            created_at: r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(FolioResponse {
        id: folio_id,
        reservation_id: res_id,
        property_id,
        status,
        closed_at: folio.get::<Option<chrono::DateTime<chrono::Utc>>, _>("closed_at"),
        payment_method: folio.get::<Option<String>, _>("payment_method"),
        charges,
        payments,
    }))
}
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations/{res_id}/charges",
    request_body = ChargePostRequest,
    responses(
        (status = 200, description = "Charge posted to the open folio", body = PostedCharge),
        (status = 404, description = "No open folio for reservation"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn post_charge(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<ChargePostRequest>,
) -> Result<Json<PostedCharge>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:write"),
    )
    .await?;
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
    let charge_code = req.charge_code;
    let description = req.description;
    let amount: rust_decimal::Decimal = req
        .amount
        .parse()
        .unwrap_or_default();
    let quantity: i32 = req.quantity;
    let row = sqlx::query("INSERT INTO pms.folio_charges (folio_id, charge_code, description, amount, quantity) VALUES ($1, $2, $3, $4::numeric, $5) RETURNING id, charge_code, description, amount::text as amount, quantity, created_at")
        .bind(folio_id)
        .bind(&charge_code)
        .bind(&description)
        .bind(amount.to_string())
        .bind(quantity)
        .fetch_one(&mut *conn)
        .await
        .map_err(super::err_db)?;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:folio:charge_posted",
        serde_json::json!({ "folio_id": folio_id, "charge_code": &charge_code, "amount": amount }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    let amount_str: String = row.get("amount");
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(PostedCharge {
        id: row.get::<uuid::Uuid, _>("id"),
        folio_id,
        charge_code: row.get::<String, _>("charge_code"),
        description: row.get::<String, _>("description"),
        amount: amount_str,
        quantity: row.get::<i32, _>("quantity"),
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    }))
}
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations/{res_id}/payments",
    request_body = PaymentPostRequest,
    responses(
        (status = 200, description = "Payment posted to the open folio", body = PostedPayment),
        (status = 404, description = "No open folio for reservation"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn post_payment(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<PaymentPostRequest>,
) -> Result<Json<PostedPayment>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:write"),
    )
    .await?;
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
    let payment_code = req.payment_code;
    let amount: rust_decimal::Decimal = req
        .amount
        .parse()
        .unwrap_or_default();
    let reference = req.reference;
    let row = sqlx::query("INSERT INTO pms.folio_payments (folio_id, payment_code, amount, reference) VALUES ($1, $2, $3::numeric, $4) RETURNING id, payment_code, amount::text as amount, reference, created_at")
        .bind(folio_id)
        .bind(&payment_code)
        .bind(amount.to_string())
        .bind(reference)
        .fetch_one(&mut *conn)
        .await
        .map_err(super::err_db)?;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:folio:payment_posted",
        serde_json::json!({ "folio_id": folio_id, "payment_code": &payment_code, "amount": amount }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    let amount_str: String = row.get("amount");
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(PostedPayment {
        id: row.get::<uuid::Uuid, _>("id"),
        folio_id,
        payment_code: row.get::<String, _>("payment_code"),
        amount: amount_str,
        reference: row.get::<Option<String>, _>("reference"),
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    }))
}

// ── Folio Generation ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations/{res_id}/folio/generate",
    responses(
        (status = 200, description = "Printable folio number generated", body = FolioGenerated),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn generate_folio(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<Json<FolioGenerated>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let folio_number = format!("FOL-{}/{}", chrono::Utc::now().format("%Y%m%d"), res_id);
    let _ = sqlx::query("UPDATE pms.folios SET payment_method = COALESCE(payment_method, 'GENERATED'), updated_at = now() WHERE reservation_id = $1 AND property_id = $2 AND status = 'OPEN'")
        .bind(res_id).bind(property_id).execute(&mut *conn).await.map_err(super::err_db)?;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:folio:generated",
        serde_json::json!({ "reservation_id": res_id, "folio_number": &folio_number }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(FolioGenerated {
        reservation_id: res_id,
        folio_number: folio_number,
        status: "generated".to_string(),
    }))
}

// ── Folio dispute handling ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/reservations/{res_id}/charges/dispute",
    request_body = DisputeChargeRequest,
    responses(
        (status = 200, description = "Dispute recorded, rebate charge posted", body = DisputeResult),
        (status = 400, description = "charge_id required"),
        (status = 404, description = "No open folio"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn dispute_charge(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, res_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<DisputeChargeRequest>,
) -> Result<Json<DisputeResult>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let charge_id: uuid::Uuid = req.charge_id;
    let reason = req.reason;
    let rebate_amount_str = req.rebate_amount;
    // Post a rebate charge
    let folio = sqlx::query("SELECT id FROM pms.folios WHERE reservation_id = $1 AND property_id = $2 AND status = 'OPEN' ORDER BY created_at DESC LIMIT 1")
        .bind(res_id).bind(property_id).fetch_one(&mut *conn).await.map_err(|e| match e { sqlx::Error::RowNotFound => (StatusCode::NOT_FOUND, "No open folio".to_string()), e => super::err_db(e) })?;
    let folio_id: uuid::Uuid = folio.get("id");
    let row = sqlx::query("INSERT INTO pms.folio_charges (folio_id, charge_code, description, amount, quantity) VALUES ($1, 'REBATE', $2, $3::numeric, 1) RETURNING id, charge_code, description, amount::text as amount")
        .bind(folio_id).bind(format!("Rebate for dispute: {}", &reason)).bind(format!("-{}", &rebate_amount_str))
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:folio:disputed", serde_json::json!({ "charge_id": charge_id, "reason": &reason, "rebate_amount": &rebate_amount_str }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(DisputeResult {
        rebate_id: row.get::<uuid::Uuid, _>("id"),
        original_charge_id: charge_id,
        reason: reason,
        rebate_amount: row.get::<String, _>("amount"),
    }))
}

// ── Transaction Code management ──
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/transaction-codes",
    responses(
        (status = 200, description = "Transaction codes (property rows or system defaults)", body = TransactionCodeList),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn list_transaction_codes(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<TransactionCodeList>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    // Check if property has specific transaction codes; if not, return system defaults
    let rows = sqlx::query("SELECT id, code, description, category, is_active FROM pms.transaction_codes WHERE property_id = $1 ORDER BY sort_order, code")
        .bind(property_id).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    if rows.is_empty() {
        let defaults = sqlx::query("SELECT lov_code as code, lov_value as description FROM pms.lov_defaults WHERE lov_type = 'TRANSACTION_CODE' ORDER BY sort_order")
            .fetch_all(&mut *conn).await.map_err(super::err_db)?;
        let items: Vec<TransactionCode> = defaults
            .iter()
            .map(|r| TransactionCode {
                id: None,
                code: r.get::<String, _>("code"),
                description: r.get::<String, _>("description"),
                category: "GENERAL".to_string(),
                is_active: true,
            })
            .collect();
        return Ok(Json(TransactionCodeList {
            items,
            source: "defaults".to_string(),
        }));
    }
    let items: Vec<TransactionCode> = rows
        .iter()
        .map(|r| TransactionCode {
            id: Some(r.get::<uuid::Uuid, _>("id")),
            code: r.get::<String, _>("code"),
            description: r.get::<String, _>("description"),
            category: r.get::<String, _>("category"),
            is_active: r.get::<bool, _>("is_active"),
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(TransactionCodeList {
        items,
        source: "property".to_string(),
    }))
}

// ── -Gift Voucher validation and redemption ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/vouchers/validate",
    request_body = VoucherValidateRequest,
    responses(
        (status = 200, description = "Voucher validation (valid=false + error reason when not found)", body = VoucherValidation),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn validate_voucher(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<VoucherValidateRequest>,
) -> Result<Json<VoucherValidation>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:read"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let voucher_number = req.voucher_number;
    let row = sqlx::query("SELECT id, balance::text as balance, currency_code, status, expires_at FROM pms.gift_vouchers WHERE property_id = $1 AND voucher_number = $2")
        .bind(property_id).bind(&voucher_number).fetch_optional(&mut *conn).await.map_err(super::err_db)?;
    match row {
        Some(r) => {
            let status: String = r.get("status");
            let expires_at: Option<chrono::DateTime<chrono::Utc>> = r.get("expires_at");
            let is_expired = expires_at.map(|d| d < chrono::Utc::now()).unwrap_or(false);
            conn.commit().await.map_err(super::err_db)?;
            Ok(Json(VoucherValidation {
                valid: status == "ACTIVE" && !is_expired,
                voucher_number: voucher_number,
                balance: Some(r.get::<String, _>("balance")),
                currency_code: Some(r.get::<String, _>("currency_code")),
                status: Some(status),
                expires_at,
                error: None,
            }))
        }
        None => Ok(Json(VoucherValidation {
            valid: false,
            voucher_number: voucher_number,
            balance: None,
            currency_code: None,
            status: None,
            expires_at: None,
            error: Some("Voucher not found".to_string()),
        })),
    }
}
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/vouchers/redeem",
    request_body = VoucherRedeemRequest,
    responses(
        (status = 200, description = "Voucher redeemed", body = VoucherRedeemResult),
        (status = 400, description = "Voucher not found, inactive, or insufficient balance"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn redeem_voucher(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<VoucherRedeemRequest>,
) -> Result<Json<VoucherRedeemResult>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:cashiering:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let voucher_number = req.voucher_number;
    let amount_str = req.amount;
    let row = sqlx::query("UPDATE pms.gift_vouchers SET balance = balance - $3 WHERE property_id = $1 AND voucher_number = $2 AND status = 'ACTIVE' AND balance >= $3 RETURNING id, balance::text as balance, voucher_number")
        .bind(property_id).bind(&voucher_number).bind(&amount_str)
        .fetch_one(&mut *conn).await.map_err(|e| match e {
            sqlx::Error::RowNotFound => (StatusCode::BAD_REQUEST, "Voucher not found, inactive, or insufficient balance".to_string()),
            e => super::err_db(e),
        })?;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:voucher:redeemed",
        serde_json::json!({ "voucher_number": &voucher_number, "amount": &amount_str }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(VoucherRedeemResult {
        voucher_number: row.get::<String, _>("voucher_number"),
        redeemed_amount: amount_str,
        remaining_balance: row.get::<String, _>("balance"),
    }))
}
