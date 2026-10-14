// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Property management handlers.
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use crate::handlers::AppState;
use crate::auth;
use hotel8::pms::contracts::{Property, PropertyCreate};

pub async fn create_property(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PropertyCreate>,
) -> Result<Json<Property>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:admin")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let row = sqlx::query_as::<_, PropertyRow>(
        "INSERT INTO pms.properties (env_id, property_code, property_name, timezone, currency_code, languages, address, phone, email)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING *",
    )
    .bind(env_id)
    .bind(&req.property_code)
    .bind(&req.property_name)
    .bind(req.timezone.as_deref().unwrap_or("UTC"))
    .bind(req.currency_code.as_deref().unwrap_or("USD"))
    .bind(serde_json::to_value(req.languages.clone().unwrap_or_default()).unwrap_or_default())
    .bind(serde_json::to_value(&req.address).unwrap_or(serde_json::Value::Null))
    .bind(&req.phone)
    .bind(&req.email)
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:property:created", serde_json::json!({ "property_id": row.id, "property_code": &req.property_code }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(row.to_contract()))
}

pub async fn list_properties(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<Property>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:admin")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let rows = sqlx::query_as::<_, PropertyRow>(
        "SELECT * FROM pms.properties ORDER BY property_code",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(rows.into_iter().map(|r| r.to_contract()).collect()))
}

pub async fn get_property(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<Property>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:admin")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let row = sqlx::query_as::<_, PropertyRow>(
        "SELECT * FROM pms.properties WHERE id = $1",
    )
    .bind(property_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => super::err_not_found("Property not found"),
        e => super::err_db(e),
    })?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(row.to_contract()))
}

pub async fn update_property(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<PropertyCreate>,
) -> Result<Json<Property>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:admin")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let row = sqlx::query_as::<_, PropertyRow>(
        "UPDATE pms.properties SET property_code = $2, property_name = $3, timezone = $4, currency_code = $5, languages = $6, address = $7, phone = $8, email = $9, updated_at = now()
         WHERE id = $1 RETURNING *",
    )
    .bind(property_id)
    .bind(&req.property_code)
    .bind(&req.property_name)
    .bind(req.timezone.as_deref().unwrap_or("UTC"))
    .bind(req.currency_code.as_deref().unwrap_or("USD"))
    .bind(serde_json::to_value(req.languages.clone().unwrap_or_default()).unwrap_or_default())
    .bind(serde_json::to_value(&req.address).unwrap_or(serde_json::Value::Null))
    .bind(&req.phone)
    .bind(&req.email)
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:property:updated", serde_json::json!({ "property_id": property_id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(row.to_contract()))
}

pub async fn delete_property(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:admin")).await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let _ = sqlx::query("DELETE FROM pms.properties WHERE id = $1")
        .bind(property_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:property:deleted", serde_json::json!({ "property_id": property_id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(sqlx::FromRow)]
struct PropertyRow {
    id: uuid::Uuid,
    env_id: uuid::Uuid,
    property_code: String,
    property_name: String,
    timezone: String,
    currency_code: String,
    languages: serde_json::Value,
    address: Option<serde_json::Value>,
    phone: Option<String>,
    email: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl PropertyRow {
    fn to_contract(self) -> Property {
        Property {
            id: self.id,
            env_id: self.env_id,
            property_code: self.property_code,
            property_name: self.property_name,
            timezone: self.timezone,
            currency_code: self.currency_code,
            languages: serde_json::from_value(self.languages).unwrap_or_default(),
            address: self.address.and_then(|v| serde_json::from_value(v).ok()),
            phone: self.phone,
            email: self.email,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}