// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Guest profile management handlers.
use crate::auth;
use crate::handlers::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use sqlx::Row;

pub async fn create_profile(
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
        sentin8::shield::EvalTarget::new("hotel8:pms:profile:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let profile_type = req
        .get("profile_type")
        .and_then(|v| v.as_str())
        .unwrap_or("GUEST");
    let vip_status = req
        .get("vip_status")
        .and_then(|v| v.as_str())
        .unwrap_or("NONE");
    let row = sqlx::query("INSERT INTO pms.guest_profiles (property_id, profile_type, vip_status, first_name, last_name, email, phone, address, company_name, loyalty_number, preferred_language, preferences)
         VALUES ($1, $2::pms.profile_type, $3::pms.vip_status, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id, profile_type, first_name, last_name, email, created_at")
        .bind(property_id)
        .bind(profile_type)
        .bind(vip_status)
        .bind(req.get("first_name").and_then(|v| v.as_str()).unwrap_or(""))
        .bind(req.get("last_name").and_then(|v| v.as_str()).unwrap_or(""))
        .bind(req.get("email").and_then(|v| v.as_str()))
        .bind(req.get("phone").and_then(|v| v.as_str()))
        .bind(req.get("address").and_then(|v| v.as_str()))
        .bind(req.get("company_name").and_then(|v| v.as_str()))
        .bind(req.get("loyalty_number").and_then(|v| v.as_str()))
        .bind(req.get("preferred_language").and_then(|v| v.as_str()))
        .bind(serde_json::to_value(req.get("preferences").cloned().unwrap_or(serde_json::Value::Null)).unwrap_or(serde_json::Value::Null))
        .fetch_one(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let profile_id: uuid::Uuid = row.get("id");
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:profile:created",
        serde_json::json!({ "profile_id": profile_id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "id": profile_id,
        "profile_type": row.get::<String, _>("profile_type"),
        "first_name": row.get::<String, _>("first_name"),
        "last_name": row.get::<String, _>("last_name"),
        "email": row.get::<Option<String>, _>("email"),
        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    })))
}

pub async fn list_profiles(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
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
    let rows = sqlx::query("SELECT id, profile_type, vip_status, first_name, last_name, email, phone, company_name, loyalty_number FROM pms.guest_profiles WHERE property_id = $1 ORDER BY last_name, first_name LIMIT 200")
        .bind(property_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let pt: String = r.get("profile_type");
            let vip: String = r.get("vip_status");
            serde_json::json!({
                "id": r.get::<uuid::Uuid, _>("id"),
                "profile_type": pt,
                "vip_status": vip,
                "first_name": r.get::<String, _>("first_name"),
                "last_name": r.get::<String, _>("last_name"),
                "email": r.get::<Option<String>, _>("email"),
                "phone": r.get::<Option<String>, _>("phone"),
                "company_name": r.get::<Option<String>, _>("company_name"),
                "loyalty_number": r.get::<Option<String>, _>("loyalty_number"),
            })
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

pub async fn get_profile(
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
    let row = sqlx::query("SELECT * FROM pms.guest_profiles WHERE id = $1 AND property_id = $2")
        .bind(profile_id)
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => super::err_not_found("Profile not found"),
            e => super::err_db(e),
        })?;
    let pt: String = row.get("profile_type");
    let vip: String = row.get("vip_status");
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "id": row.get::<uuid::Uuid, _>("id"),
        "property_id": row.get::<uuid::Uuid, _>("property_id"),
        "profile_type": pt,
        "vip_status": vip,
        "first_name": row.get::<String, _>("first_name"),
        "last_name": row.get::<String, _>("last_name"),
        "email": row.get::<Option<String>, _>("email"),
        "phone": row.get::<Option<String>, _>("phone"),
        "company_name": row.get::<Option<String>, _>("company_name"),
        "loyalty_number": row.get::<Option<String>, _>("loyalty_number"),
        "preferred_language": row.get::<Option<String>, _>("preferred_language"),
        "preferences": row.get::<serde_json::Value, _>("preferences"),
        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        "updated_at": row.get::<chrono::DateTime<chrono::Utc>, _>("updated_at"),
    })))
}

// ── Preference management ──

pub async fn add_preference(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, profile_id)): Path<(uuid::Uuid, uuid::Uuid)>,
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
    let pref_type = req
        .get("preference_type")
        .and_then(|v| v.as_str())
        .unwrap_or("ROOM");
    let pref_code = req
        .get("preference_code")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let pref_value = req.get("preference_value").and_then(|v| v.as_str());
    let row = sqlx::query("INSERT INTO pms.guest_preferences (profile_id, preference_type, preference_code, preference_value) VALUES ($1, $2, $3, $4) RETURNING id, preference_type, preference_code, preference_value")
        .bind(profile_id).bind(pref_type).bind(pref_code).bind(pref_value)
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let id: uuid::Uuid = row.get("id");
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "id": id, "preference_type": row.get::<String, _>("preference_type"), "preference_code": row.get::<String, _>("preference_code"), "preference_value": row.get::<Option<String>, _>("preference_value") }),
    ))
}

pub async fn list_preferences(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, profile_id)): Path<(uuid::Uuid, uuid::Uuid)>,
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
    let rows = sqlx::query("SELECT id, preference_type, preference_code, preference_value FROM pms.guest_preferences WHERE profile_id = $1 ORDER BY preference_type, preference_code")
        .bind(profile_id).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
        "id": r.get::<uuid::Uuid, _>("id"), "preference_type": r.get::<String, _>("preference_type"),
        "preference_code": r.get::<String, _>("preference_code"), "preference_value": r.get::<Option<String>, _>("preference_value"),
    })).collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

pub async fn remove_preference(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, _profile_id, pref_id)): Path<(uuid::Uuid, uuid::Uuid, uuid::Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
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
    sqlx::query("DELETE FROM pms.guest_preferences WHERE id = $1")
        .bind(pref_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Loyalty Program linking ──

pub async fn link_loyalty(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((_property_id, profile_id)): Path<(uuid::Uuid, uuid::Uuid)>,
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
    let loyalty_number = req
        .get("loyalty_number")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let program_code = req.get("program_code").and_then(|v| v.as_str());
    let row = sqlx::query("UPDATE pms.guest_profiles SET loyalty_number = $2, updated_at = now() WHERE id = $1 RETURNING id, loyalty_number")
        .bind(profile_id).bind(loyalty_number)
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:profile:loyalty_linked", serde_json::json!({ "profile_id": profile_id, "loyalty_number": loyalty_number, "program_code": program_code }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(
        serde_json::json!({ "profile_id": row.get::<uuid::Uuid, _>("id"), "loyalty_number": row.get::<String, _>("loyalty_number") }),
    ))
}

// ── Stay History ──

pub async fn get_stay_history(
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
    let rows = sqlx::query("SELECT id, confirmation_number, arrival_date, departure_date, status, num_adults, num_children, assigned_room_number FROM pms.reservations WHERE guest_profile_id = $1 AND property_id = $2 ORDER BY arrival_date DESC LIMIT 100")
        .bind(profile_id).bind(property_id).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let items: Vec<serde_json::Value> = rows.iter().map(|r| { let s: String = r.get("status"); serde_json::json!({
        "id": r.get::<uuid::Uuid, _>("id"), "confirmation_number": r.get::<String, _>("confirmation_number"),
        "arrival_date": r.get::<chrono::NaiveDate, _>("arrival_date"), "departure_date": r.get::<chrono::NaiveDate, _>("departure_date"),
        "status": s, "num_adults": r.get::<i32, _>("num_adults"), "num_children": r.get::<i32, _>("num_children"),
        "room_number": r.get::<Option<String>, _>("assigned_room_number"),
    })}).collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({ "items": items })))
}

// ── Profile merge — deduplicate guest profiles, merge stay history ──

pub async fn merge_profiles(
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
        sentin8::shield::EvalTarget::new("hotel8:pms:profile:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let source_id_str = req
        .get("source_profile_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| super::err_bad_request("source_profile_id required"))?;
    let target_id_str = req
        .get("target_profile_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| super::err_bad_request("target_profile_id required"))?;
    let source_id = uuid::Uuid::parse_str(source_id_str)
        .map_err(|e| super::err_bad_request(&format!("invalid source_profile_id: {e}")))?;
    let target_id = uuid::Uuid::parse_str(target_id_str)
        .map_err(|e| super::err_bad_request(&format!("invalid target_profile_id: {e}")))?;
    if source_id == target_id {
        return Err(super::err_bad_request(
            "source and target must be different",
        ));
    }
    // Verify both profiles exist
    let src = sqlx::query("SELECT id, first_name, last_name, email, phone, company_name, loyalty_number, preferences FROM pms.guest_profiles WHERE id = $1 AND property_id = $2")
        .bind(source_id).bind(property_id)
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let tgt = sqlx::query("SELECT id, first_name, last_name, email, phone, company_name, loyalty_number, preferences FROM pms.guest_profiles WHERE id = $1 AND property_id = $2")
        .bind(target_id).bind(property_id)
        .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    // Merge: keep target, fill empty fields from source, merge preferences JSONB
    let src_prefs: serde_json::Value = src.get("preferences");
    let tgt_prefs: serde_json::Value = tgt.get("preferences");
    let merged_prefs = tgt_prefs
        .as_object()
        .map(|tgt_obj| {
            let mut merged = tgt_obj.clone();
            if let Some(src_obj) = src_prefs.as_object() {
                for (k, v) in src_obj {
                    if !merged.contains_key(k) {
                        merged.insert(k.clone(), v.clone());
                    }
                }
            }
            serde_json::Value::Object(merged)
        })
        .unwrap_or(tgt_prefs);
    // Update target with non-null source fields where target is empty
    sqlx::query(
        "UPDATE pms.guest_profiles SET
            email = COALESCE(NULLIF(email, ''), $3),
            phone = COALESCE(NULLIF(phone, ''), $4),
            company_name = COALESCE(NULLIF(company_name, ''), $5),
            loyalty_number = COALESCE(NULLIF(loyalty_number, ''), $6),
            preferences = $7,
            updated_at = now()
         WHERE id = $1 AND property_id = $2",
    )
    .bind(target_id)
    .bind(property_id)
    .bind(src.get::<Option<String>, _>("email"))
    .bind(src.get::<Option<String>, _>("phone"))
    .bind(src.get::<Option<String>, _>("company_name"))
    .bind(src.get::<Option<String>, _>("loyalty_number"))
    .bind(merged_prefs)
    .execute(&mut *conn)
    .await
    .map_err(super::err_db)?;
    // Re-point all reservations from source to target
    let moved = sqlx::query("UPDATE pms.reservations SET guest_profile_id = $1 WHERE guest_profile_id = $2 AND property_id = $3")
        .bind(target_id).bind(source_id).bind(property_id)
        .execute(&mut *conn).await.map_err(super::err_db)?;
    let moved_count = moved.rows_affected();
    // Re-point preferences from source to target
    let _ = sqlx::query("UPDATE pms.guest_preferences SET profile_id = $1 WHERE profile_id = $2 AND property_id = $3")
        .bind(target_id).bind(source_id).bind(property_id)
        .execute(&mut *conn).await;
    // Mark source as merged (soft delete by setting preferences to indicate merged)
    sqlx::query("UPDATE pms.guest_profiles SET preferences = preferences || jsonb_build_object('merged_into', $3::text, 'merged_at', now()::text) WHERE id = $1 AND property_id = $2")
        .bind(source_id).bind(property_id).bind(target_id.to_string())
        .execute(&mut *conn).await.map_err(super::err_db)?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:profile:merged", serde_json::json!({ "property_id": property_id, "source_profile_id": source_id, "target_profile_id": target_id, "reservations_moved": moved_count }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "merged": true,
        "source_profile_id": source_id,
        "target_profile_id": target_id,
        "reservations_moved": moved_count,
    })))
}
// ── Loyalty member link (service-to-service) ──

/// `PUT /v1/properties/{property_id}/profiles/{profile_id}/loyalty-number`
/// Sets the loyalty member number on a guest profile. Called by Hotel8:Loyalty
/// via `pms-client` over its HTTP API (DESIGN.md §1 — no cross-service SQL).
pub async fn set_loyalty_number(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, profile_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    // Step 5 — Shield decides. The profile-creation proxy-back also touches
    // the loyalty member; the mirror permit for this action is keyed on the
    // pms profile-write scope (the loyalty grant rides the caller's live
    // scope set when the tenant authors the cross-service rule).
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
    let loyalty_number = req
        .get("loyalty_number")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let row = sqlx::query(
        "UPDATE pms.guest_profiles SET loyalty_number = $3, updated_at = now() \
         WHERE id = $1 AND property_id = $2 \
         RETURNING id, loyalty_number",
    )
    .bind(profile_id)
    .bind(property_id)
    .bind(&loyalty_number)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => super::err_not_found("Profile not found"),
        e => super::err_db(e),
    })?;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:profile:loyalty_linked",
        serde_json::json!({
            "profile_id": profile_id,
            "property_id": property_id,
            "loyalty_number": loyalty_number,
        }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(serde_json::json!({
        "profile_id": row.get::<uuid::Uuid, _>("id"),
        "loyalty_number": row.get::<Option<String>, _>("loyalty_number"),
        "linked": true,
    })))
}
