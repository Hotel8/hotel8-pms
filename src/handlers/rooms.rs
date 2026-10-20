// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Room and room type management handlers.
use crate::auth;
use crate::handlers::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use hotel8::pms::contracts::{
    InventoryList, InventoryRow, ItemCreateRequest, ItemList, ItemUpdateRequest, ItemView, Room,
    RoomCreate, RoomStatusUpdate, RoomType, RoomTypeCreate, SellLimitResult,
    SellLimitUpdateRequest,
};
use sqlx::Row;

// ── Room Types ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/room-types",
    request_body = RoomTypeCreate,
    responses(
        (status = 200, description = "Room type created", body = RoomType),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn create_room_type(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<RoomTypeCreate>,
) -> Result<Json<RoomType>, (StatusCode, String)> {
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
    let row = sqlx::query(
        "INSERT INTO pms.room_types (property_id, room_type_code, room_type_name, description, max_occupancy, bed_type, is_smoking, features)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, property_id, room_type_code, room_type_name, description, max_occupancy, bed_type, is_smoking, features, created_at, updated_at",
    )
    .bind(property_id)
    .bind(&req.room_type_code)
    .bind(&req.room_type_name)
    .bind(&req.description)
    .bind(req.max_occupancy)
    .bind(&req.bed_type)
    .bind(req.is_smoking)
    .bind(serde_json::to_value(req.features.clone().unwrap_or_default()).unwrap_or_default())
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:room_type:created",
        serde_json::json!({ "property_id": property_id, "room_type_code": &req.room_type_code }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(row_to_room_type(&row)))
}
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/room-types",
    responses(
        (status = 200, description = "Room types of the property", body = [RoomType]),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn list_room_types(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<Vec<RoomType>>, (StatusCode, String)> {
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
    let rows = sqlx::query(
        "SELECT id, property_id, room_type_code, room_type_name, description, max_occupancy, bed_type, is_smoking, features, created_at, updated_at FROM pms.room_types WHERE property_id = $1 ORDER BY room_type_code",
    )
    .bind(property_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(super::err_db)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(rows.iter().map(row_to_room_type).collect()))
}
#[utoipa::path(
    delete,
    path = "/v1/properties/{property_id}/room-types/{type_id}",
    responses(
        (status = 204, description = "Room type deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn delete_room_type(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, type_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
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
    sqlx::query("DELETE FROM pms.room_types WHERE id = $1 AND property_id = $2")
        .bind(type_id)
        .bind(property_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Rooms ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/rooms",
    request_body = RoomCreate,
    responses(
        (status = 200, description = "Room created (VACANT / DIRTY by default)", body = Room),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn create_room(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<RoomCreate>,
) -> Result<Json<Room>, (StatusCode, String)> {
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
    let row = sqlx::query(
        "INSERT INTO pms.rooms (property_id, room_type_id, room_number, floor, building, front_office_status, housekeeping_status, is_smoking, max_occupancy, bed_type, features)
         VALUES ($1, $2, $3, $4, $5, 'VACANT', 'DIRTY', $6, $7, $8, $9) RETURNING *",
    )
    .bind(property_id)
    .bind(req.room_type_id)
    .bind(&req.room_number)
    .bind(&req.floor)
    .bind(&req.building)
    .bind(req.is_smoking.unwrap_or(false))
    .bind(req.max_occupancy.unwrap_or(2))
    .bind(&req.bed_type)
    .bind(serde_json::to_value(req.features.clone().unwrap_or_default()).unwrap_or_default())
    .fetch_one(&mut *conn)
    .await
    .map_err(super::err_db)?;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:room:created",
        serde_json::json!({ "property_id": property_id, "room_number": &req.room_number }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(row_to_room(&row)))
}
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/rooms",
    responses(
        (status = 200, description = "Rooms of the property", body = [Room]),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn list_rooms(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<Vec<Room>>, (StatusCode, String)> {
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
    let rows = sqlx::query("SELECT * FROM pms.rooms WHERE property_id = $1 ORDER BY room_number")
        .bind(property_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(super::err_db)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(rows.iter().map(row_to_room).collect()))
}
#[utoipa::path(
    put,
    path = "/v1/properties/{property_id}/rooms/{room_number}",
    request_body = RoomStatusUpdate,
    responses(
        (status = 200, description = "Room with the updated statuses", body = Room),
        (status = 404, description = "Room not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn update_room_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, room_number)): Path<(uuid::Uuid, String)>,
    Json(req): Json<RoomStatusUpdate>,
) -> Result<Json<Room>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:frontdesk:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let fo = req
        .front_office_status
        .map(|s| s.to_string())
        .unwrap_or_default();
    let hk = req
        .housekeeping_status
        .map(|s| s.to_string())
        .unwrap_or_default();
    let row = sqlx::query(
        "UPDATE pms.rooms SET
            front_office_status = COALESCE(NULLIF($3, '')::pms.fo_status, front_office_status),
            housekeeping_status = COALESCE(NULLIF($4, '')::pms.hk_status, housekeeping_status),
            last_cleaned_at = CASE WHEN $4 = 'CLEAN' THEN now() ELSE last_cleaned_at END,
            last_inspected_at = CASE WHEN $4 = 'INSPECTED' THEN now() ELSE last_inspected_at END,
            updated_at = now()
         WHERE property_id = $1 AND room_number = $2 RETURNING *",
    )
    .bind(property_id)
    .bind(&room_number)
    .bind(&fo)
    .bind(&hk)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => super::err_not_found("Room not found"),
        e => super::err_db(e),
    })?;
    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:room:status_changed", serde_json::json!({ "property_id": property_id, "room_number": &room_number, "fo_status": &fo, "hk_status": &hk }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(row_to_room(&row)))
}

fn row_to_room_type(row: &sqlx::postgres::PgRow) -> RoomType {
    RoomType {
        id: row.get("id"),
        property_id: row.get("property_id"),
        room_type_code: row.get("room_type_code"),
        room_type_name: row.get("room_type_name"),
        description: row.get("description"),
        max_occupancy: row.get("max_occupancy"),
        bed_type: row.get("bed_type"),
        is_smoking: row.get("is_smoking"),
        features: serde_json::from_value(row.get("features")).unwrap_or_default(),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn row_to_room(row: &sqlx::postgres::PgRow) -> Room {
    let fo_status: String = row.get("front_office_status");
    let hk_status: String = row.get("housekeeping_status");
    Room {
        id: row.get("id"),
        property_id: row.get("property_id"),
        room_type_id: row.get("room_type_id"),
        room_number: row.get("room_number"),
        floor: row.get("floor"),
        building: row.get("building"),
        front_office_status: serde_json::from_str(&fo_status)
            .unwrap_or(hotel8::pms::contracts::FrontOfficeStatus::Vacant),
        housekeeping_status: serde_json::from_str(&hk_status)
            .unwrap_or(hotel8::pms::contracts::HousekeepingStatus::Dirty),
        is_smoking: row.get("is_smoking"),
        max_occupancy: row.get("max_occupancy"),
        bed_type: row.get("bed_type"),
        features: serde_json::from_value(row.get("features")).unwrap_or_default(),
        current_reservation_id: row.get("current_reservation_id"),
        next_reservation_id: row.get("next_reservation_id"),
        last_cleaned_at: row.get("last_cleaned_at"),
        last_inspected_at: row.get("last_inspected_at"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

// ── Room status matrix validation ──

pub fn validate_room_status_matrix(fo: &str, hk: &str) -> Result<(), String> {
    let valid = match (fo, hk) {
        ("VACANT", "CLEAN")
        | ("VACANT", "DIRTY")
        | ("VACANT", "INSPECTED")
        | ("VACANT", "PICKUP")
        | ("VACANT", "OUT_OF_ORDER")
        | ("VACANT", "OUT_OF_SERVICE") => true,
        ("OCCUPIED", "DIRTY")
        | ("OCCUPIED", "PICKUP")
        | ("OCCUPIED", "OUT_OF_ORDER")
        | ("OCCUPIED", "OUT_OF_SERVICE") => true,
        ("DUE_OUT", "DIRTY")
        | ("DUE_OUT", "PICKUP")
        | ("DUE_OUT", "OUT_OF_ORDER")
        | ("DUE_OUT", "OUT_OF_SERVICE") => true,
        ("DEPARTED", "DIRTY") | ("DEPARTED", "OUT_OF_ORDER") => true,
        ("STAYOVER", "DIRTY")
        | ("STAYOVER", "CLEAN")
        | ("STAYOVER", "INSPECTED")
        | ("STAYOVER", "PICKUP") => true,
        (_, "OUT_OF_ORDER") | (_, "OUT_OF_SERVICE") => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(format!(
            "Invalid room status combination: FO={} HSK={}",
            fo, hk
        ))
    }
}

// ── -Room Inventory ──
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/inventory",
    responses(
        (status = 200, description = "Inventory rows for the date window", body = InventoryList),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn get_inventory(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    axum::extract::Query(params): axum::extract::Query<serde_json::Value>,
) -> Result<Json<InventoryList>, (StatusCode, String)> {
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
    let start_date = params
        .get("start_date")
        .and_then(|v| v.as_str())
        .unwrap_or("2020-01-01");
    let end_date = params
        .get("end_date")
        .and_then(|v| v.as_str())
        .unwrap_or("2030-12-31");
    let rows = sqlx::query("SELECT * FROM pms.inventory WHERE property_id = $1 AND date >= $2 AND date <= $3 ORDER BY date, room_type_id")
        .bind(property_id).bind(start_date).bind(end_date)
        .fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let items: Vec<InventoryRow> = rows
        .iter()
        .map(|r| InventoryRow {
            property_id: r.get::<uuid::Uuid, _>("property_id"),
            room_type_id: r.get::<uuid::Uuid, _>("room_type_id"),
            date: r.get::<chrono::NaiveDate, _>("date"),
            physical_rooms: r.get::<i32, _>("physical_rooms"),
            sell_limit: r.get::<i32, _>("sell_limit"),
            sold_rooms: r.get::<i32, _>("sold_rooms"),
            available_rooms: r.get::<i32, _>("available_rooms"),
            out_of_order: r.get::<i32, _>("out_of_order"),
            out_of_service: r.get::<i32, _>("out_of_service"),
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(InventoryList { items }))
}
#[utoipa::path(
    put,
    path = "/v1/properties/{property_id}/inventory/sell-limits",
    request_body = SellLimitUpdateRequest,
    responses(
        (status = 200, description = "Sell limit applied over the date window", body = SellLimitResult),
        (status = 400, description = "room_type_id required"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn update_sell_limit(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<SellLimitUpdateRequest>,
) -> Result<Json<SellLimitResult>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:inventory:write"),
    )
    .await?;
    let env_id = super::resolve_org_env(&a);
    let mut conn = state.pool.begin().await.map_err(super::err_db)?;
    super::set_tenant_context(&mut conn, env_id).await;
    let room_type_id: uuid::Uuid = req.room_type_id;
    let start_date = req.start_date;
    let end_date = req.end_date;
    let sell_limit: i32 = req.sell_limit;
    let reason = req.reason.unwrap_or_default();

    let _ = sqlx::query(
        "INSERT INTO pms.inventory (property_id, room_type_id, date, physical_rooms, sell_limit, sold_rooms, available_rooms, out_of_order, out_of_service)
         SELECT $1, $2, d::date,
            COALESCE((SELECT physical_rooms FROM pms.inventory WHERE property_id = $1 AND room_type_id = $2 AND date = d::date), (SELECT COUNT(*)::int FROM pms.rooms WHERE room_type_id = $2)),
            $4,
            COALESCE((SELECT sold_rooms FROM pms.inventory WHERE property_id = $1 AND room_type_id = $2 AND date = d::date), 0),
            $4 - COALESCE((SELECT sold_rooms FROM pms.inventory WHERE property_id = $1 AND room_type_id = $2 AND date = d::date), 0),
            COALESCE((SELECT out_of_order FROM pms.inventory WHERE property_id = $1 AND room_type_id = $2 AND date = d::date), 0),
            COALESCE((SELECT out_of_service FROM pms.inventory WHERE property_id = $1 AND room_type_id = $2 AND date = d::date), 0)
         FROM generate_series($3::date, $5::date, '1 day'::interval) AS d
         ON CONFLICT (property_id, room_type_id, date) DO UPDATE SET sell_limit = EXCLUDED.sell_limit, available_rooms = EXCLUDED.available_rooms, updated_at = now()"
    )
    .bind(property_id).bind(room_type_id).bind(start_date).bind(sell_limit).bind(end_date)
    .execute(&mut *conn).await.map_err(super::err_db)?;

    crate::event_emit::emit_tx(&mut *conn, env_id, "hotel8:pms:inventory:sell_limit_changed", serde_json::json!({ "property_id": property_id, "room_type_id": room_type_id, "sell_limit": sell_limit, "reason": reason }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope)).await.map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(SellLimitResult {
        status: "updated".to_string(),
        room_type_id,
        sell_limit,
    }))
}

// ── Item Inventory (non-room sellable items: amenity kits, minibar, parking passes, etc.) ──
#[utoipa::path(
    post,
    path = "/v1/properties/{property_id}/items",
    request_body = ItemCreateRequest,
    responses(
        (status = 200, description = "Item created", body = ItemView),
        (status = 400, description = "item_code and item_name required"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn create_item(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
    Json(req): Json<ItemCreateRequest>,
) -> Result<Json<ItemView>, (StatusCode, String)> {
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
    let item_code = req.item_code;
    let item_name = req.item_name;
    let category = req.category;
    let unit_price = req.unit_price;
    let unit_cost = req.unit_cost;
    let stock_qty: i32 = req.stock_qty;
    let reorder_point: i32 = req.reorder_point;
    let is_sellable = req.is_sellable;
    let row = sqlx::query(
        "INSERT INTO pms.items (property_id, item_code, item_name, category, unit_price, unit_cost, stock_qty, reorder_point, is_sellable)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, item_code, item_name, category, unit_price::text as unit_price, unit_cost::text as unit_cost, stock_qty, reorder_point, is_sellable",
    )
    .bind(property_id).bind(&item_code).bind(&item_name).bind(&category).bind(&unit_price).bind(&unit_cost).bind(stock_qty).bind(reorder_point).bind(is_sellable)
    .fetch_one(&mut *conn).await.map_err(super::err_db)?;
    let id: uuid::Uuid = row.get("id");
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:item:created",
        serde_json::json!({ "property_id": property_id, "item_id": id, "item_code": item_code }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(ItemView {
        id,
        item_code: row.get::<String, _>("item_code"),
        item_name: row.get::<String, _>("item_name"),
        category: row.get::<String, _>("category"),
        unit_price: row.get::<String, _>("unit_price"),
        unit_cost: row.get::<String, _>("unit_cost"),
        stock_qty: row.get::<i32, _>("stock_qty"),
        reorder_point: row.get::<i32, _>("reorder_point"),
        is_sellable: row.get::<bool, _>("is_sellable"),
    }))
}
#[utoipa::path(
    get,
    path = "/v1/properties/{property_id}/items",
    responses(
        (status = 200, description = "Sellable/stock items of the property", body = ItemList),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn list_items(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(property_id): Path<uuid::Uuid>,
) -> Result<Json<ItemList>, (StatusCode, String)> {
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
    let rows = sqlx::query(
        "SELECT id, item_code, item_name, category, unit_price::text as unit_price, unit_cost::text as unit_cost, stock_qty, reorder_point, is_sellable
         FROM pms.items WHERE property_id = $1 ORDER BY item_code",
    )
    .bind(property_id).fetch_all(&mut *conn).await.map_err(super::err_db)?;
    let items: Vec<ItemView> = rows
        .iter()
        .map(|r| ItemView {
            id: r.get::<uuid::Uuid, _>("id"),
            item_code: r.get::<String, _>("item_code"),
            item_name: r.get::<String, _>("item_name"),
            category: r.get::<String, _>("category"),
            unit_price: r.get::<String, _>("unit_price"),
            unit_cost: r.get::<String, _>("unit_cost"),
            stock_qty: r.get::<i32, _>("stock_qty"),
            reorder_point: r.get::<i32, _>("reorder_point"),
            is_sellable: r.get::<bool, _>("is_sellable"),
        })
        .collect();
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(ItemList { items }))
}
#[utoipa::path(
    put,
    path = "/v1/properties/{property_id}/items/{item_id}",
    request_body = ItemUpdateRequest,
    responses(
        (status = 200, description = "Item with the updated fields", body = ItemView),
        (status = 404, description = "Item not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn update_item(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, item_id)): Path<(uuid::Uuid, uuid::Uuid)>,
    Json(req): Json<ItemUpdateRequest>,
) -> Result<Json<ItemView>, (StatusCode, String)> {
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
    let item_name = req.item_name;
    let unit_price = req.unit_price;
    let unit_cost = req.unit_cost;
    let stock_qty: Option<i32> = req.stock_qty;
    let reorder_point: Option<i32> = req.reorder_point;
    let is_sellable = req.is_sellable;
    let row = sqlx::query(
        "UPDATE pms.items SET
            item_name = COALESCE($3, item_name),
            unit_price = COALESCE($4::numeric, unit_price),
            unit_cost = COALESCE($5::numeric, unit_cost),
            stock_qty = COALESCE($6, stock_qty),
            reorder_point = COALESCE($7, reorder_point),
            is_sellable = COALESCE($8, is_sellable),
            updated_at = now()
         WHERE id = $1 AND property_id = $2
         RETURNING id, item_code, item_name, category, unit_price::text as unit_price, unit_cost::text as unit_cost, stock_qty, reorder_point, is_sellable",
    )
    .bind(item_id).bind(property_id).bind(item_name).bind(unit_price).bind(unit_cost).bind(stock_qty).bind(reorder_point).bind(is_sellable)
    .fetch_optional(&mut *conn).await.map_err(super::err_db)?
        .ok_or_else(|| super::err_not_found("item not found"))?;
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:item:updated",
        serde_json::json!({ "property_id": property_id, "item_id": item_id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(Json(ItemView {
        id: row.get::<uuid::Uuid, _>("id"),
        item_code: row.get::<String, _>("item_code"),
        item_name: row.get::<String, _>("item_name"),
        category: row.get::<String, _>("category"),
        unit_price: row.get::<String, _>("unit_price"),
        unit_cost: row.get::<String, _>("unit_cost"),
        stock_qty: row.get::<i32, _>("stock_qty"),
        reorder_point: row.get::<i32, _>("reorder_point"),
        is_sellable: row.get::<bool, _>("is_sellable"),
    }))
}
#[utoipa::path(
    delete,
    path = "/v1/properties/{property_id}/items/{item_id}",
    responses(
        (status = 204, description = "Item deleted"),
        (status = 404, description = "Item not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms",
)]

pub async fn delete_item(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path((property_id, item_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
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
    let res = sqlx::query("DELETE FROM pms.items WHERE id = $1 AND property_id = $2")
        .bind(item_id)
        .bind(property_id)
        .execute(&mut *conn)
        .await
        .map_err(super::err_db)?;
    if res.rows_affected() == 0 {
        return Err(super::err_not_found("item not found"));
    }
    crate::event_emit::emit_tx(
        &mut *conn,
        env_id,
        "hotel8:pms:item:deleted",
        serde_json::json!({ "property_id": property_id, "item_id": item_id }),
        &crate::event_emit::Publisher::from_parts(&a.claims.sub, &a.claims.scope),
    )
    .await
    .map_err(super::err_emit)?;
    conn.commit().await.map_err(super::err_db)?;
    Ok(StatusCode::NO_CONTENT)
}
