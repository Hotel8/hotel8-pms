// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! GraphQL endpoint handler.
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use crate::handlers::AppState;
use crate::auth;

pub async fn graphql(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
crate::policy::require(&state.policy, &_a, &headers, sentin8::shield::EvalTarget::new("hotel8:pms:read")).await?;
    let query = req.get("query").and_then(|v| v.as_str()).unwrap_or("");
    // Simple introspection: return schema info for now
    if query.contains("__schema") || query.contains("__type") {
        return Ok(Json(serde_json::json!({
            "data": {
                "__schema": {
                    "types": [
                        { "name": "Property", "kind": "OBJECT" },
                        { "name": "Property", "kind": "OBJECT" },
                        { "name": "Room", "kind": "OBJECT" },
                        { "name": "RoomType", "kind": "OBJECT" },
                        { "name": "RatePlan", "kind": "OBJECT" },
                        { "name": "Reservation", "kind": "OBJECT" },
                        { "name": "GuestProfile", "kind": "OBJECT" },
                        { "name": "Folio", "kind": "OBJECT" },
                        { "name": "Block", "kind": "OBJECT" },
                        { "name": "Event", "kind": "OBJECT" },
                    ]
                }
            }
        })));
    }
    // TODO: Implement full GraphQL resolver
    Ok(Json(serde_json::json!({
        "data": null,
        "errors": [{ "message": "GraphQL queries not yet implemented — use REST API" }]
    })))
}