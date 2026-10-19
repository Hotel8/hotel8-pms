// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! GraphQL endpoint handler.
use crate::auth;
use crate::handlers::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use hotel8::pms::contracts::{GraphQlError, GraphQlResponse};
#[utoipa::path(
    post,
    path = "/v1/graphql",
    responses(
        (status = 200, description = "OK - GraphQL envelope; `data` is query-shaped (free-form), `errors` carries message strings", body = GraphQlResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
    ),
    security(),
    tag = "pms-graphql",
)]

pub async fn graphql(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<GraphQlResponse>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:read"),
    )
    .await?;
    let query = req.get("query").and_then(|v| v.as_str()).unwrap_or("");
    // Simple introspection: return schema info for now
    if query.contains("__schema") || query.contains("__type") {
        return Ok(Json(GraphQlResponse {
            data: serde_json::json!({
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
            }),
            errors: None,
        }));
    }
    // TODO: Implement full GraphQL resolver
    Ok(Json(GraphQlResponse {
        data: serde_json::Value::Null,
        errors: Some(vec![GraphQlError {
            message: "GraphQL queries not yet implemented - use REST API".into(),
        }]),
    }))
}
