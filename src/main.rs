// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 PMS - Property Management System for the hospitality industry.
//!
//! Boot runs on the platform `sentin8-shell` crate (design
//! `sentin8/design/sentin8-sentin8-shell-technical-design.md`): registration
//! flag, PQ provider, config, capped pool, PG18 check, state binding, OpenAPI
//! merge, middleware stack and PQ-TLS listener are owned by the shell. This
//! binary supplies only its registration data, state and routes.

#[allow(dead_code)]
mod admin_ui;
mod auth;
#[allow(dead_code)]
mod config;
mod event_consumer;
mod event_emit;
#[allow(dead_code)]
mod handlers;
mod openapi;

// The utoipa dump as a fn pointer for registration.rs (which cannot
// name crate::openapi - embedded test harnesses have no openapi module;
// see registration.rs and the mirrored static in lib.rs).
static OPENAPI_DUMP: fn() -> serde_json::Value = || {
    use utoipa::OpenApi as _;
    serde_json::to_value(openapi::PmsOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
};

mod platform_exec;
pub mod policy;
mod registration;
#[allow(dead_code)]
mod server;
mod state_machine;
#[allow(dead_code)]
mod types;

use utoipa::OpenApi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("hotel8:pms", "HOTEL8_PMS")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::PmsOpenApi::openapi()),
    )
    .await
}
