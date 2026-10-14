// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! PMS configuration loaded from environment variables.
use std::env;
use sentin8::auth::client::{Client as AuthClient, ClientOptions};

#[derive(Clone)]
pub struct H8pmsConfig {
    pub port: u16,
    pub database_url: String,
    pub sentin8_auth_issuer: String,
    pub sentin8_auth_jwks_url: String,
    pub sentin8_bus_url: String,
    pub stream_family: String,
    pub bill8_payments_url: String,
    pub bill8_ledger_url: String,
    pub sentin8_post_url: String,
    pub sentin8_cron_url: String,
    pub sentin8_func_url: String,
    /// Shared Auth client — constructed once so discovery + JWKS caches
    /// are reused across every request (5-min TTL each). Cloning is cheap (Arc).
    pub sentin8_auth_client: AuthClient,
    /// Certificate-presenting transport for the `pms-payments` workload
    /// (Bill8:Payments charges + token consume — CERTFREE-4V, no M2M
    /// token exists).
    pub payments_http: Option<reqwest::Client>,
    /// Certificate-presenting transport for the `pms-ledger` workload
    /// (Bill8:Ledger postings + folio-settlement provisioning).
    pub ledger_http: Option<reqwest::Client>,
    /// Certificate-presenting transport for the `pms-post` workload
    /// (Sentin8:Post send API).
    pub post_http: Option<reqwest::Client>,
    /// Certificate-presenting Storage client for the service's own `pms`
    /// workload certificate (property-image uploads).
    pub storage_client: Option<sentin8_storage_sdk::client::StorageClient>,
}

/// Manual `Debug`: `StorageClient` is not `Debug`, and the DSN is redacted.
impl std::fmt::Debug for H8pmsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H8pmsConfig")
            .field("port", &self.port)
            .field("database_url", &"<redacted>")
            .field("bill8_payments_url", &self.bill8_payments_url)
            .field("bill8_ledger_url", &self.bill8_ledger_url)
            .field("payments_http", &self.payments_http.is_some())
            .field("ledger_http", &self.ledger_http.is_some())
            .field("post_http", &self.post_http.is_some())
            .field("storage_client", &self.storage_client.is_some())
            .finish_non_exhaustive()
    }
}

impl H8pmsConfig {
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env::var("HOTEL8_PMS_PORT")
                .expect("HOTEL8_PMS_PORT must be set by captain")
                .parse()
                .expect("HOTEL8_PMS_PORT must be a number"),
            // DBX (§VDC.3) — the DSN is REQUIRED and must name the vertical
            // database (hotel8): the shell verifies the service identity's
            // expected database and refuses to boot otherwise. There is no
            // platform-database fallback.
            database_url: env::var("HOTEL8_PMS_DATABASE_URL")
                .unwrap_or_else(|_| "postgres://hotel8_pms_service@localhost:5432/hotel8".into()),
            sentin8_auth_issuer: env::var("SENTIN8_AUTH_ISSUER")
                .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL")
                .unwrap_or_else(|_| cfg.sentin8_bus_url()),
            stream_family: env::var("HOTEL8_PMS_STREAM_FAMILY")
                .unwrap_or_else(|_| "pms-events".into()),
            bill8_payments_url: env::var("BILL8_PAYMENTS_URL")
                .unwrap_or_else(|_| format!("https://{}", cfg.platform_domain("bill8:payments"))),
            bill8_ledger_url: env::var("BILL8_LEDGER_URL")
                .unwrap_or_else(|_| format!("https://{}", cfg.platform_domain("bill8:ledger"))),
            sentin8_post_url: env::var("SENTIN8_POST_URL")
                .unwrap_or_else(|_| cfg.sentin8_post_url()),
            sentin8_cron_url: env::var("SENTIN8_CRON_URL")
                .unwrap_or_else(|_| cfg.sentin8_cron_url()),
            sentin8_func_url: env::var("SENTIN8_FUNC_URL")
                .unwrap_or_else(|_| cfg.sentin8_func_url()),
            sentin8_auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
            payments_http: None,
            ledger_http: None,
            post_http: None,
            storage_client: None,
        }
    }
}