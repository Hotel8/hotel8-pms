// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for PMS.

use std::sync::Arc;

use axum::routing::{get, post, put, delete};

use crate::handlers::{self, AppState};

/// Build a cert-presenting HTTP transport for `workload` (CERTFREE-4V,
/// auth DESIGN §4.3f): mint-or-load the Acme-issued pair and wrap it in
/// a reqwest client. The receiving service's TLS layer authenticates the
/// handshake and the enroll-published registry map authorizes the
/// scopes — no bearer token exists on this path.
///
/// # Errors
/// Returns the certificate-ensure or transport-build failure (the
/// caller logs and degrades).
async fn build_workload_http(
    auth_issuer: &str,
    workload: &str,
) -> anyhow::Result<reqwest::Client> {
    let cert = sentin8::auth::m2m::ensure_workload_certificate(
        auth_issuer,
        workload,
        &sentin8::auth::m2m::platform_ca_path(),
    )
    .await?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| anyhow::anyhow!("workload '{workload}' transport: {e}"))
}

/// Build a cert-presenting Storage client for the service's own `pms`
/// workload certificate (CERTFREE-4V — same identity, Storage-specific
/// transport).
///
/// # Errors
/// Returns the certificate-ensure or transport-build failure.
async fn build_storage_client(
    auth_issuer: &str,
) -> anyhow::Result<sentin8_storage_sdk::client::StorageClient> {
    let cert = sentin8::auth::m2m::ensure_workload_certificate(
        auth_issuer,
        "pms",
        &sentin8::auth::m2m::platform_ca_path(),
    )
    .await?;
    sentin8_storage_sdk::client::StorageClient::with_workload_identity(
        &sentin8::config::Sentin8Config::from_env().sentin8_storage_url(),
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    )
    .map_err(|e| anyhow::anyhow!("pms storage transport: {e}"))
}

pub async fn build_state(core: sentin8::shell::ServiceCore)
    -> anyhow::Result<crate::handlers::AppState> {
    let mut config = crate::config::H8pmsConfig::from_env();

    // Cert-presenting Bus client (CERTFREE-4V): the `pms` workload
    // CERTIFICATE is the identity — no DCR, no token (auth DESIGN
    // §4.3f); the mint retries while the fleet boots.
    let bus_client = loop {
        match sentin8::bus::client::BusClient::for_workload(
            &config.sentin8_bus_url,
            &config.sentin8_auth_issuer,
            "pms",
        )
        .await
        {
            Ok(c) => break c,
            Err(e) => {
                tracing::debug!(error = %e, "pms bus client: certificate not ready yet");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };

    // Cross-service workload transports (CERTFREE-4V): one certificate
    // per declared workload (registration.rs M2M_GRANTS) — the receiving
    // service's TLS layer authenticates the handshake and the registry
    // map authorizes the scopes.
    match build_workload_http(&config.sentin8_auth_issuer, "pms-payments").await {
        Ok(http) => config.payments_http = Some(http),
        Err(e) => tracing::warn!(error = %e, "pms-payments transport unavailable — payment processing degraded"),
    }
    match build_workload_http(&config.sentin8_auth_issuer, "pms-ledger").await {
        Ok(http) => config.ledger_http = Some(http),
        Err(e) => tracing::warn!(error = %e, "pms-ledger transport unavailable — ledger postings degraded"),
    }
    match build_workload_http(&config.sentin8_auth_issuer, "pms-post").await {
        Ok(http) => config.post_http = Some(http),
        Err(e) => tracing::warn!(error = %e, "pms-post transport unavailable — notification emails degraded"),
    }
    match build_storage_client(&config.sentin8_auth_issuer).await {
        Ok(storage) => config.storage_client = Some(storage),
        Err(e) => tracing::warn!(error = %e, "pms storage transport unavailable — image uploads degraded"),
    }

    // ── Sentin8:Policy (Shield) ──
    // Load the service's policy sets; an unparsable policy text REFUSES TO
    // START (fail-closed at boot, design §3.3). Hot-reload consumes the
    // `policy` stream as a direct consumer (design §3.2); deny/would-deny
    // decisions emit to Stat (§4.2f). The engine is stored in AppState so
    // handlers gate via `policy::require` (step 5 is the ONLY gate).
    // ── Sentin8:Policy (Shield, shell-owned boot): consume the
    // engine the shell booted in step 8 — no second engine, consumer, or
    // DCR registration here.
    let policy_engine = core.admin.policy.clone();

    let state = AppState {
        config: Arc::new(config),
        pool: core.pool.clone(),
        bus_client,
        policy: policy_engine.clone(),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "hotel8:pms".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine,
            auth_client: Arc::new(core.config.sentin8_auth_client.clone()),
        },
    };

    Ok(state)
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding, OpenAPI merge and the standard
/// middleware stack; this adds ONLY routes (including the service's own
/// `/v1/health` — custom payload).
pub fn routes(router: axum::Router<crate::handlers::AppState>)
    -> axum::Router<crate::handlers::AppState> {
   router
        .route("/v1/health", get(handlers::health))
        // ── Admin UI (RFW) ─────────────────────────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        // Admin data + form-submit endpoints (pms/DESIGN.md §4 Admin/RFU):
        // live JSON for the RFW tables; POST aliases reuse the public
        // domain handlers. NOTE: registered under the property scope — Dash
        // proxies with {property_id} in the path (registration data_endpoint
        // is /v1/admin/{resource} relative to the property root).
        .route("/v1/admin/{property_id}/{resource}", get(crate::handlers::admin_data::get_admin_data))
        .route("/v1/admin/{property_id}/{resource}", post(crate::handlers::admin_data::submit_admin_data))
        // ── Sentin8:Policy admin API (shared implementation,
        // handlers generic over this AppState).
        .route("/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<crate::handlers::AppState>))
        .route("/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<crate::handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<crate::handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<crate::handlers::AppState>))
        .route("/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<crate::handlers::AppState>))
        .route("/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<crate::handlers::AppState>))
        .route("/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<crate::handlers::AppState>))
        .route("/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<crate::handlers::AppState>))
        .route("/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<crate::handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<crate::handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<crate::handlers::AppState>))
        .route("/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<crate::handlers::AppState>))
        .route("/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<crate::handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<crate::handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<crate::handlers::AppState>))
        // ── Properties ─────────────────────────────────────────────────────
        .route("/v1/properties", post(handlers::properties::create_property).get(handlers::properties::list_properties))
        .route("/v1/properties/{property_id}", get(handlers::properties::get_property).put(handlers::properties::update_property).delete(handlers::properties::delete_property))
        // ── Room Types ──────────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/room-types", post(handlers::rooms::create_room_type).get(handlers::rooms::list_room_types))
        .route("/v1/properties/{property_id}/room-types/{type_id}", delete(handlers::rooms::delete_room_type))
        // ── Rooms ───────────────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/rooms", post(handlers::rooms::create_room).get(handlers::rooms::list_rooms))
        .route("/v1/properties/{property_id}/rooms/{room_number}", put(handlers::rooms::update_room_status))
        // ── Rate Plans ──────────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/rate-plans", post(handlers::rate_plans::create_rate_plan).get(handlers::rate_plans::list_rate_plans))
        .route("/v1/properties/{property_id}/rate-plans/{plan_id}", get(handlers::rate_plans::get_rate_plan))
        // ── Availability ────────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/availability", get(handlers::availability::search_availability))
        .route("/v1/properties/{property_id}/corporate-availability", post(handlers::availability::corporate_availability))
        .route("/v1/properties/{property_id}/guarantee-policies", get(handlers::availability::get_guarantee_policies))
        // ── Multi-property (org-wide) availability ──
        .route("/v1/availability", get(handlers::availability::search_availability_org))
        // ── Guest Profiles ──────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/profiles", post(handlers::profiles::create_profile).get(handlers::profiles::list_profiles))
        .route("/v1/properties/{property_id}/profiles/{profile_id}", get(handlers::profiles::get_profile))
        .route("/v1/properties/{property_id}/profiles/{profile_id}/loyalty-number", put(handlers::profiles::set_loyalty_number))
        // ── Reservations ────────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/reservations", post(handlers::reservations::create_reservation).get(handlers::reservations::search_reservations))
        .route("/v1/properties/{property_id}/reservations/{res_id}", get(handlers::reservations::get_reservation).put(handlers::staff_corporate::update_reservation))
        .route("/v1/properties/{property_id}/reservations/{res_id}/cancel", post(handlers::reservations::cancel_reservation))
        // ── Walk-in booking (kiosk express booking) ──
        .route("/v1/properties/{property_id}/walk-in", post(handlers::staff_corporate::create_walk_in))
        // ── Corporate: company payment methods (credit approval) + user bindings ──
        .route("/v1/properties/{property_id}/companies/{profile_id}/payment-methods", get(handlers::staff_corporate::list_company_payment_methods).post(handlers::staff_corporate::create_company_payment_method))
        .route("/v1/properties/{property_id}/companies/{profile_id}/users", get(handlers::staff_corporate::list_company_users).post(handlers::staff_corporate::create_company_user))
        .route("/v1/properties/{property_id}/companies/by-traveler/{profile_id}", get(handlers::staff_corporate::list_companies_for_traveler))
        .route("/v1/properties/{property_id}/companies/{profile_id}/admin-provisioning", get(handlers::staff_corporate::get_company_admin_provisioning).put(handlers::staff_corporate::provision_company_admin))
        // ── Kiosk terminal config ──
        .route("/v1/properties/{property_id}/kiosk-config", get(handlers::staff_corporate::get_kiosk_config).put(handlers::staff_corporate::update_kiosk_config))
        // ── Front Desk ──────────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/reservations/{res_id}/check-in", post(handlers::front_desk::check_in))
        .route("/v1/properties/{property_id}/reservations/{res_id}/check-out", post(handlers::front_desk::check_out))
        .route("/v1/properties/{property_id}/in-house", get(handlers::front_desk::list_in_house))
        // ── Housekeeping ────────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/housekeeping", get(handlers::housekeeping::list_housekeeping_tasks))
        .route("/v1/properties/{property_id}/housekeeping/{room_number}", put(handlers::housekeeping::update_housekeeping_status))
        // ── Cashiering / Folio ──────────────────────────────────────────────
        .route("/v1/properties/{property_id}/reservations/{res_id}/folio", get(handlers::cashiering::get_folio))
        .route("/v1/properties/{property_id}/reservations/{res_id}/charges", post(handlers::cashiering::post_charge))
        .route("/v1/properties/{property_id}/reservations/{res_id}/payments", post(handlers::cashiering::post_payment))
        // ── Blocks ──────────────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/blocks", post(handlers::blocks::create_block).get(handlers::blocks::list_blocks))
        .route("/v1/properties/{property_id}/blocks/{block_id}/status", put(handlers::blocks::update_block_status))
        // ── Events ──────────────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/events", post(handlers::events::create_event).get(handlers::events::list_events))
        // ── LOV ──────────────────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/lov", get(handlers::lov::list_lov).post(handlers::lov::create_lov))
        .route("/v1/properties/{property_id}/lov/{lov_type}", get(handlers::lov::list_lov_by_type))
        // ── Back Office / Reports ───────────────────────────────────────────
        .route("/v1/properties/{property_id}/reports/occupancy", get(handlers::back_office::get_occupancy_report))
        .route("/v1/properties/{property_id}/reports/revenue", get(handlers::back_office::get_revenue_report))
        .route("/v1/properties/{property_id}/config", get(handlers::back_office::get_property_config))
        // ── Inventory ───────────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/inventory", get(handlers::rooms::get_inventory))
        .route("/v1/properties/{property_id}/inventory/sell-limits", put(handlers::rooms::update_sell_limit))
        // ── Rate Schedules & Packages ───────────────────────────────────────
        .route("/v1/properties/{property_id}/rate-plans/{plan_id}/schedules", post(handlers::rate_plans::create_rate_schedule).get(handlers::rate_plans::list_rate_schedules))
        .route("/v1/properties/{property_id}/rate-plans/{plan_id}/schedules/{schedule_id}", delete(handlers::rate_plans::delete_rate_schedule))
        .route("/v1/properties/{property_id}/packages", post(handlers::rate_plans::create_package).get(handlers::rate_plans::list_packages))
        // NOTE: `GET packages` was previously also registered under Availability
        // (handlers::availability::get_packages).  The Rate Plans handler
        // (handlers::rate_plans::list_packages) is the canonical one — it
        // supports both GET (list) and POST (create).
        // ── Negotiated rate plans ──
        .route("/v1/properties/{property_id}/negotiated-rate-plans", get(handlers::rate_plans::list_negotiated_rate_plans))
        .route("/v1/properties/{property_id}/negotiated-rate-plans/{rate_plan_id}/link-company", post(handlers::rate_plans::link_negotiated_rate_to_company))
        // ── Promo code validation ──
        .route("/v1/properties/{property_id}/promo/validate", post(handlers::rate_plans::validate_promo_code))
        // ── Item inventory ──
        .route("/v1/properties/{property_id}/items", post(handlers::rooms::create_item).get(handlers::rooms::list_items))
        .route("/v1/properties/{property_id}/items/{item_id}", put(handlers::rooms::update_item).delete(handlers::rooms::delete_item))
        // ── Reservation extras ──────────────────────────────────────────────
        .route("/v1/properties/{property_id}/reservations/{res_id}/split", post(handlers::reservations::split_reservation))
        .route("/v1/properties/{property_id}/reservations/{res_id}/upsell", post(handlers::reservations::upsell_reservation))
        .route("/v1/properties/{property_id}/reservations/{res_id}/instructions", get(handlers::reservations::fetch_instructions))
        // ── Front Desk extras ───────────────────────────────────────────────
        .route("/v1/properties/{property_id}/reservations/{res_id}/pre-check-in", post(handlers::front_desk::pre_check_in))
        .route("/v1/properties/{property_id}/reservations/{res_id}/check-in", delete(handlers::front_desk::revert_check_in))
        .route("/v1/properties/{property_id}/reservations/{res_id}/messages", get(handlers::front_desk::get_messages).post(handlers::front_desk::send_message))
        .route("/v1/properties/{property_id}/reservations/{res_id}/service-requests", get(handlers::front_desk::get_service_requests).post(handlers::front_desk::create_service_request))
        // ── Guest-app surfaces (guest_surfaces.rs) ──────────────────
        .route("/v1/properties/{property_id}/digital-keys", post(handlers::guest_surfaces::issue_digital_key).get(handlers::guest_surfaces::list_digital_keys))
        .route("/v1/properties/{property_id}/digital-keys/{key_id}/activate", post(handlers::guest_surfaces::activate_digital_key))
        .route("/v1/properties/{property_id}/digital-keys/{key_id}/deactivate", post(handlers::guest_surfaces::deactivate_digital_key))
        .route("/v1/properties/{property_id}/reservations/{res_id}/boarding-pass", get(handlers::guest_surfaces::get_boarding_pass))
        .route("/v1/properties/{property_id}/folios", get(handlers::guest_surfaces::get_folio_by_room))
        .route("/v1/properties/{property_id}/feedback", post(handlers::guest_surfaces::submit_feedback).get(handlers::guest_surfaces::get_feedback))
        // ── Guest payment methods (eGuest profile tab) + anonymous-booking linking ──
        .route("/v1/properties/{property_id}/payment-methods", post(handlers::guest_surfaces::create_payment_method).get(handlers::guest_surfaces::list_payment_methods))
        .route("/v1/properties/{property_id}/payment-methods/{method_id}", delete(handlers::guest_surfaces::delete_payment_method))
        .route("/v1/properties/{property_id}/reservations/{res_id}/link-guest", post(handlers::guest_surfaces::link_reservation_guest))
        // ── Housekeeping tasks ──────────────────────────────────────────────
        .route("/v1/properties/{property_id}/housekeeping/tasks", post(handlers::housekeeping::create_task).get(handlers::housekeeping::list_tasks))
        .route("/v1/properties/{property_id}/housekeeping/tasks/{task_id}", put(handlers::housekeeping::update_task))
        .route("/v1/properties/{property_id}/housekeeping/forecast", get(handlers::housekeeping::get_forecast))
        // ── Cashiering extras ───────────────────────────────────────────────
        .route("/v1/properties/{property_id}/reservations/{res_id}/folio/generate", post(handlers::cashiering::generate_folio))
        .route("/v1/properties/{property_id}/reservations/{res_id}/charges/dispute", post(handlers::cashiering::dispute_charge))
        .route("/v1/properties/{property_id}/transaction-codes", get(handlers::cashiering::list_transaction_codes))
        .route("/v1/properties/{property_id}/vouchers/validate", post(handlers::cashiering::validate_voucher))
        .route("/v1/properties/{property_id}/vouchers/redeem", post(handlers::cashiering::redeem_voucher))
        // ── Block extras ────────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/blocks/{block_id}/next-statuses", get(handlers::blocks::get_next_statuses))
        .route("/v1/properties/{property_id}/blocks/{block_id}/posting-master", post(handlers::blocks::create_posting_master))
        // ── Function Spaces & Event Resources ───────────────────────────────
        .route("/v1/properties/{property_id}/function-spaces", get(handlers::blocks::get_available_spaces))
        .route("/v1/properties/{property_id}/events/{event_id}/resources", get(handlers::blocks::get_event_resources).put(handlers::blocks::update_event_resources))
        // ── Profile extras ──────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/profiles/{profile_id}/preferences", post(handlers::profiles::add_preference).get(handlers::profiles::list_preferences))
        .route("/v1/properties/{property_id}/profiles/{profile_id}/preferences/{pref_id}", delete(handlers::profiles::remove_preference))
        .route("/v1/properties/{property_id}/profiles/{profile_id}/loyalty", post(handlers::profiles::link_loyalty))
        .route("/v1/properties/{property_id}/profiles/{profile_id}/stay-history", get(handlers::profiles::get_stay_history))
        // ── Profile merge ──
        .route("/v1/properties/{property_id}/profiles/merge", post(handlers::profiles::merge_profiles))
        // ── EOD & Reports ───────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/end-of-day", post(handlers::back_office::end_of_day))
        .route("/v1/properties/{property_id}/reports/reservation-summary", get(handlers::back_office::get_reservation_summary))
        // ── EOD exception handling ──
        .route("/v1/properties/{property_id}/end-of-day/exceptions", get(handlers::back_office::get_eod_exceptions))
        .route("/v1/properties/{property_id}/end-of-day/{eod_id}/retry", post(handlers::back_office::retry_eod))
        // ── -Additional report subject areas ──
        .route("/v1/properties/{property_id}/reports/guest-history", get(handlers::back_office::get_guest_history_report))
        .route("/v1/properties/{property_id}/reports/housekeeping-analysis", get(handlers::back_office::get_housekeeping_analysis_report))
        .route("/v1/properties/{property_id}/reports/sales-catering", get(handlers::back_office::get_sales_catering_report))
        .route("/v1/properties/{property_id}/reports/channel-performance", get(handlers::back_office::get_channel_performance_report))
        .route("/v1/properties/{property_id}/reports/market-segment", get(handlers::back_office::get_market_segment_report))
        .route("/v1/properties/{property_id}/reports/rate-analysis", get(handlers::back_office::get_rate_analysis_report))
        // ── Property modules ────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/modules", get(handlers::back_office::get_property_modules).put(handlers::back_office::update_property_modules))
        // ── Async API ───────────────────────────────────────────────────────
        .route("/v1/properties/{property_id}/async", post(handlers::back_office::create_async_job))
        .route("/v1/async/status/{job_id}", get(handlers::back_office::get_async_status))
        .route("/v1/async/result/{job_id}", get(handlers::back_office::get_async_result))
        // ── Async module-specific operations ──
        .route("/v1/properties/{property_id}/async/inventory", post(handlers::back_office::create_inventory_async))
        .route("/v1/properties/{property_id}/async/cashiering", post(handlers::back_office::create_cashiering_async))
        .route("/v1/properties/{property_id}/async/crm", post(handlers::back_office::create_crm_async))
        .route("/v1/properties/{property_id}/async/par", post(handlers::back_office::create_par_async))
        // ── External system config ──
        .route("/v1/properties/{property_id}/external-systems", get(handlers::back_office::get_external_system_config).put(handlers::back_office::update_external_system_config))
        // ── GraphQL ─────────────────────────────────────────────────────────
        .route("/v1/graphql", post(handlers::graphql::graphql))
        // ── Integration ─────────────────────────────────────────────
        .route("/v1/properties/{property_id}/reservations/{res_id}/payments-process", post(handlers::integration::process_payment_via_payments))
        .route("/v1/properties/{property_id}/reservations/{res_id}/ledger-post", post(handlers::integration::post_to_ledger))
        .route("/v1/properties/{property_id}/images", post(handlers::integration::upload_property_image))
        .route("/v1/properties/{property_id}/notifications", post(handlers::integration::send_notification))
        .route("/v1/properties/{property_id}/rate-limits", get(handlers::integration::get_rate_limit_config))
        .route("/v1/properties/{property_id}/audit-log", get(handlers::integration::get_audit_log))
        .route("/v1/properties/{property_id}/pci-compliance", get(handlers::integration::verify_pci_compliance))
        // ── -, Flow, Func, Post integration ──
        .route("/v1/properties/{property_id}/flow/workflows", post(handlers::integration::start_sentin8_flow_workflow))
        .route("/v1/properties/{property_id}/func/invoke", post(handlers::integration::invoke_sentin8_func_module))
        .route("/v1/properties/{property_id}/post/emails", post(handlers::integration::send_sentin8_post_email))
        // Traffic counter — counts every inbound request (excludes health checks).
}

/// Shared policy-admin surface accessor — the shared
/// handlers extract this service's admin state via `HasPolicyAdmin`.
impl sentin8::shield::admin::HasPolicyAdmin for crate::handlers::AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
