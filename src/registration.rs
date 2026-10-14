// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Hotel8:PMS.
//!
//! Output via `--print-registration` flag. See `sentin8/design/sentin8-service-self-registration-design.md`.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, EventTriggerDecl, M2mGrant, PgRole, PolicySetDecl,
    Registration, RelationDecl, SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "hotel8:pms:read,hotel8:pms:write",
    role: "hotel8_pms_service",
    bypass_rls: false,
    // DBX (§6.6): grants + scope-map rows live in the hotel8 vertical
    // database only (database-per-vertical, schema-per-service).
    database: "hotel8",
    // This service owns all its reads — no cross-schema grants.
    cross_schema_grants: &[],
}];

/// M2M DCR scope grants (self-registration design §3.11). One entry per
/// workload this service registers via DCR; `vertical enroll` upserts
/// `certless:<workload>` rows into `sentin8.auth_m2m_scope_grants` (alignment
/// doc §13). DBX (§6.7): `sentin8:bus:produce` rides the `pms` workload —
/// the shell's producer relay shares its DCR client; `pms-audit` ships the
/// local audit journal to Sys; `pms-policy`/`pms-tls` are the shell's
/// Shield hot-reload and DB-free TLS host-context workloads.
const M2M_GRANTS: &[M2mGrant] = &[
    M2mGrant {
        workload: "hotel8:pms",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
        ],
    },
    M2mGrant {
        workload: "pms",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
        ],
    },
    M2mGrant {
        workload: "pms-post",
        scopes: &["sentin8:post:send"],
    },
    M2mGrant {
        workload: "pms-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    M2mGrant {
        workload: "hotel8:pms-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    M2mGrant {
        workload: "pms-policy",
        scopes: &["sentin8:stat:measure"],
    },
    M2mGrant {
        workload: "hotel8-pms-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
    // Settlement lane (bill8): one DCR workload per scope-set.
    M2mGrant {
        workload: "pms-payments",
        scopes: &[
            "bill8:payments:charges:write",
            "bill8:payments:tokens:write",
        ],
    },
    M2mGrant {
        workload: "pms-ledger",
        scopes: &[
            "bill8:ledger:accounts:read",
            "bill8:ledger:accounts:write",
            "bill8:ledger:balances:read",
            "bill8:ledger:balance-transactions:write",
        ],
    },
];

/// Declarative event triggers (alignment doc §12): PMS emits the
/// reservation/inventory domain events; the CONSUMING services (loyalty,
/// pos, upsell, distrib, meta) drain them in their own consumer groups
/// (direct consumers — no Func needed).
///
/// `json!` is not const-callable, so the slice is leaked once per process
/// (registration runs once at boot/`--print-registration`).
fn event_triggers() -> &'static [EventTriggerDecl] {
    use std::sync::OnceLock;
    static TRIGGERS: OnceLock<&'static [EventTriggerDecl]> = OnceLock::new();
    TRIGGERS.get_or_init(|| {
        let decls = vec![
            EventTriggerDecl {
                event_type: "hotel8:pms:reservation:checked_out",
                target: serde_json::json!({ "kind": "direct" }),
                consumer_group: "hotel8-loyalty-awards",
                retry: serde_json::json!({ "max_retries": 3, "backoff": "exponential" }),
            },
            EventTriggerDecl {
                event_type: "hotel8:pms:reservation:checked_in",
                target: serde_json::json!({ "kind": "direct" }),
                consumer_group: "hotel8-pos-table-prep",
                retry: serde_json::json!({ "max_retries": 3, "backoff": "exponential" }),
            },
            EventTriggerDecl {
                event_type: "hotel8:pms:reservation:created",
                target: serde_json::json!({ "kind": "direct" }),
                consumer_group: "hotel8-upsell-offers",
                retry: serde_json::json!({ "max_retries": 3, "backoff": "exponential" }),
            },
            EventTriggerDecl {
                event_type: "hotel8:pms:inventory:updated",
                target: serde_json::json!({ "kind": "direct" }),
                consumer_group: "hotel8-distrib-ari",
                retry: serde_json::json!({ "max_retries": 3, "backoff": "exponential" }),
            },
            EventTriggerDecl {
                event_type: "hotel8:pms:inventory:updated",
                target: serde_json::json!({ "kind": "direct" }),
                consumer_group: "hotel8-meta-ari-sync",
                retry: serde_json::json!({ "max_retries": 3, "backoff": "exponential" }),
            },
        ];
        Box::leak(decls.into_boxed_slice())
    })
}

const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:admin",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:read",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:reservation:write",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:reservation:read",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:frontdesk:write",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:frontdesk:read",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:cashiering:write",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:cashiering:read",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:housekeeping:write",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:housekeeping:read",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:profile:write",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:profile:read",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:rate:write",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:rate:read",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:block:write",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:block:read",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:event:write",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:availability:read",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:report:read",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:eod:write",
    },
    // Policy-admin surface (policy design §3.6; principles §6.0b per-service scope).
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:policy:read",
    },
    AdminScope::Typed {
        role: "hotel8:pms:admin",
        scope: "hotel8:pms:policy:write",
    },
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "overview",
        label: "Overview",
        ui_endpoint: "/v1/admin/ui/overview",
        data_endpoint: "/v1/admin/overview",
        icon: "0xe1b1",
    },
    AdminUiPage {
        route: "reservations",
        label: "Reservations",
        ui_endpoint: "/v1/admin/ui/reservations",
        data_endpoint: "/v1/admin/reservations",
        icon: "0xe23e",
    },
    AdminUiPage {
        route: "frontdesk",
        label: "Front Desk",
        ui_endpoint: "/v1/admin/ui/frontdesk",
        data_endpoint: "/v1/admin/frontdesk",
        icon: "0xe621",
    },
    AdminUiPage {
        route: "housekeeping",
        label: "Housekeeping",
        ui_endpoint: "/v1/admin/ui/housekeeping",
        data_endpoint: "/v1/admin/housekeeping",
        icon: "0xe167",
    },
    AdminUiPage {
        route: "rates",
        label: "Rates",
        ui_endpoint: "/v1/admin/ui/rates",
        data_endpoint: "/v1/admin/rates",
        icon: "0xe4e8",
    },
    AdminUiPage {
        route: "blocks",
        label: "Blocks",
        ui_endpoint: "/v1/admin/ui/blocks",
        data_endpoint: "/v1/admin/blocks",
        icon: "0xe0e1",
    },
    AdminUiPage {
        route: "events",
        label: "Events",
        ui_endpoint: "/v1/admin/ui/events",
        data_endpoint: "/v1/admin/events",
        icon: "0xe44f",
    },
    AdminUiPage {
        route: "reports",
        label: "Reports",
        ui_endpoint: "/v1/admin/ui/reports",
        data_endpoint: "/v1/admin/reports",
        icon: "0xe0a4",
    },
    AdminUiPage {
        route: "settings",
        label: "Settings",
        ui_endpoint: "/v1/admin/ui/settings",
        data_endpoint: "/v1/admin/settings",
        icon: "0xe57f",
    },
    AdminUiPage {
        route: "corporate",
        label: "Corporate",
        ui_endpoint: "/v1/admin/ui/corporate",
        data_endpoint: "/v1/admin/corporate",
        icon: "0xe7ef",
    },
    AdminUiPage {
        route: "kiosk-config",
        label: "Kiosk Config",
        ui_endpoint: "/v1/admin/ui/kiosk-config",
        data_endpoint: "/v1/admin/kiosk-config",
        icon: "0xe57f",
    }, // Sentin8:Policy admin surface (Shield pattern).
    AdminUiPage {
        route: "policy-sets",
        label: "Policy Sets",
        ui_endpoint: "/v1/admin/ui/policy-sets",
        data_endpoint: "/v1/admin/policy-sets",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "policy-decisions",
        label: "Policy Decisions",
        ui_endpoint: "/v1/admin/ui/policy-decisions",
        data_endpoint: "/v1/admin/policy-decisions",
        icon: "0xf070",
    },
    AdminUiPage {
        route: "relations",
        label: "Relations",
        ui_endpoint: "/v1/admin/ui/relations",
        data_endpoint: "/v1/admin/relations",
        icon: "0xe572",
    },
    AdminUiPage {
        route: "attributes",
        label: "Attributes",
        ui_endpoint: "/v1/admin/ui/attributes",
        data_endpoint: "/v1/admin/attributes",
        icon: "0xe8d3",
    },
];

/// The Shield text of the declared scope-mirror set — public so the
/// policy wiring tests assert against the REAL seed (drift
/// fails the suite instead of silently diverging from enrollment).
pub const SCOPE_MIRROR_POLICIES: &str = "permit(principal, action == Action::\"hotel8:pms:admin\", resource) when { principal.scopes.contains(\"hotel8:pms:admin\") };\npermit(principal, action == Action::\"hotel8:pms:admin\", resource) when { principal.scopes.contains(\"hotel8:pms:blocks:write\") };\npermit(principal, action == Action::\"hotel8:pms:admin\", resource) when { principal.scopes.contains(\"hotel8:pms:eod:read\") };\npermit(principal, action == Action::\"hotel8:pms:admin\", resource) when { principal.scopes.contains(\"hotel8:pms:eod:write\") };\npermit(principal, action == Action::\"hotel8:pms:admin\", resource) when { principal.scopes.contains(\"hotel8:pms:frontdesk:read\") };\npermit(principal, action == Action::\"hotel8:pms:admin\", resource) when { principal.scopes.contains(\"hotel8:pms:housekeeping:read\") };\npermit(principal, action == Action::\"hotel8:pms:admin\", resource) when { principal.scopes.contains(\"hotel8:pms:read\") };\npermit(principal, action == Action::\"hotel8:pms:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:admin\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:block:read\", resource) when { principal.scopes.contains(\"hotel8:pms:block:read\") };\npermit(principal, action == Action::\"hotel8:pms:block:read\", resource) when { principal.scopes.contains(\"hotel8:pms:read\") };\npermit(principal, action == Action::\"hotel8:pms:block:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:block:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:block:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:block:write\", resource) when { principal.scopes.contains(\"hotel8:pms:block:write\") };\npermit(principal, action == Action::\"hotel8:pms:block:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:block:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:block:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:cashiering:read\", resource) when { principal.scopes.contains(\"hotel8:pms:cashiering:read\") };\npermit(principal, action == Action::\"hotel8:pms:cashiering:read\", resource) when { principal.scopes.contains(\"hotel8:pms:read\") };\npermit(principal, action == Action::\"hotel8:pms:cashiering:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:cashiering:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:cashiering:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:cashiering:write\", resource) when { principal.scopes.contains(\"hotel8:pms:cashiering:write\") };\npermit(principal, action == Action::\"hotel8:pms:cashiering:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:cashiering:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:cashiering:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:event:read\", resource) when { principal.scopes.contains(\"hotel8:pms:event:read\") };\npermit(principal, action == Action::\"hotel8:pms:event:read\", resource) when { principal.scopes.contains(\"hotel8:pms:read\") };\npermit(principal, action == Action::\"hotel8:pms:event:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:event:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:event:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:event:write\", resource) when { principal.scopes.contains(\"hotel8:pms:event:write\") };\npermit(principal, action == Action::\"hotel8:pms:event:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:event:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:event:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:frontdesk:read\", resource) when { principal.scopes.contains(\"hotel8:pms:frontdesk:read\") };\npermit(principal, action == Action::\"hotel8:pms:frontdesk:read\", resource) when { principal.scopes.contains(\"hotel8:pms:read\") };\npermit(principal, action == Action::\"hotel8:pms:frontdesk:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:frontdesk:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:frontdesk:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:frontdesk:write\", resource) when { principal.scopes.contains(\"hotel8:pms:frontdesk:write\") };\npermit(principal, action == Action::\"hotel8:pms:frontdesk:write\", resource) when { principal.scopes.contains(\"hotel8:pms:housekeeping:write\") };\npermit(principal, action == Action::\"hotel8:pms:frontdesk:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:frontdesk:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:frontdesk:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:housekeeping:read\", resource) when { principal.scopes.contains(\"hotel8:pms:housekeeping:read\") };\npermit(principal, action == Action::\"hotel8:pms:housekeeping:read\", resource) when { principal.scopes.contains(\"hotel8:pms:read\") };\npermit(principal, action == Action::\"hotel8:pms:housekeeping:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:housekeeping:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:housekeeping:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:housekeeping:write\", resource) when { principal.scopes.contains(\"hotel8:pms:housekeeping:write\") };\npermit(principal, action == Action::\"hotel8:pms:housekeeping:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:housekeeping:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:housekeeping:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:inventory:write\", resource) when { principal.scopes.contains(\"hotel8:pms:inventory:write\") };\npermit(principal, action == Action::\"hotel8:pms:inventory:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:inventory:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:inventory:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:profile:read\", resource) when { principal.scopes.contains(\"hotel8:pms:profile:read\") };\npermit(principal, action == Action::\"hotel8:pms:profile:read\", resource) when { principal.scopes.contains(\"hotel8:pms:read\") };\npermit(principal, action == Action::\"hotel8:pms:profile:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:profile:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:profile:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:profile:write\", resource) when { principal.scopes.contains(\"hotel8:pms:profile:write\") };\npermit(principal, action == Action::\"hotel8:pms:profile:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:profile:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:profile:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:rate:read\", resource) when { principal.scopes.contains(\"hotel8:pms:rate:read\") };\npermit(principal, action == Action::\"hotel8:pms:rate:read\", resource) when { principal.scopes.contains(\"hotel8:pms:read\") };\npermit(principal, action == Action::\"hotel8:pms:rate:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:rate:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:rate:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:rate:write\", resource) when { principal.scopes.contains(\"hotel8:pms:admin\") };\npermit(principal, action == Action::\"hotel8:pms:rate:write\", resource) when { principal.scopes.contains(\"hotel8:pms:rate:write\") };\npermit(principal, action == Action::\"hotel8:pms:rate:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:rate:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:rate:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:read\", resource) when { principal.scopes.contains(\"hotel8:pms:availability:read\") };\npermit(principal, action == Action::\"hotel8:pms:read\", resource) when { principal.scopes.contains(\"hotel8:pms:inventory:read\") };\npermit(principal, action == Action::\"hotel8:pms:read\", resource) when { principal.scopes.contains(\"hotel8:pms:read\") };\npermit(principal, action == Action::\"hotel8:pms:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:report:read\", resource) when { principal.scopes.contains(\"hotel8:pms:read\") };\npermit(principal, action == Action::\"hotel8:pms:report:read\", resource) when { principal.scopes.contains(\"hotel8:pms:report:read\") };\npermit(principal, action == Action::\"hotel8:pms:report:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:report:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:report:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:reservation:read\", resource) when { principal.scopes.contains(\"hotel8:pms:read\") };\npermit(principal, action == Action::\"hotel8:pms:reservation:read\", resource) when { principal.scopes.contains(\"hotel8:pms:reservation:read\") };\npermit(principal, action == Action::\"hotel8:pms:reservation:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:reservation:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:reservation:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"hotel8:pms:reservation:write\", resource) when { principal.scopes.contains(\"hotel8:pms:reservation:write\") };\npermit(principal, action == Action::\"hotel8:pms:reservation:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"hotel8:pms:reservation:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"hotel8:pms:reservation:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };";

/// Default declarative policy set (Sentin8:Policy design §3.2/§3.4,
/// seeded by `vertical enroll` as `origin='platform'`, `mode='enforced'`):
/// action-granular scope permits over the LIVE effective scope set — the
/// exact mirror of the gates this service's handlers evaluate in step 5
/// (policy design §4.3). Enforced: step 5 is the
/// only gate; shadow is the emergency one-UPDATE rollback lever only.
const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for hotel8:pms over the LIVE effective scope set (design §3.1d). Enforced — step 5 is the only gate.",
    // Shield text lives in SCOPE_MIRROR_POLICIES (single source).
    policies: SCOPE_MIRROR_POLICIES,
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

/// Default ReBAC relation tuples (design §3.1c) — none declared by this
/// service today; env admins author their own graph (staff→station,
/// channel-partner, holder edges) via the relations admin API.
const RELATIONS: &[RelationDecl] = &[];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::PmsOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

/// Print the registration JSON to stdout.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "hotel8:pms",
        subdomain: "hotel8-pms",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "PMS",
            icon: "0xe322",
            service_flag: "pms",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        pg_roles: PG_ROLES,
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: event_triggers(),
        schedules: &[],
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
