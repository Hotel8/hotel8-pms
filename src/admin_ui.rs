// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Hotel8:PMS Admin UI handlers - RFW definitions.
//! Served from `GET /v1/admin/ui/{page}`, rendered by Sentin8:Dash at runtime.

use crate::handlers::AppState;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    responses(
        (status = 200, description = "OK - RFW page definition rendered by Sentin8:Dash: the SDK envelope tagged response_type = page|redirect|error (page carries the AdminPage widget tree; error carries message + code). Defined by sentin8::rfw; not re-schemaed here.", body = sentin8::rfw::AdminUiResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Unknown admin UI page"),
    ),
    security(),
    tag = "pms-admin",
)]

pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("hotel8:pms:admin"),
    )
    .await?;
    let def = match page.as_str() {
        "overview" => AdminPage::new("PMS Overview")
            .widget(card(
                "Summary",
                "Reservations, front desk, housekeeping, rates, blocks, events, reports.",
            ))
            .build(),
        "reservations" => AdminPage::new("Reservations")
            .widget(table(
                vec![
                    col("id", "Reservation ID"),
                    cols("guest_name", "Guest"),
                    cols("status", "Status"),
                    cols("check_in", "Check In"),
                ],
                "/reservations",
            ))
            .build(),
        "frontdesk" => AdminPage::new("Front Desk")
            .widget(card("Front Desk", "Check-in, check-out, room assignments."))
            .build(),
        "housekeeping" => AdminPage::new("Housekeeping")
            .widget(table(
                vec![
                    col("room_number", "Room"),
                    cols("status", "Status"),
                    cols("assigned_to", "Assigned"),
                ],
                "/housekeeping",
            ))
            .build(),
        "rates" => AdminPage::new("Rates")
            .widget(table(
                vec![
                    col("id", "Rate ID"),
                    cols("name", "Rate Plan"),
                    cols("amount", "Amount"),
                ],
                "/rates",
            ))
            .build(),
        "blocks" => AdminPage::new("Blocks")
            .widget(table(
                vec![
                    col("id", "Block ID"),
                    cols("name", "Block Name"),
                    cols("rooms", "Rooms"),
                ],
                "/blocks",
            ))
            .build(),
        "events" => AdminPage::new("Events")
            .widget(table(
                vec![
                    col("id", "Event ID"),
                    cols("name", "Event"),
                    cols("date", "Date"),
                ],
                "/events",
            ))
            .build(),
        "reports" => AdminPage::new("Reports")
            .widget(card("Reports", "Occupancy, revenue, ADR, RevPAR reports."))
            .build(),
        "settings" => AdminPage::new("PMS Settings")
            .widget(card("Settings", "Hotel8:PMS configuration."))
            .widget(RemoteWidget::Button(WidgetButton {
                label: "Kiosk terminal config".into(),
                button_type: ButtonType::Link,
                route: Some("/kiosk-config".into()),
                endpoint: None,
                icon: None,
            }))
            .build(),
        // Kiosk terminal config - the eKiosk mode-menu source of truth
        // (pms/DESIGN.md §3 "Staff & corporate surfaces"); the form PUTs
        // via the submit alias on the same resource.
        "kiosk-config" => AdminPage::new("Kiosk Terminal Config")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "CHECK_IN".into(),
                        label: "Check-in mode".into(),
                        field_type: FormFieldType::Checkbox,
                        required: false,
                        placeholder: None,
                        default_value: Some(serde_json::json!(true)),
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "CHECK_OUT".into(),
                        label: "Check-out mode".into(),
                        field_type: FormFieldType::Checkbox,
                        required: false,
                        placeholder: None,
                        default_value: Some(serde_json::json!(true)),
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "COLLECT_KEY".into(),
                        label: "Key collection mode".into(),
                        field_type: FormFieldType::Checkbox,
                        required: false,
                        placeholder: None,
                        default_value: Some(serde_json::json!(true)),
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "WALK_IN".into(),
                        label: "Walk-in booking mode".into(),
                        field_type: FormFieldType::Checkbox,
                        required: false,
                        placeholder: None,
                        default_value: Some(serde_json::json!(false)),
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "lockdown".into(),
                        label: "Lockdown terminal".into(),
                        field_type: FormFieldType::Toggle,
                        required: false,
                        placeholder: None,
                        default_value: Some(serde_json::json!(false)),
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some(
                            "Freezes the terminal at the attract loop (staff unlock at the device)"
                                .into(),
                        ),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "max_keys_per_stay".into(),
                        label: "Max keys per stay".into(),
                        field_type: FormFieldType::Number,
                        required: false,
                        placeholder: None,
                        default_value: Some(serde_json::json!(4)),
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/kiosk-config".into(),
                submit_label: "Save kiosk config".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Put,
            }))
            .build(),
        // Corporate account admin (ECRP-2) - company roster + credit methods
        // + traveler users + negotiated-rate links (pms/DESIGN.md §4).
        "corporate" => AdminPage::new("Corporate Accounts")
            .widget(RemoteWidget::DataTable(WidgetDataTable {
                columns: vec![
                    cols("company_name", "Company"),
                    cols("email", "Email"),
                    cols("credit_approvals", "Credit Approvals"),
                ],
                data_endpoint: "/companies".into(),
                sortable: true,
                filterable: true,
                page_size: 20,
                empty_message: Some("No corporate accounts yet.".into()),
                row_link: None,
                row_actions: vec![],
            }))
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "company_profile_id".into(),
                        label: "Company profile ID".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some("From the table above".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "label".into(),
                        label: "Method label".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: None,
                        default_value: Some(serde_json::json!("Corporate account")),
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "approval".into(),
                        label: "Credit approval".into(),
                        field_type: FormFieldType::Select,
                        required: true,
                        placeholder: None,
                        default_value: Some(serde_json::json!("POSTPAY")),
                        options: Some(vec![
                            FormFieldOption {
                                value: "PENDING".into(),
                                label: "Pending".into(),
                            },
                            FormFieldOption {
                                value: "POSTPAY".into(),
                                label: "Post-pay".into(),
                            },
                            FormFieldOption {
                                value: "BILL_TO_COMPANY".into(),
                                label: "Bill to company".into(),
                            },
                            FormFieldOption {
                                value: "REJECTED".into(),
                                label: "Rejected".into(),
                            },
                        ]),
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "payment_method_id".into(),
                        label: "Payment method reference".into(),
                        field_type: FormFieldType::Text,
                        required: false,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "credit_limit".into(),
                        label: "Credit limit".into(),
                        field_type: FormFieldType::Decimal,
                        required: false,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/company_payment_methods".into(),
                submit_label: "Save credit method".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "company_profile_id".into(),
                        label: "Company profile ID".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some("From the table above".into()),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "traveler_profile_id".into(),
                        label: "Traveler profile ID".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: None,
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "role_at_company".into(),
                        label: "Role".into(),
                        field_type: FormFieldType::Select,
                        required: true,
                        placeholder: None,
                        default_value: Some(serde_json::json!("TRAVELER")),
                        options: Some(vec![
                            FormFieldOption {
                                value: "ADMIN".into(),
                                label: "Admin".into(),
                            },
                            FormFieldOption {
                                value: "BOOKING_AGENT".into(),
                                label: "Booking agent".into(),
                            },
                            FormFieldOption {
                                value: "TRAVELER".into(),
                                label: "Traveler".into(),
                            },
                        ]),
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "is_default".into(),
                        label: "Default company".into(),
                        field_type: FormFieldType::Toggle,
                        required: false,
                        placeholder: None,
                        default_value: Some(serde_json::json!(false)),
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/company_users".into(),
                submit_label: "Bind user".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        // ── Policy Studio - shared page
        // constructors; the guard guarantees `Some` (§3.7 dispatch).
        p if sentin8::rfw::policy_page("hotel8:pms", p).is_some() => {
            sentin8::rfw::policy_page("hotel8:pms", p)
                .expect("policy_page checked in guard")
                .build()
        }
        _ => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ))
        }
    };
    Ok(Json(AdminUiResponse::page(def)))
}

#[allow(dead_code)]
fn col(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: false,
        width: None,
        format: None,
    }
}
#[allow(dead_code)]
fn cols(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: true,
        width: None,
        format: None,
    }
}
#[allow(dead_code)]
fn table(columns: Vec<WidgetDataTableColumn>, endpoint: &str) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions: vec![],
    })
}
fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}
#[allow(dead_code)]
fn link(label: &str, route: &str) -> AdminUiAction {
    AdminUiAction {
        label: label.into(),
        action_type: AdminUiActionType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: Some("0xe145".into()),
    }
}
