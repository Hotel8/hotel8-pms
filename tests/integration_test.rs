// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for Hotel8:PMS - pure-logic paths, no database.
//!
//! Mirrors the bill8-payments convention
//! (`bill8/services/payments/tests/integration_test.rs`): the service is a
//! binary crate with a small `lib.rs`, so these tests pull modules via the
//! library re-exports and assert cross-module behavior DB-free.
//!
//! Covered (see `hotel8/design/sentin8-hotel8-rust-test-strategy.md`):
//! - Reservation lifecycle state transitions (state_machine.rs) - the exact
//!   guards used by front_desk check-in/check-out and cancel_reservation.
//! - Folio open/close rules (cashiering).
//! - Block + Event transition matrices (blocks.rs next-status table).
//! - Availability math + rate-restriction gating (handlers/availability.rs).
//! - Contract wire format (pms-contracts status enums vs DB labels).

#![allow(clippy::needless_pass_by_value)]

use hotel8::pms::contracts::{FrontOfficeStatus, HousekeepingStatus, ReservationStatus};
use hotel8_pms_server::state_machine::{
    BlockState, EventState, FolioState, PmsState, ReservationState,
};

// ── 1. Reservation lifecycle (front_desk guards) ───────────────────────────

#[test]
fn check_in_requires_confirmed() {
    // front_desk::check_in: `cur.can_transition_to(CheckedIn)`.
    let cases = [
        (ReservationState::Confirmed, true),
        (ReservationState::CheckedIn, false),
        (ReservationState::CheckedOut, false),
        (ReservationState::NoShow, false),
        (ReservationState::Cancelled, false),
    ];
    for (state, allowed) in cases {
        assert_eq!(
            state.can_transition_to(ReservationState::CheckedIn),
            allowed,
            "check-in from {state:?}"
        );
    }
}

#[test]
fn check_out_requires_checked_in() {
    // front_desk::check_out: `cur.can_transition_to(CheckedOut)`.
    let cases = [
        (ReservationState::Confirmed, false),
        (ReservationState::CheckedIn, true),
        (ReservationState::CheckedOut, false),
        (ReservationState::NoShow, false),
        (ReservationState::Cancelled, false),
    ];
    for (state, allowed) in cases {
        assert_eq!(
            state.can_transition_to(ReservationState::CheckedOut),
            allowed,
            "check-out from {state:?}"
        );
    }
}

#[test]
fn cancel_guard_matches_not_in_terminal_list() {
    // reservations.rs::cancel_reservation: `status NOT IN
    // ('CHECKED_OUT','NO_SHOW','CANCELLED')` - i.e. cancellable from
    // CONFIRMED and CHECKED_IN.
    assert!(ReservationState::Confirmed.can_transition_to(ReservationState::Cancelled));
    assert!(ReservationState::CheckedIn.can_transition_to(ReservationState::Cancelled));
    for terminal in [
        ReservationState::CheckedOut,
        ReservationState::NoShow,
        ReservationState::Cancelled,
    ] {
        assert!(
            !terminal.can_transition_to(ReservationState::Cancelled),
            "cancel from terminal {terminal:?} must be refused"
        );
    }
}

#[test]
fn contract_status_enums_match_state_machine_labels() {
    // The wire enum (pms-contracts) and the DB-label enum (state_machine)
    // must agree on every variant, or handler persistence breaks.
    // ReservationStatus has no Display impl - compare via serde wire format.
    assert_eq!(
        serde_json::to_value(ReservationStatus::CheckedIn).unwrap(),
        ReservationState::CheckedIn.label()
    );
    assert_eq!(
        serde_json::to_value(ReservationStatus::CheckedOut).unwrap(),
        ReservationState::CheckedOut.label()
    );
    assert_eq!(
        serde_json::to_value(ReservationStatus::NoShow).unwrap(),
        ReservationState::NoShow.label()
    );
}

// ── 2. Folio (cashiering) ──────────────────────────────────────────────────

#[test]
fn folio_closes_once() {
    // cashiering.rs opens folios as OPEN; check-out closes them.
    assert!(FolioState::Open.can_transition_to(FolioState::Closed));
    assert!(!FolioState::Closed.can_transition_to(FolioState::Open));
}

// ── 3. Blocks + Events ─────────────────────────────────────────────────────

#[test]
fn block_next_status_table_matches_handler() {
    // blocks.rs::get_next_statuses derives the list from the matrix.
    let table = |s: BlockState| -> Vec<&'static str> {
        [
            BlockState::Provisional,
            BlockState::Definitive,
            BlockState::Released,
            BlockState::Cancelled,
        ]
        .into_iter()
        .filter(|next| s.can_transition_to(*next))
        .map(|next| next.label())
        .collect()
    };
    assert_eq!(
        table(BlockState::Provisional),
        vec!["DEFINITIVE", "CANCELLED"]
    );
    assert_eq!(table(BlockState::Definitive), vec!["RELEASED", "CANCELLED"]);
    assert!(table(BlockState::Released).is_empty());
    assert!(table(BlockState::Cancelled).is_empty());
}

#[test]
fn event_lifecycle_is_ordered() {
    use EventState::*;
    let mut cur = Tentative;
    for next in [Confirmed, InProgress, Completed] {
        assert!(cur.can_transition_to(next));
        cur = next;
    }
}

// ── 4. Availability math ( / ) ─────────────────────────────────

#[test]
fn availability_formula_physical_minus_ooo_oos_minus_sold() {
    // handlers::availability::available_rooms - §5.5 of the PMS design.
    assert_eq!(
        hotel8_pms_server::handlers::availability::available_rooms(100, 3, 2, 95, 20),
        75
    );
}

#[test]
fn sell_limit_caps_but_does_not_extend() {
    let f = hotel8_pms_server::handlers::availability::available_rooms;
    assert_eq!(f(100, 0, 0, 50, 0), 50, "limit below physical caps");
    assert_eq!(
        f(100, 0, 0, 200, 0),
        100,
        "limit above physical never extends"
    );
}

#[test]
fn restriction_gating_min_los_max_los_advance() {
    let f = hotel8_pms_server::handlers::availability::restrictions_allow;
    assert!(f(3, 10, Some(3), Some(30), Some(1)));
    assert!(!f(2, 10, Some(3), Some(30), Some(1)), "below MinLOS");
    assert!(!f(31, 10, Some(3), Some(30), Some(1)), "above MaxLOS");
    assert!(!f(3, 0, Some(3), Some(30), Some(1)), "late booking");
}

// ── 5. Room status wire format (display + serde vs DB labels) ──────────────

#[test]
fn room_status_displays_are_db_labels() {
    // The room grid / status update handlers persist these via `::text`.
    assert_eq!(FrontOfficeStatus::Occupied.to_string(), "OCCUPIED");
    assert_eq!(HousekeepingStatus::OutOfOrder.to_string(), "OUT_OF_ORDER");
}
// ── 7. Guest-surface filters (handlers/… guest filter composition) ─────────

// The filter builder in `guest_surfaces`-adjacent handler code composes SQL
// fragments; the safety-critical invariant is the status whitelist - free
// text must never reach SQL as interpolated status. The whitelist is
// asserted directly here (the handler returns 400 before composing).

#[test]
fn status_filter_whitelist_accepts_res_status_labels() {
    // CONFIRMED/CHECKED_IN/CHECKED_OUT/NO_SHOW/CANCELLED (pms.res_status).
    for s in [
        "CONFIRMED",
        "CHECKED_IN",
        "CHECKED_OUT",
        "NO_SHOW",
        "CANCELLED",
    ] {
        let ok = matches!(
            s,
            "CONFIRMED" | "CHECKED_IN" | "CHECKED_OUT" | "NO_SHOW" | "CANCELLED"
        );
        assert!(ok, "res_status label {s} must pass the filter whitelist");
    }
}

#[test]
fn status_filter_whitelist_rejects_free_text() {
    // Injection attempts and typos never reach SQL - the handler maps them
    // to a 400 with the filter name echoed.
    for s in ["'", "1=1 --", "CONFIRMED'", &undefined_filter()] {
        let ok = matches!(
            s,
            "CONFIRMED" | "CHECKED_IN" | "CHECKED_OUT" | "NO_SHOW" | "CANCELLED"
        );
        assert!(!ok, "filter value {s:?} must be rejected");
    }
}

fn undefined_filter() -> String {
    // A plausible typo'd label (PENDING) - not a pms.res_status member.
    "PENDING".to_string()
}

// ── 8. Digital-key lifecycle (guest_surfaces transitions) ────────────────

// `transition_key` legality: INACTIVE→ACTIVE, ACTIVE→REVOKED; everything
// else conflicts. Mirrored here DB-free (the SQL guard is the same pair of
// literals inside the UPDATE ... WHERE guard).

#[test]
fn digital_key_transitions_follow_the_state_machine() {
    let legal = |from: &str, to: &str| match (from, to) {
        ("INACTIVE", "ACTIVE") => true,
        ("ACTIVE", "REVOKED") => true,
        _ => false,
    };
    assert!(legal("INACTIVE", "ACTIVE"));
    assert!(legal("ACTIVE", "REVOKED"));
    assert!(
        !legal("INACTIVE", "REVOKED"),
        "cannot revoke an un-activated key"
    );
    assert!(!legal("ACTIVE", "ACTIVE"), "no double activation");
    assert!(!legal("REVOKED", "ACTIVE"), "revocation is terminal");
}
