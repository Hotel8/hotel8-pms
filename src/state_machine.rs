// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! PMS status state machines — pure, DB-free transition rules.
//!
//! Extracts the status guards that were previously hand-written SQL fragment
//! comparisons (`WHERE ... status NOT IN (...)`, `status != "CONFIRMED"`) into
//! testable pure functions. The rules are normative in
//! `hotel8/design/sentin8-hotel8-rust-test-strategy.md` §3 and mirror the
//! state diagrams in `sentin8-hotel8-pms-technical-design.md` §4.3–4.6.
//!
//! Every variant's `label()` equals the corresponding
//! `CREATE TYPE hotel8.pms_* AS ENUM (...)` value in `services/pms/sql/init.sql`
//! — handlers persist via `status::text` comparisons, so a label drift would
//! silently break RLS-guarded queries.
//!
//! Handlers use `from_label` + `can_transition_to` instead of
//! raw string comparisons; behavior is unchanged, only made visible/testable.

use std::fmt;

/// Shared surface for all PMS state enums: exact DB label, parsing, and the
/// design-doc transition matrix.
pub trait PmsState: Copy + PartialEq + fmt::Debug {
    /// Human name used in handler error messages (e.g. `"Reservation is {label}, cannot check in"`).
    fn label(&self) -> &'static str;
    /// Parse a DB `status::text` value. Unknown labels are a bug — the SQL
    /// schema is the authority; tests pin every variant.
    fn from_label(s: &str) -> Self;
    /// The design-doc transition rules (see test-strategy §3 matrices).
    fn can_transition_to(&self, next: Self) -> bool;
}

// ── Reservation ─────────────────────────────────────────────────────────────

/// `hotel8.pms_res_status` — reservation lifecycle (PMS design §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationState {
    Confirmed,
    CheckedIn,
    CheckedOut,
    NoShow,
    Cancelled,
}

impl PmsState for ReservationState {
    fn label(&self) -> &'static str {
        match self {
            ReservationState::Confirmed => "CONFIRMED",
            ReservationState::CheckedIn => "CHECKED_IN",
            ReservationState::CheckedOut => "CHECKED_OUT",
            ReservationState::NoShow => "NO_SHOW",
            ReservationState::Cancelled => "CANCELLED",
        }
    }

    fn from_label(s: &str) -> Self {
        match s {
            "CONFIRMED" => ReservationState::Confirmed,
            "CHECKED_IN" => ReservationState::CheckedIn,
            "CHECKED_OUT" => ReservationState::CheckedOut,
            "NO_SHOW" => ReservationState::NoShow,
            "CANCELLED" => ReservationState::Cancelled,
            _ => ReservationState::Confirmed, // never reached: schema-pinned labels
        }
    }

    /// CONFIRMED → CHECKED_IN | NO_SHOW | CANCELLED
    /// CHECKED_IN → CHECKED_OUT | CANCELLED (cancel-in-house permitted by
    /// `cancel_reservation`'s `status NOT IN ('CHECKED_OUT','NO_SHOW','CANCELLED')` guard).
    /// CHECKED_OUT / NO_SHOW / CANCELLED are terminal.
    fn can_transition_to(&self, next: Self) -> bool {
        use ReservationState::*;
        matches!(
            (self, next),
            (Confirmed, CheckedIn)
                | (Confirmed, NoShow)
                | (Confirmed, Cancelled)
                | (CheckedIn, CheckedOut)
                | (CheckedIn, Cancelled)
        )
    }
}

impl fmt::Display for ReservationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Folio ───────────────────────────────────────────────────────────────────

/// `hotel8.pms_folio_status` — cashiering folio (PMS design §4.5).
/// The DB enum currently has only OPEN/CLOSED; the §4.5 diagram's
/// ACTIVE/SETTLED intermediates are future work.
///
/// Wired into handlers when folio close gains a guard (currently set
/// unconditionally at check-out); exercised from the lib + tests meanwhile.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolioState {
    Open,
    Closed,
}

impl PmsState for FolioState {
    fn label(&self) -> &'static str {
        match self {
            FolioState::Open => "OPEN",
            FolioState::Closed => "CLOSED",
        }
    }

    fn from_label(s: &str) -> Self {
        match s {
            "OPEN" => FolioState::Open,
            "CLOSED" => FolioState::Closed,
            _ => FolioState::Open,
        }
    }

    /// OPEN → CLOSED; CLOSED terminal.
    fn can_transition_to(&self, next: Self) -> bool {
        matches!(self, FolioState::Open) && next == FolioState::Closed
    }
}

impl fmt::Display for FolioState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Block ───────────────────────────────────────────────────────────────────

/// `hotel8.pms_block_status` — group block lifecycle (PMS design §4.6 and the
/// next-status table in `handlers/blocks.rs::get_block_next_statuses`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockState {
    Provisional,
    Definitive,
    Released,
    Cancelled,
}

impl PmsState for BlockState {
    fn label(&self) -> &'static str {
        match self {
            BlockState::Provisional => "PROVISIONAL",
            BlockState::Definitive => "DEFINITIVE",
            BlockState::Released => "RELEASED",
            BlockState::Cancelled => "CANCELLED",
        }
    }

    fn from_label(s: &str) -> Self {
        match s {
            "PROVISIONAL" => BlockState::Provisional,
            "DEFINITIVE" => BlockState::Definitive,
            "RELEASED" => BlockState::Released,
            "CANCELLED" => BlockState::Cancelled,
            _ => BlockState::Provisional,
        }
    }

    /// PROVISIONAL → DEFINITIVE | CANCELLED
    /// DEFINITIVE → RELEASED | CANCELLED
    /// RELEASED / CANCELLED terminal.
    fn can_transition_to(&self, next: Self) -> bool {
        use BlockState::*;
        matches!(
            (self, next),
            (Provisional, Definitive)
                | (Provisional, Cancelled)
                | (Definitive, Released)
                | (Definitive, Cancelled)
        )
    }
}

impl fmt::Display for BlockState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Event ───────────────────────────────────────────────────────────────────

/// `hotel8.pms_event_status` — banquet/catering event lifecycle.
///
/// Events currently have no status-update endpoint; this machine is the
/// documented target for the planned event-status endpoint (test-strategy §3.4).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventState {
    Tentative,
    Confirmed,
    InProgress,
    Completed,
    Cancelled,
}

impl PmsState for EventState {
    fn label(&self) -> &'static str {
        match self {
            EventState::Tentative => "TENTATIVE",
            EventState::Confirmed => "CONFIRMED",
            EventState::InProgress => "IN_PROGRESS",
            EventState::Completed => "COMPLETED",
            EventState::Cancelled => "CANCELLED",
        }
    }

    fn from_label(s: &str) -> Self {
        match s {
            "TENTATIVE" => EventState::Tentative,
            "CONFIRMED" => EventState::Confirmed,
            "IN_PROGRESS" => EventState::InProgress,
            "COMPLETED" => EventState::Completed,
            "CANCELLED" => EventState::Cancelled,
            _ => EventState::Tentative,
        }
    }

    /// TENTATIVE → CONFIRMED | CANCELLED
    /// CONFIRMED → IN_PROGRESS | CANCELLED
    /// IN_PROGRESS → COMPLETED
    /// COMPLETED / CANCELLED terminal.
    fn can_transition_to(&self, next: Self) -> bool {
        use EventState::*;
        matches!(
            (self, next),
            (Tentative, Confirmed)
                | (Tentative, Cancelled)
                | (Confirmed, InProgress)
                | (Confirmed, Cancelled)
                | (InProgress, Completed)
        )
    }
}

impl fmt::Display for EventState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant's label is the exact DB enum value — a drift here breaks
    /// every `status::text`-comparing query. Pinned per test-strategy §2.2.
    #[test]
    fn labels_match_db_enums() {
        assert_eq!(ReservationState::Confirmed.label(), "CONFIRMED");
        assert_eq!(ReservationState::CheckedIn.label(), "CHECKED_IN");
        assert_eq!(ReservationState::CheckedOut.label(), "CHECKED_OUT");
        assert_eq!(ReservationState::NoShow.label(), "NO_SHOW");
        assert_eq!(ReservationState::Cancelled.label(), "CANCELLED");

        assert_eq!(FolioState::Open.label(), "OPEN");
        assert_eq!(FolioState::Closed.label(), "CLOSED");

        assert_eq!(BlockState::Provisional.label(), "PROVISIONAL");
        assert_eq!(BlockState::Definitive.label(), "DEFINITIVE");
        assert_eq!(BlockState::Released.label(), "RELEASED");
        assert_eq!(BlockState::Cancelled.label(), "CANCELLED");

        assert_eq!(EventState::Tentative.label(), "TENTATIVE");
        assert_eq!(EventState::Confirmed.label(), "CONFIRMED");
        assert_eq!(EventState::InProgress.label(), "IN_PROGRESS");
        assert_eq!(EventState::Completed.label(), "COMPLETED");
        assert_eq!(EventState::Cancelled.label(), "CANCELLED");
    }

    #[test]
    fn from_label_round_trips_every_variant() {
        for s in [
            ReservationState::Confirmed,
            ReservationState::CheckedIn,
            ReservationState::CheckedOut,
            ReservationState::NoShow,
            ReservationState::Cancelled,
        ] {
            assert_eq!(ReservationState::from_label(s.label()), s);
        }
        for s in [FolioState::Open, FolioState::Closed] {
            assert_eq!(FolioState::from_label(s.label()), s);
        }
        for s in [
            BlockState::Provisional,
            BlockState::Definitive,
            BlockState::Released,
            BlockState::Cancelled,
        ] {
            assert_eq!(BlockState::from_label(s.label()), s);
        }
        for s in [
            EventState::Tentative,
            EventState::Confirmed,
            EventState::InProgress,
            EventState::Completed,
            EventState::Cancelled,
        ] {
            assert_eq!(EventState::from_label(s.label()), s);
        }
    }

    // ── Reservation matrix (test-strategy §3.1) ──

    #[test]
    fn reservation_happy_path_confirmed_to_checked_out() {
        use ReservationState::*;
        assert!(Confirmed.can_transition_to(CheckedIn));
        assert!(CheckedIn.can_transition_to(CheckedOut));
    }

    #[test]
    fn reservation_cancellation_rules() {
        use ReservationState::*;
        assert!(Confirmed.can_transition_to(Cancelled));
        // Cancel-in-house is permitted (matches cancel_reservation's
        // `status NOT IN ('CHECKED_OUT','NO_SHOW','CANCELLED')` guard).
        assert!(CheckedIn.can_transition_to(Cancelled));
        // Terminal states cannot be cancelled again.
        assert!(!CheckedOut.can_transition_to(Cancelled));
        assert!(!NoShow.can_transition_to(Cancelled));
        assert!(!Cancelled.can_transition_to(Cancelled));
    }

    #[test]
    fn reservation_no_show_only_from_confirmed() {
        use ReservationState::*;
        assert!(Confirmed.can_transition_to(NoShow));
        assert!(!CheckedIn.can_transition_to(NoShow));
        assert!(!CheckedOut.can_transition_to(NoShow));
    }

    #[test]
    fn reservation_terminal_states_are_dead_ends() {
        use ReservationState::*;
        let all = [Confirmed, CheckedIn, CheckedOut, NoShow, Cancelled];
        for from in [CheckedOut, NoShow, Cancelled] {
            for to in all {
                assert!(!from.can_transition_to(to), "{from:?} → {to:?} must be illegal");
            }
        }
    }

    #[test]
    fn reservation_no_re_check_in_or_re_open() {
        use ReservationState::*;
        assert!(!CheckedOut.can_transition_to(CheckedIn));
        assert!(!Cancelled.can_transition_to(Confirmed));
        assert!(!NoShow.can_transition_to(Confirmed));
    }

    // ── Folio matrix (test-strategy §3.2) ──

    #[test]
    fn folio_only_open_to_closed() {
        assert!(FolioState::Open.can_transition_to(FolioState::Closed));
        assert!(!FolioState::Open.can_transition_to(FolioState::Open));
        assert!(!FolioState::Closed.can_transition_to(FolioState::Open));
        assert!(!FolioState::Closed.can_transition_to(FolioState::Closed));
    }

    // ── Block matrix (test-strategy §3.3) ──

    #[test]
    fn block_matrix_matches_blocks_rs_table() {
        use BlockState::*;
        // The exact table from handlers/blocks.rs::get_block_next_statuses.
        assert!(Provisional.can_transition_to(Definitive));
        assert!(Provisional.can_transition_to(Cancelled));
        assert!(Definitive.can_transition_to(Released));
        assert!(Definitive.can_transition_to(Cancelled));
        // Illegal directions
        assert!(!Provisional.can_transition_to(Released));
        assert!(!Definitive.can_transition_to(Provisional));
        assert!(!Released.can_transition_to(Cancelled));
        assert!(!Released.can_transition_to(Definitive));
        assert!(!Cancelled.can_transition_to(Definitive));
    }

    // ── Event matrix (test-strategy §3.4) ──

    #[test]
    fn event_full_lifecycle() {
        use EventState::*;
        let mut cur = Tentative;
        let happy = [Confirmed, InProgress, Completed];
        for next in happy {
            assert!(cur.can_transition_to(next), "{cur:?} → {next:?}");
            cur = next;
        }
        assert!(!Completed.can_transition_to(Completed));
    }

    #[test]
    fn event_cancellation_windows() {
        use EventState::*;
        // Cancellable until the event goes in progress.
        assert!(Tentative.can_transition_to(Cancelled));
        assert!(Confirmed.can_transition_to(Cancelled));
        // Once underway, it must complete.
        assert!(!InProgress.can_transition_to(Cancelled));
        assert!(!InProgress.can_transition_to(Confirmed));
        assert!(!Completed.can_transition_to(Cancelled));
    }

    #[test]
    fn display_uses_label() {
        assert_eq!(format!("{}", ReservationState::CheckedIn), "CHECKED_IN");
        assert_eq!(format!("{}", EventState::InProgress), "IN_PROGRESS");
    }
}