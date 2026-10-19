# Hotel8:PMS - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Hotel8:PMS **does for the business**. For architecture read `README.md`;
> for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

- Operate the hotel's system of record: rooms, rates, reservations, folios,
  housekeeping, banquet events, night audit.
- Guarantee every hospitality application and channel integration works from
  one consistent, tenant-isolated model rather than per-app copies.
- Drive companion services by emitting reservation and inventory events at
  the moment business facts change.

## 2. Business Scope (What the Service Provides)

| Capability | Description |
|---|---|
| Property setup | Properties, room types, rooms, rate plans, rate schedules, packages, items, lists of values |
| Reservations | Create, modify, cancel, no-show handling, confirmation numbering |
| Front desk | Check-in, check-out, in-house management, check-in reversal, pre-registration |
| Cashiering | Folio lifecycle, charge posting, payment posting, folio generation, disputes |
| Housekeeping | Room-status lifecycle (clean/dirty/inspected/out-of-order), task flows |
| Group blocks | Provisional→definitive blocks with room/type allocation and release |
| Banquet & catering | Function spaces, event booking with resources, event lifecycle |
| Rate & inventory control | Availability search (property and org-wide), sell limits, restriction gates |
| Night audit (EOD) | Atomically roll up folios, reset housekeeping, roll inventory, no-show processing |
| Reporting | Occupancy, revenue, and operations reports for the admin surface |
| Admin console | 14 RFW pages (incl. the kiosk terminal config) + live data/submit endpoints behind every domain page, incl. the shared policy admin triplet |
| Corporate accounts | Credit-approved payment methods (post-pay / bill-to-company), traveler company bindings, SSO-free first-admin provisioning, and company-scoped negotiated availability for eCorpBooking; hotel sales manages all of it on the Corporate admin page |
| Walk-in booking | Express booking from the kiosk terminal - availability-gated, never oversells |
| Guest communications | Confirmation/folio emails via Sentin8:Post |
| Image management | Property/room images via Sentin8:Storage |
| Platform execution | Payment charges (Bill8:Payments), double-entry movements (Bill8:Ledger), module execution hooks |

**What the service does NOT own (business boundary)**

| Concern | Owning service |
|---|---|
| Card/payment capture | Bill8:Payments |
| Double-entry money movement | Bill8:Ledger |
| Channel distribution & ARI | hotel8:distrib |
| Metasearch rate feed | hotel8:meta |
| Guest rewards | hotel8:loyalty |
| Restaurant/retail billing | hotel8:pos |
| Offer creation & pricing nudges | hotel8:upsell |
| Identity & consent | Sentin8:Auth |
| Email transport | Sentin8:Post |

## 3. Business Capabilities

| Area | Business rule |
|---|---|
| Reservations | A reservation is created against available physical inventory; status moves only along the legal lifecycle (confirmed → checked-in → checked-out / no-show / cancelled). |
| Availability | Sellable = physical rooms − out-of-order − out-of-service, capped by the room type's sell limit; restrictions (min/max LOS, advance) gate booking windows. |
| Front desk | A checked-in reservation always has an open folio; check-out closes the folio and frees the room to the housekeeping cycle. |
| Cashiering | Charges and payments append-only while open; closing settles against payments first; disputes never silently adjust revenue. |
| Housekeeping | Room status drives sellability; pickup status is set only on reservation assignment. |
| Blocks | Definitive blocks reserve room-type inventory; release makes rooms sellable again. |
| Events | An event reserves function spaces with resources; lifecycle mirrors reservation discipline. |
| Night audit | EOD is atomic - folios roll, housekeeping resets, inventory rolls, no-shows apply, and the log records one close per property per business day. |
| Guest profiles | Profiles aggregate stays and preferences; VIP tiers carry service expectations; loyalty linkage is delegated to hotel8:loyalty. |

## 4. Business Events (Outbound)

All events are published on the `pms` stream with self-contained payloads.
Representative set (full list mirrored in `DESIGN.md` §4):

| Event | Fires when |
|---|---|
| `hotel8:pms:reservation:created` | A booking is confirmed (triggers upsell offer generation) |
| `hotel8:pms:reservation:checked_in` | Front-desk check-in (triggers POS table preparation) |
| `hotel8:pms:reservation:checked_out` | Check-out with settled folio (triggers loyalty stay-points) |
| `hotel8:pms:inventory:updated` | Room/rate inventory changes (triggers distrib + meta re-sync) |
| `hotel8:pms:folio:charge_posted` / `folio:payment_posted` | Cashiering movements |
| `hotel8:pms:block:created` / `block:status_changed` | Block lifecycle |
| `hotel8:pms:housekeeping:status_changed` | Room-condition changes |
| `hotel8:pms:eod:completed` | Night audit closed |
| `hotel8:pms:notification:sent` / `hotel8:pms:post:email_queued` | Guest communication dispatched |

**Inbound (consumed directly):** none from other hotel8 services today - PMS
is the origin of the reservation/inventory facts the rest of the vertical
reacts to.

## 5. Business Rules & Invariants

1. A reservation never occupies a room without an open folio.
2. Availability never sells more rooms than physical inventory minus
   non-sellable rooms, nor beyond the sell limit.
3. Folio balances equal charges minus payments at all times; closure requires
   a non-negative remaining balance.
4. Every state transition passes the server-side state machine - illegal
   transitions are rejected before persistence.
5. A business fact change and its event are committed atomically - no event
   is ever lost or orphaned.
6. Audit history for every mutation persists even during platform outages.
7. Each property has one EOD closure per business day.
8. A guest never sees another guest's folio or profile - tenant isolation is
   enforced on every read.

## 6. Target-User Roles & Use Cases

| Persona | Use |
|---|---|
| Front-desk agent | Check-in/out, folio adjustments, room moves |
| Housekeeping staff | Room-condition updates, task completion |
| Reservations manager | Booking, rate planning, block management |
| Revenue manager | Rate plans, availability windows, restrictions |
| Night auditor | EOD close, no-show handling, revenue roll-up |
| Banquet coordinator | Function-space events and resources |
| Hotel admin / chain admin | Property settings, reporting, policy admin |
| Platform auditor (read-only) | Journal access via admin surface |

## 7. KPIs / Success Criteria

- Reservation-create p95 well under the ingress budget; availability search
  remains cacheable and index-driven.
- Zero sold-when-unavailable incidents (availability invariant holds).
- Zero lost revenue events: every charge/payment has an audit trail.
- EOD completes inside the maintenance window for the largest property.
- Event delivery to consumers within the relay latency budget; DLQ empty in
  steady state.
- 100% mutation coverage by the audit journal.

## 8. Dependencies & Reliance on Other Services

| Reliance | For |
|---|---|
| Sentin8:Auth | Identity, JWKS, M2M credentials (cert-bound) |
| Shield (embedded) | Every authorization decision |
| Sentin8:Bus | Durable delivery of `pms` family events |
| Sentin8:Sys | Audit ingestion, runtime registry |
| Sentin8:Storage | Property image objects |
| Sentin8:Post | Guest email delivery |
| Sentin8:Func / Flow / Cron | Module hooks, scheduled work |
| Bill8:Payments / Bill8:Ledger | Monetary settlement of room charges (folio account + balances lazily ensured per env; charge idempotency per settlement) |

## 9. Acceptance Criteria

1. A reservation can be created, checked in, charged, paid, and checked out
   entirely through the service without manual intervention.
2. Every state transition not in the documented lifecycle is rejected with a
   client-facing 4xx.
3. Companion services (POS, loyalty, upsell, distrib, meta) react to every
   business fact change without polling PMS.
4. Admin surfaces render and operate for all 14 pages via RFW, with live data
   behind every domain table and working form submission.
5. Night audit completes and produces the operational roll forward.
6. During a Bus or Sys outage the service keeps accepting business traffic
   and no event or audit record is lost.

## 10. Open Business Questions

- Multi-currency folio settlement for international properties.
- Overbooking policy per room class (current protection is per type
  sell-limit only).
- Yield-management pricing beyond restriction gates.

---

**Design attribution:** hotel8:pms and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
