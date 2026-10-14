-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
-- SPDX-License-Identifier: Apache-2.0

-- Hotel8:PMS — Property Management System tables for the hospitality industry.
--
-- This migration creates all tables for the Hotel8:PMS service:
--   packages, guest_profiles, reservations, folios, folio_charges,
--   folio_payments, blocks, events, lov.
--
-- All tables use RLS (Row-Level Security) via the shared
-- sentin8_set_tenant_context() function.

-- ═══════════════════════════════════════════════════════════════════════════
-- Custom enum types
-- ═══════════════════════════════════════════════════════════════════════════

CREATE SCHEMA IF NOT EXISTS pms;
DO $$ BEGIN
    CREATE TYPE pms.fo_status AS ENUM ('VACANT', 'OCCUPIED', 'DUE_OUT', 'DEPARTED', 'STAYOVER');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE pms.hk_status AS ENUM ('CLEAN', 'DIRTY', 'INSPECTED', 'PICKUP', 'OUT_OF_ORDER', 'OUT_OF_SERVICE');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE pms.res_status AS ENUM ('CONFIRMED', 'CHECKED_IN', 'CHECKED_OUT', 'NO_SHOW', 'CANCELLED');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE pms.folio_status AS ENUM ('OPEN', 'CLOSED');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE pms.block_status AS ENUM ('PROVISIONAL', 'DEFINITIVE', 'RELEASED', 'CANCELLED');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE pms.event_status AS ENUM ('TENTATIVE', 'CONFIRMED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE pms.profile_type AS ENUM ('GUEST', 'COMPANY', 'TRAVEL_AGENT', 'GROUP', 'CONTACT');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE pms.vip_status AS ENUM ('NONE', 'BRONZE', 'SILVER', 'GOLD', 'PLATINUM', 'DIAMOND');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ═══════════════════════════════════════════════════════════════════════════
-- Properties
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pms.properties (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id        UUID NOT NULL,
    property_code TEXT NOT NULL,
    property_name TEXT NOT NULL,
    timezone      TEXT NOT NULL DEFAULT 'UTC',
    currency_code TEXT NOT NULL DEFAULT 'USD',
    languages     JSONB NOT NULL DEFAULT '[]',
    address       JSONB,
    phone         TEXT,
    email         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);


CREATE INDEX IF NOT EXISTS idx_pms_properties_env ON pms.properties (env_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_properties_env_code ON pms.properties (env_id, property_code);

-- ═══════════════════════════════════════════════════════════════════════════
-- Room Types
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pms.room_types (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id    UUID NOT NULL REFERENCES pms.properties(id),
    room_type_code TEXT NOT NULL,
    room_type_name TEXT NOT NULL,
    description    TEXT,
    max_occupancy  INTEGER NOT NULL DEFAULT 2,
    bed_type       TEXT,
    is_smoking     BOOLEAN NOT NULL DEFAULT false,
    features       JSONB NOT NULL DEFAULT '[]',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pms_room_types_property ON pms.room_types (property_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_room_types_code ON pms.room_types (property_id, room_type_code);

-- ═══════════════════════════════════════════════════════════════════════════
-- Rooms
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pms.rooms (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id           UUID NOT NULL REFERENCES pms.properties(id),
    room_type_id          UUID NOT NULL REFERENCES pms.room_types(id),
    room_number           TEXT NOT NULL,
    floor                 TEXT,
    building              TEXT,
    front_office_status   pms.fo_status NOT NULL DEFAULT 'VACANT',
    housekeeping_status   pms.hk_status NOT NULL DEFAULT 'DIRTY',
    is_smoking            BOOLEAN NOT NULL DEFAULT false,
    max_occupancy         INTEGER NOT NULL DEFAULT 2,
    bed_type              TEXT,
    features              JSONB NOT NULL DEFAULT '[]',
    current_reservation_id UUID,
    next_reservation_id   UUID,
    last_cleaned_at       TIMESTAMPTZ,
    last_inspected_at     TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pms_rooms_property ON pms.rooms (property_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_rooms_number ON pms.rooms (property_id, room_number);
CREATE INDEX IF NOT EXISTS idx_pms_rooms_fo_status ON pms.rooms (property_id, front_office_status);
CREATE INDEX IF NOT EXISTS idx_pms_rooms_hk_status ON pms.rooms (property_id, housekeeping_status);

-- ═══════════════════════════════════════════════════════════════════════════
-- Rate Plans
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pms.rate_plans (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id         UUID NOT NULL REFERENCES pms.properties(id),
    rate_plan_code      TEXT NOT NULL,
    rate_plan_name      TEXT NOT NULL,
    rate_category       TEXT,
    rate_class          TEXT,
    description         TEXT,
    currency_code       TEXT NOT NULL DEFAULT 'USD',
    market_code         TEXT,
    source_code         TEXT,
    is_active           BOOLEAN NOT NULL DEFAULT true,
    is_negotiated       BOOLEAN NOT NULL DEFAULT false,
    min_los             INTEGER,
    max_los             INTEGER,
    min_advance_booking INTEGER,
    max_advance_booking INTEGER,
    cancellation_policy TEXT,
    deposit_policy      TEXT,
    guarantee_policy    TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pms_rate_plans_property ON pms.rate_plans (property_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_rate_plans_code ON pms.rate_plans (property_id, rate_plan_code);

-- ═══════════════════════════════════════════════════════════════════════════
-- Rate Schedules (daily rates per rate plan × room type)
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pms.rate_schedules (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id          UUID NOT NULL REFERENCES pms.properties(id),
    rate_plan_id         UUID NOT NULL REFERENCES pms.rate_plans(id),
    room_type_id         UUID NOT NULL REFERENCES pms.room_types(id),
    start_date           DATE NOT NULL,
    end_date             DATE NOT NULL,
    days_of_week         JSONB NOT NULL DEFAULT '["MON","TUE","WED","THU","FRI","SAT","SUN"]',
    rate_amount          NUMERIC(12,2) NOT NULL,
    rate_amount_single   NUMERIC(12,2),
    rate_amount_double   NUMERIC(12,2),
    rate_amount_extra_adult NUMERIC(12,2),
    rate_amount_extra_child NUMERIC(12,2),
    package_code         TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pms_rate_schedules_plan ON pms.rate_schedules (rate_plan_id);
CREATE INDEX IF NOT EXISTS idx_pms_rate_schedules_room_type ON pms.rate_schedules (room_type_id);
CREATE INDEX IF NOT EXISTS idx_pms_rate_schedules_dates ON pms.rate_schedules (start_date, end_date);

-- ═══════════════════════════════════════════════════════════════════════════
-- Inventory (daily per room type)
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pms.inventory (
    property_id    UUID NOT NULL REFERENCES pms.properties(id),
    room_type_id   UUID NOT NULL REFERENCES pms.room_types(id),
    date           DATE NOT NULL,
    physical_rooms INTEGER NOT NULL DEFAULT 0,
    sell_limit     INTEGER NOT NULL DEFAULT 0,
    sold_rooms     INTEGER NOT NULL DEFAULT 0,
    out_of_order   INTEGER NOT NULL DEFAULT 0,
    out_of_service INTEGER NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (property_id, room_type_id, date)
);

-- ═══════════════════════════════════════════════════════════════════════════
-- Packages
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pms.packages (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id  UUID NOT NULL REFERENCES pms.properties(id),
    package_code TEXT NOT NULL,
    package_name TEXT NOT NULL,
    quantity     INTEGER NOT NULL DEFAULT 1,
    price        NUMERIC(12,2) NOT NULL DEFAULT 0,
    per_stay     BOOLEAN NOT NULL DEFAULT false,
    is_active    BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pms_packages_property ON pms.packages (property_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_packages_code ON pms.packages (property_id, package_code);

-- ═══════════════════════════════════════════════════════════════════════════
-- Guest Profiles (CRM)
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pms.guest_profiles (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id       UUID NOT NULL REFERENCES pms.properties(id),
    profile_type      pms.profile_type NOT NULL DEFAULT 'GUEST',
    vip_status        pms.vip_status NOT NULL DEFAULT 'NONE',
    first_name        TEXT NOT NULL DEFAULT '',
    last_name         TEXT NOT NULL DEFAULT '',
    email             TEXT,
    phone             TEXT,
    address           TEXT,
    company_name      TEXT,
    loyalty_number    TEXT,
    preferred_language TEXT,
    preferences       JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pms_profiles_property ON pms.guest_profiles (property_id);
CREATE INDEX IF NOT EXISTS idx_pms_profiles_name ON pms.guest_profiles (property_id, last_name, first_name);
CREATE INDEX IF NOT EXISTS idx_pms_profiles_email ON pms.guest_profiles (email) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pms_profiles_loyalty ON pms.guest_profiles (loyalty_number) WHERE loyalty_number IS NOT NULL;

-- ═══════════════════════════════════════════════════════════════════════════
-- Reservations
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pms.reservations (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id        UUID NOT NULL REFERENCES pms.properties(id),
    confirmation_number TEXT NOT NULL,
    guest_profile_id   UUID REFERENCES pms.guest_profiles(id),
    room_type_id       UUID REFERENCES pms.room_types(id),
    rate_plan_id       UUID REFERENCES pms.rate_plans(id),
    arrival_date       DATE NOT NULL,
    departure_date     DATE NOT NULL,
    num_adults         INTEGER NOT NULL DEFAULT 1,
    num_children       INTEGER NOT NULL DEFAULT 0,
    num_rooms          INTEGER NOT NULL DEFAULT 1,
    status             pms.res_status NOT NULL DEFAULT 'CONFIRMED',
    guarantee_type     TEXT NOT NULL DEFAULT 'CCG',
    guarantee_code     TEXT,
    special_requests   TEXT,
    package_code       TEXT,
    market_code        TEXT,
    source_code        TEXT,
    channel_code       TEXT,
    assigned_room_number TEXT,
    checked_in_at      TIMESTAMPTZ,
    checked_out_at     TIMESTAMPTZ,
    cancelled_at       TIMESTAMPTZ,
    no_show_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pms_reservations_property ON pms.reservations (property_id);
CREATE INDEX IF NOT EXISTS idx_pms_reservations_status ON pms.reservations (property_id, status);
CREATE INDEX IF NOT EXISTS idx_pms_reservations_dates ON pms.reservations (arrival_date, departure_date);
CREATE INDEX IF NOT EXISTS idx_pms_reservations_conf ON pms.reservations (confirmation_number);
CREATE INDEX IF NOT EXISTS idx_pms_reservations_profile ON pms.reservations (guest_profile_id) WHERE guest_profile_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_reservations_conf_unique ON pms.reservations (property_id, confirmation_number);

-- ═══════════════════════════════════════════════════════════════════════════
-- Folios
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pms.folios (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id    UUID NOT NULL REFERENCES pms.properties(id),
    reservation_id UUID NOT NULL REFERENCES pms.reservations(id),
    status         pms.folio_status NOT NULL DEFAULT 'OPEN',
    payment_method TEXT,
    closed_at      TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pms_folios_reservation ON pms.folios (reservation_id);
CREATE INDEX IF NOT EXISTS idx_pms_folios_status ON pms.folios (property_id, status);

-- Folio charges
CREATE TABLE IF NOT EXISTS pms.folio_charges (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    folio_id    UUID NOT NULL REFERENCES pms.folios(id),
    charge_code TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    amount      NUMERIC(12,2) NOT NULL DEFAULT 0,
    quantity    INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pms_folio_charges_folio ON pms.folio_charges (folio_id);

-- Folio payments
CREATE TABLE IF NOT EXISTS pms.folio_payments (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    folio_id     UUID NOT NULL REFERENCES pms.folios(id),
    payment_code TEXT NOT NULL,
    amount       NUMERIC(12,2) NOT NULL DEFAULT 0,
    reference    TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pms_folio_payments_folio ON pms.folio_payments (folio_id);

-- ═══════════════════════════════════════════════════════════════════════════
-- Blocks (Allotments)
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pms.blocks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id     UUID NOT NULL REFERENCES pms.properties(id),
    block_code      TEXT NOT NULL,
    block_name      TEXT NOT NULL DEFAULT '',
    room_type_id    UUID REFERENCES pms.room_types(id),
    start_date      DATE NOT NULL,
    end_date        DATE NOT NULL,
    blocked_rooms   INTEGER NOT NULL DEFAULT 0,
    picked_up       INTEGER NOT NULL DEFAULT 0,
    released_until  TEXT NOT NULL DEFAULT '0',
    status          pms.block_status NOT NULL DEFAULT 'PROVISIONAL',
    block_type      TEXT NOT NULL DEFAULT 'ALLOTMENT',
    negotiated_rate NUMERIC(12,2),
    cutoff_date     DATE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pms_blocks_property ON pms.blocks (property_id);
CREATE INDEX IF NOT EXISTS idx_pms_blocks_dates ON pms.blocks (start_date, end_date);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_blocks_code ON pms.blocks (property_id, block_code);

-- ═══════════════════════════════════════════════════════════════════════════
-- Events
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pms.events (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id        UUID NOT NULL REFERENCES pms.properties(id),
    event_code         TEXT NOT NULL,
    event_name         TEXT NOT NULL DEFAULT '',
    event_type         TEXT NOT NULL DEFAULT 'MEETING',
    start_date         DATE NOT NULL,
    end_date           DATE NOT NULL,
    status             pms.event_status NOT NULL DEFAULT 'TENTATIVE',
    expected_attendees INTEGER NOT NULL DEFAULT 0,
    banquet_order      TEXT,
    contact_name       TEXT,
    contact_phone      TEXT,
    notes              TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pms_events_property ON pms.events (property_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_events_code ON pms.events (property_id, event_code);

-- ═══════════════════════════════════════════════════════════════════════════
-- List of Values (LOV) — reference data per property
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pms.lov (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id UUID NOT NULL REFERENCES pms.properties(id),
    lov_type    TEXT NOT NULL,
    lov_code    TEXT NOT NULL,
    lov_value   TEXT NOT NULL,
    is_active   BOOLEAN NOT NULL DEFAULT true,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pms_lov_property ON pms.lov (property_id);
CREATE INDEX IF NOT EXISTS idx_pms_lov_type ON pms.lov (property_id, lov_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_lov_code ON pms.lov (property_id, lov_type, lov_code);

-- ═══════════════════════════════════════════════════════════════════════════
-- RLS Policies — enable RLS on all Hotel8:PMS tables
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE pms.properties ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.properties FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.room_types ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.room_types FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.rooms ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.rooms FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.rate_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.rate_plans FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.rate_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.rate_schedules FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.inventory FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.packages FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.guest_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.guest_profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.reservations FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.folios ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.folios FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.folio_charges ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.folio_charges FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.folio_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.folio_payments FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.blocks FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.events FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.lov ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.lov FORCE ROW LEVEL SECURITY;

-- Standard RLS policy: env_id matches tenant context.
-- env_id is the sole tenant key (architecture-principles.md §4.3).
DROP POLICY IF EXISTS pms_properties_rls ON pms.properties;
CREATE POLICY pms_properties_rls ON pms.properties
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

DROP POLICY IF EXISTS pms_room_types_rls ON pms.room_types;
CREATE POLICY pms_room_types_rls ON pms.room_types
    USING (property_id IN (SELECT id FROM pms.properties));

DROP POLICY IF EXISTS pms_rooms_rls ON pms.rooms;
CREATE POLICY pms_rooms_rls ON pms.rooms
    USING (property_id IN (SELECT id FROM pms.properties));

DROP POLICY IF EXISTS pms_rate_plans_rls ON pms.rate_plans;
CREATE POLICY pms_rate_plans_rls ON pms.rate_plans
    USING (property_id IN (SELECT id FROM pms.properties));

DROP POLICY IF EXISTS pms_rate_schedules_rls ON pms.rate_schedules;
CREATE POLICY pms_rate_schedules_rls ON pms.rate_schedules
    USING (property_id IN (SELECT id FROM pms.properties));

DROP POLICY IF EXISTS pms_inventory_rls ON pms.inventory;
CREATE POLICY pms_inventory_rls ON pms.inventory
    USING (property_id IN (SELECT id FROM pms.properties));

DROP POLICY IF EXISTS pms_packages_rls ON pms.packages;
CREATE POLICY pms_packages_rls ON pms.packages
    USING (property_id IN (SELECT id FROM pms.properties));

DROP POLICY IF EXISTS pms_guest_profiles_rls ON pms.guest_profiles;
CREATE POLICY pms_guest_profiles_rls ON pms.guest_profiles
    USING (property_id IN (SELECT id FROM pms.properties));

DROP POLICY IF EXISTS pms_reservations_rls ON pms.reservations;
CREATE POLICY pms_reservations_rls ON pms.reservations
    USING (property_id IN (SELECT id FROM pms.properties));

DROP POLICY IF EXISTS pms_folios_rls ON pms.folios;
CREATE POLICY pms_folios_rls ON pms.folios
    USING (property_id IN (SELECT id FROM pms.properties));

DROP POLICY IF EXISTS pms_folio_charges_rls ON pms.folio_charges;
CREATE POLICY pms_folio_charges_rls ON pms.folio_charges
    USING (folio_id IN (SELECT id FROM pms.folios));

DROP POLICY IF EXISTS pms_folio_payments_rls ON pms.folio_payments;
CREATE POLICY pms_folio_payments_rls ON pms.folio_payments
    USING (folio_id IN (SELECT id FROM pms.folios));

DROP POLICY IF EXISTS pms_blocks_rls ON pms.blocks;
CREATE POLICY pms_blocks_rls ON pms.blocks
    USING (property_id IN (SELECT id FROM pms.properties));

DROP POLICY IF EXISTS pms_events_rls ON pms.events;
CREATE POLICY pms_events_rls ON pms.events
    USING (property_id IN (SELECT id FROM pms.properties));

DROP POLICY IF EXISTS pms_lov_rls ON pms.lov;
CREATE POLICY pms_lov_rls ON pms.lov
    USING (property_id IN (SELECT id FROM pms.properties));
-- ──────────────────────────────────────────────────────────────────────────
-- Local outbox (DBX, architecture-principles §6.7) — producer path:
-- rows are appended in the SAME transaction as the domain change; the
-- shell's post-commit relay pushes them to Bus POST /v1/produce
-- (M2M sentin8:bus:produce, idempotency_key = row id).
-- Generated from sentin8_outbox::outbox_table_sql("pms").
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pms.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_outbox_unrelayed
    ON pms.outbox (created_at) WHERE relayed = false;
ALTER TABLE pms.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON pms.outbox;
CREATE POLICY outbox_select ON pms.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON pms.outbox;
CREATE POLICY outbox_insert ON pms.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON pms.outbox;
CREATE POLICY outbox_update ON pms.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION pms.pms_notify_outbox() RETURNS TRIGGER
    LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('pms_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON pms.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON pms.outbox
    FOR EACH ROW
    EXECUTE FUNCTION pms.pms_notify_outbox();

-- ──────────────────────────────────────────────────────────────────────────
-- Local audit journal (architecture-principles §6.8): same-transaction
-- journal rows; the shell's post-commit pusher ships them to Sys
-- POST /v1/audit (M2M sentin8:sys:audit:write). A Sys outage only delays
-- delivery — rows persist until pushed.
-- Generated from sentin8_audit::audit_journal_sql("pms").
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pms.audit_journal (
    id              UUID PRIMARY KEY,
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pms_audit_journal_unpushed
    ON pms.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE pms.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON pms.audit_journal;
CREATE POLICY audit_journal_dml ON pms.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- ──────────────────────────────────────────────────────────────────────────
-- Per-service role grants + search_path (§4.3e / VDC §VDC.3):
-- hotel8_{leaf}_service connects via PostgreSQL 18 OAuth (scope→role map in
-- hotel8.sys.pg_oauth_scope_map). search_path puts the service's OWN schema
-- FIRST (outbox/audit_journal resolution for the shell's relay + journal
-- pusher; unqualified domain tables resolve here), then public (RLS helpers).
-- `sentin8-cli vertical enroll`'s never-clobber block preserves this role-level setting.
-- ──────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hotel8_pms_service') THEN
        ALTER ROLE hotel8_pms_service SET search_path = pms, public;
        GRANT USAGE ON SCHEMA pms TO hotel8_pms_service;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA pms TO hotel8_pms_service;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA pms TO hotel8_pms_service;
    END IF;
END $$;


-- ═════════════════════════════════════════════════════════════════════════════
-- From migrations: extended
-- ═══════════════════════════════════════════════════════════════════════════
-- Hotel8:PMS additional tables for Phase H0 remaining stories.
-- Covers: housekeeping tasks, function spaces, event resources,
-- transaction codes, gift vouchers, async jobs, reservation messages,
-- service requests, preferences, EOD log.

-- Housekeeping Tasks (H0.10.3)
CREATE SCHEMA IF NOT EXISTS pms;
CREATE TABLE IF NOT EXISTS pms.hk_tasks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id     UUID NOT NULL REFERENCES pms.properties(id),
    room_number     TEXT,
    task_type       TEXT NOT NULL DEFAULT 'CLEAN',
    status          TEXT NOT NULL DEFAULT 'OPEN',
    priority        TEXT NOT NULL DEFAULT 'NORMAL',
    assigned_to     TEXT,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pms_hkt_property ON pms.hk_tasks (property_id);
CREATE INDEX IF NOT EXISTS idx_pms_hkt_status ON pms.hk_tasks (property_id, status);

-- Function Spaces (H0.12.7)
CREATE TABLE IF NOT EXISTS pms.function_spaces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id     UUID NOT NULL REFERENCES pms.properties(id),
    space_code      TEXT NOT NULL,
    space_name      TEXT NOT NULL,
    capacity        INTEGER NOT NULL DEFAULT 0,
    setup_styles    JSONB NOT NULL DEFAULT '[]',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pms_fs_property ON pms.function_spaces (property_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_fs_code ON pms.function_spaces (property_id, space_code);

-- Event Resources (H0.12.8)
CREATE TABLE IF NOT EXISTS pms.event_resources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        UUID NOT NULL REFERENCES pms.events(id),
    resource_type   TEXT NOT NULL,
    resource_name   TEXT NOT NULL,
    quantity        INTEGER NOT NULL DEFAULT 1,
    cost            NUMERIC(12,2) NOT NULL DEFAULT 0,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pms_er_event ON pms.event_resources (event_id);

-- Transaction Codes (H0.11.8)
CREATE TABLE IF NOT EXISTS pms.transaction_codes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id     UUID NOT NULL REFERENCES pms.properties(id),
    code            TEXT NOT NULL,
    description     TEXT NOT NULL,
    category        TEXT NOT NULL DEFAULT 'ROOM',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    sort_order      INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pms_tc_property ON pms.transaction_codes (property_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_tc_code ON pms.transaction_codes (property_id, code);

-- Gift Vouchers (H0.11.9)
CREATE TABLE IF NOT EXISTS pms.gift_vouchers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id     UUID NOT NULL REFERENCES pms.properties(id),
    voucher_number  TEXT NOT NULL,
    balance         NUMERIC(12,2) NOT NULL DEFAULT 0,
    currency_code   TEXT NOT NULL DEFAULT 'USD',
    status          TEXT NOT NULL DEFAULT 'ACTIVE',
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pms_gv_property ON pms.gift_vouchers (property_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_gv_number ON pms.gift_vouchers (property_id, voucher_number);

-- Async Jobs (H0.15.1)
CREATE TABLE IF NOT EXISTS pms.async_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id     UUID NOT NULL REFERENCES pms.properties(id),
    module          TEXT NOT NULL,
    operation       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'IN_PROGRESS',
    result          JSONB,
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pms_aj_property ON pms.async_jobs (property_id);
CREATE INDEX IF NOT EXISTS idx_pms_aj_status ON pms.async_jobs (status);

-- Reservation Messages (H0.9.5)
CREATE TABLE IF NOT EXISTS pms.reservation_messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reservation_id  UUID NOT NULL REFERENCES pms.reservations(id),
    direction       TEXT NOT NULL DEFAULT 'INBOUND',
    message_type    TEXT NOT NULL DEFAULT 'MESSAGE',
    content         TEXT NOT NULL,
    sender          TEXT,
    is_read         BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pms_rm_res ON pms.reservation_messages (reservation_id);

-- Service Requests (H0.9.6)
CREATE TABLE IF NOT EXISTS pms.service_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reservation_id  UUID NOT NULL REFERENCES pms.reservations(id),
    request_type    TEXT NOT NULL DEFAULT 'HOUSEKEEPING',
    description     TEXT,
    status          TEXT NOT NULL DEFAULT 'OPEN',
    assigned_to     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pms_sr_res ON pms.service_requests (reservation_id);
CREATE INDEX IF NOT EXISTS idx_pms_sr_status ON pms.service_requests (status);

-- Guest Preferences (H0.7.4)
CREATE TABLE IF NOT EXISTS pms.guest_preferences (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id      UUID NOT NULL REFERENCES pms.guest_profiles(id),
    preference_type TEXT NOT NULL,
    preference_code TEXT NOT NULL,
    preference_value TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pms_gp_profile ON pms.guest_preferences (profile_id);

-- EOD Log (H0.13.1)
CREATE TABLE IF NOT EXISTS pms.eod_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id     UUID NOT NULL REFERENCES pms.properties(id),
    business_date   DATE NOT NULL,
    status          TEXT NOT NULL DEFAULT 'IN_PROGRESS',
    step            TEXT,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    report_data     JSONB
);
CREATE INDEX IF NOT EXISTS idx_pms_eod_property ON pms.eod_log (property_id, business_date);

-- Reservation Comments (H0.8.6)
CREATE TABLE IF NOT EXISTS pms.reservation_comments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reservation_id  UUID NOT NULL REFERENCES pms.reservations(id),
    comment_type    TEXT NOT NULL DEFAULT 'GENERAL',
    content         TEXT NOT NULL,
    author          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pms_rc_res ON pms.reservation_comments (reservation_id);

-- RLS for all new tables
ALTER TABLE pms.hk_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.hk_tasks FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.function_spaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.function_spaces FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.event_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.event_resources FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.transaction_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.transaction_codes FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.gift_vouchers ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.gift_vouchers FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.async_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.async_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.reservation_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.reservation_messages FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.service_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.service_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.guest_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.guest_preferences FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.eod_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.eod_log FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.reservation_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.reservation_comments FORCE ROW LEVEL SECURITY;

CREATE POLICY pms_hkt_rls ON pms.hk_tasks USING (property_id IN (SELECT id FROM pms.properties));
CREATE POLICY pms_fs_rls ON pms.function_spaces USING (property_id IN (SELECT id FROM pms.properties));
CREATE POLICY pms_er_rls ON pms.event_resources USING (event_id IN (SELECT id FROM pms.events));
CREATE POLICY pms_tc_rls ON pms.transaction_codes USING (property_id IN (SELECT id FROM pms.properties));
CREATE POLICY pms_gv_rls ON pms.gift_vouchers USING (property_id IN (SELECT id FROM pms.properties));
CREATE POLICY pms_aj_rls ON pms.async_jobs USING (property_id IN (SELECT id FROM pms.properties));
CREATE POLICY pms_rm_rls ON pms.reservation_messages USING (reservation_id IN (SELECT id FROM pms.reservations));
CREATE POLICY pms_sr_rls ON pms.service_requests USING (reservation_id IN (SELECT id FROM pms.reservations));
CREATE POLICY pms_gp_rls ON pms.guest_preferences USING (profile_id IN (SELECT id FROM pms.guest_profiles));
CREATE POLICY pms_eod_rls ON pms.eod_log USING (property_id IN (SELECT id FROM pms.properties));
CREATE POLICY pms_rc_rls ON pms.reservation_comments USING (reservation_id IN (SELECT id FROM pms.reservations));


-- ═════════════════════════════════════════════════════════════════════════════
-- From migrations: async-input
-- ═══════════════════════════════════════════════════════════════════════════
-- Migration 31: Hotel8:PMS async jobs input_data column (H0.15.4)
CREATE SCHEMA IF NOT EXISTS pms;
ALTER TABLE pms.async_jobs ADD COLUMN IF NOT EXISTS input_data JSONB;


-- ═════════════════════════════════════════════════════════════════════════════
-- From migrations: items
-- ═══════════════════════════════════════════════════════════════════════════
-- Migration 30: Hotel8:PMS Item Inventory (H0.4.8)
-- Non-room sellable items: amenity kits, minibar items, parking passes, etc.

CREATE SCHEMA IF NOT EXISTS pms;
CREATE TABLE IF NOT EXISTS pms.items (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    property_id     UUID NOT NULL REFERENCES pms.properties(id),
    item_code       TEXT NOT NULL,
    item_name       TEXT NOT NULL,
    category        TEXT NOT NULL DEFAULT 'GENERAL',
    unit_price      NUMERIC(12,2) NOT NULL DEFAULT 0,
    unit_cost       NUMERIC(12,2) NOT NULL DEFAULT 0,
    stock_qty       INTEGER NOT NULL DEFAULT 0,
    reorder_point   INTEGER NOT NULL DEFAULT 0,
    is_sellable     BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_items_code
    ON pms.items (property_id, item_code);
CREATE INDEX IF NOT EXISTS idx_pms_items_property
    ON pms.items (property_id);

ALTER TABLE pms.items ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.items FORCE ROW LEVEL SECURITY;
CREATE POLICY pms_items_rls ON pms.items
    USING (property_id IN (SELECT id FROM pms.properties));


-- ═════════════════════════════════════════════════════════════════════════════
-- From migrations: lov-seed
-- ═══════════════════════════════════════════════════════════════════════════
-- Hotel8:PMS LOV seed data — standard reference values for all properties.
-- This provides a base set of LOV entries that properties can customize.
-- Each property should have these seeded when created. For now, we insert
-- a template set with property_id = NULL meaning "system defaults".
-- Property-specific copies are created on property creation.

-- We insert into a separate table for system-level defaults:
CREATE SCHEMA IF NOT EXISTS pms;
CREATE TABLE IF NOT EXISTS pms.lov_defaults (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    lov_type    TEXT NOT NULL,
    lov_code    TEXT NOT NULL,
    lov_value   TEXT NOT NULL,
    sort_order  INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_pms_lovd_type_code ON pms.lov_defaults (lov_type, lov_code);

-- Room types
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('ROOM_TYPE', 'STD', 'Standard Room', 1),
('ROOM_TYPE', 'DLX', 'Deluxe Room', 2),
('ROOM_TYPE', 'EXE', 'Executive Room', 3),
('ROOM_TYPE', 'STE', 'Suite', 4),
('ROOM_TYPE', 'JSU', 'Junior Suite', 5),
('ROOM_TYPE', 'PRS', 'Presidential Suite', 6),
('ROOM_TYPE', 'FAM', 'Family Room', 7),
('ROOM_TYPE', 'ACC', 'Accessible Room', 8)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Rate categories
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('RATE_CATEGORY', 'RACK', 'Rack Rate', 1),
('RATE_CATEGORY', 'CORP', 'Corporate', 2),
('RATE_CATEGORY', 'GRP', 'Group', 3),
('RATE_CATEGORY', 'PKG', 'Package', 4),
('RATE_CATEGORY', 'PROMO', 'Promotional', 5),
('RATE_CATEGORY', 'GOV', 'Government', 6),
('RATE_CATEGORY', 'AAA', 'AAA/CAA', 7),
('RATE_CATEGORY', 'SENIOR', 'Senior', 8)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Market codes
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('MARKET_CODE', 'TRANSIENT', 'Transient', 1),
('MARKET_CODE', 'CORP', 'Corporate', 2),
('MARKET_CODE', 'GROUP', 'Group', 3),
('MARKET_CODE', 'LEISURE', 'Leisure', 4),
('MARKET_CODE', 'CONVENTION', 'Convention', 5),
('MARKET_CODE', 'GOV', 'Government', 6),
('MARKET_CODE', 'AIRLINE', 'Airline Crew', 7),
('MARKET_CODE', 'PKG', 'Package', 8)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Source codes
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('SOURCE_CODE', 'DIRECT', 'Direct Booking', 1),
('SOURCE_CODE', 'OTA', 'Online Travel Agent', 2),
('SOURCE_CODE', 'GDS', 'Global Distribution System', 3),
('SOURCE_CODE', 'PHONE', 'Phone Reservation', 4),
('SOURCE_CODE', 'WALKIN', 'Walk-in', 5),
('SOURCE_CODE', 'CORP', 'Corporate', 6),
('SOURCE_CODE', 'GROUP', 'Group Block', 7),
('SOURCE_CODE', 'META', 'Metasearch', 8)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Payment methods
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('PAYMENT_METHOD', 'CASH', 'Cash', 1),
('PAYMENT_METHOD', 'CC', 'Credit Card', 2),
('PAYMENT_METHOD', 'DC', 'Debit Card', 3),
('PAYMENT_METHOD', 'GC', 'Gift Card/Voucher', 4),
('PAYMENT_METHOD', 'ROOM', 'Room Charge', 5),
('PAYMENT_METHOD', 'COMP', 'Complimentary', 6),
('PAYMENT_METHOD', 'AR', 'Accounts Receivable', 7),
('PAYMENT_METHOD', 'MOBILE', 'Mobile Wallet', 8)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Guarantee policies
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('GUARANTEE_POLICY', 'CCG', 'Credit Card Guarantee', 1),
('GUARANTEE_POLICY', '6PM', '6PM Hold', 2),
('GUARANTEE_POLICY', '4PM', '4PM Hold', 3),
('GUARANTEE_POLICY', 'DEP', 'Deposit Required', 4),
('GUARANTEE_POLICY', 'NONE', 'No Guarantee', 5)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Cancellation policies
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('CANCEL_POLICY', 'FLEX', 'Flexible — free cancellation', 1),
('CANCEL_POLICY', 'MOD', 'Moderate — 24hr before arrival', 2),
('CANCEL_POLICY', 'STRICT', 'Strict — 72hr before arrival', 3),
('CANCEL_POLICY', 'NONREF', 'Non-refundable', 4),
('CANCEL_POLICY', 'CUSTOM', 'Custom policy', 5)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Transaction codes
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('TRANSACTION_CODE', 'ROOM', 'Room Charge', 1),
('TRANSACTION_CODE', 'ROOM_TAX', 'Room Tax', 2),
('TRANSACTION_CODE', 'ROOM_TAX2', 'Occupancy Tax', 3),
('TRANSACTION_CODE', 'PHONE', 'Telephone', 4),
('TRANSACTION_CODE', 'MINIBAR', 'Mini Bar', 5),
('TRANSACTION_CODE', 'RESTAURANT', 'Restaurant', 6),
('TRANSACTION_CODE', 'BAR', 'Bar', 7),
('TRANSACTION_CODE', 'SPA', 'Spa Services', 8),
('TRANSACTION_CODE', 'LAUNDRY', 'Laundry', 9),
('TRANSACTION_CODE', 'PARKING', 'Parking', 10),
('TRANSACTION_CODE', 'BUS_CTR', 'Business Center', 11),
('TRANSACTION_CODE', 'DEPOSIT', 'Deposit', 12),
('TRANSACTION_CODE', 'ADV_DEP', 'Advance Deposit', 13),
('TRANSACTION_CODE', 'ADJUST', 'Adjustment', 14),
('TRANSACTION_CODE', 'REBATE', 'Rebate', 15),
('TRANSACTION_CODE', 'CASH', 'Cash Payment', 16),
('TRANSACTION_CODE', 'CC', 'Credit Card Payment', 17),
('TRANSACTION_CODE', 'AR', 'Accounts Receivable', 18)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Block types
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('BLOCK_TYPE', 'ALLOTMENT', 'Allotment Block', 1),
('BLOCK_TYPE', 'CONTRACT', 'Contract Block', 2),
('BLOCK_TYPE', 'SERIES', 'Series Block', 3),
('BLOCK_TYPE', 'DECISION', 'Decision Block', 4)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Block statuses
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('BLOCK_STATUS', 'PROVISIONAL', 'Provisional', 1),
('BLOCK_STATUS', 'DEFINITIVE', 'Definitive', 2),
('BLOCK_STATUS', 'RELEASED', 'Released', 3),
('BLOCK_STATUS', 'CANCELLED', 'Cancelled', 4)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Event types
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('EVENT_TYPE', 'MEETING', 'Meeting', 1),
('EVENT_TYPE', 'BANQUET', 'Banquet', 2),
('EVENT_TYPE', 'CONF', 'Conference', 3),
('EVENT_TYPE', 'WEDDING', 'Wedding', 4),
('EVENT_TYPE', 'RECEPTION', 'Reception', 5),
('EVENT_TYPE', 'GALA', 'Gala', 6),
('EVENT_TYPE', 'TRAINING', 'Training', 7),
('EVENT_TYPE', 'EXPO', 'Exhibition', 8)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Event statuses
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('EVENT_STATUS', 'TENTATIVE', 'Tentative', 1),
('EVENT_STATUS', 'CONFIRMED', 'Confirmed', 2),
('EVENT_STATUS', 'IN_PROGRESS', 'In Progress', 3),
('EVENT_STATUS', 'COMPLETED', 'Completed', 4),
('EVENT_STATUS', 'CANCELLED', 'Cancelled', 5)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Setup styles
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('SETUP_STYLE', 'THEATER', 'Theater', 1),
('SETUP_STYLE', 'CLASSROOM', 'Classroom', 2),
('SETUP_STYLE', 'BANQUET', 'Banquet Rounds', 3),
('SETUP_STYLE', 'RECEPTION', 'Reception', 4),
('SETUP_STYLE', 'U_SHAPE', 'U-Shape', 5),
('SETUP_STYLE', 'BOARDROOM', 'Boardroom', 6),
('SETUP_STYLE', 'HOLLOW', 'Hollow Square', 7),
('SETUP_STYLE', 'TURNS', 'Cocktail', 8)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Titles
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('TITLE', 'MR', 'Mr.', 1),
('TITLE', 'MRS', 'Mrs.', 2),
('TITLE', 'MS', 'Ms.', 3),
('TITLE', 'DR', 'Dr.', 4),
('TITLE', 'PROF', 'Prof.', 5),
('TITLE', 'REV', 'Rev.', 6),
('TITLE', 'HON', 'Hon.', 7)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Languages
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('LANGUAGE', 'EN', 'English', 1),
('LANGUAGE', 'FR', 'French', 2),
('LANGUAGE', 'ES', 'Spanish', 3),
('LANGUAGE', 'DE', 'German', 4),
('LANGUAGE', 'IT', 'Italian', 5),
('LANGUAGE', 'PT', 'Portuguese', 6),
('LANGUAGE', 'ZH', 'Chinese', 7),
('LANGUAGE', 'JA', 'Japanese', 8),
('LANGUAGE', 'KO', 'Korean', 9),
('LANGUAGE', 'AR', 'Arabic', 10)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Currencies
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('CURRENCY', 'USD', 'US Dollar', 1),
('CURRENCY', 'EUR', 'Euro', 2),
('CURRENCY', 'GBP', 'British Pound', 3),
('CURRENCY', 'CAD', 'Canadian Dollar', 4),
('CURRENCY', 'AUD', 'Australian Dollar', 5),
('CURRENCY', 'JPY', 'Japanese Yen', 6),
('CURRENCY', 'CHF', 'Swiss Franc', 7),
('CURRENCY', 'CNY', 'Chinese Yuan', 8),
('CURRENCY', 'AED', 'UAE Dirham', 9)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Countries
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('COUNTRY', 'US', 'United States', 1),
('COUNTRY', 'CA', 'Canada', 2),
('COUNTRY', 'GB', 'United Kingdom', 3),
('COUNTRY', 'FR', 'France', 4),
('COUNTRY', 'DE', 'Germany', 5),
('COUNTRY', 'ES', 'Spain', 6),
('COUNTRY', 'IT', 'Italy', 7),
('COUNTRY', 'JP', 'Japan', 8),
('COUNTRY', 'CN', 'China', 9),
('COUNTRY', 'AU', 'Australia', 10),
('COUNTRY', 'AE', 'United Arab Emirates', 11),
('COUNTRY', 'MX', 'Mexico', 12)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- Profile types
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('PROFILE_TYPE', 'GUEST', 'Guest', 1),
('PROFILE_TYPE', 'COMPANY', 'Company', 2),
('PROFILE_TYPE', 'TRAVEL_AGENT', 'Travel Agent', 3),
('PROFILE_TYPE', 'GROUP', 'Group', 4),
('PROFILE_TYPE', 'CONTACT', 'Contact', 5),
('PROFILE_TYPE', 'SOURCE', 'Source', 6)
ON CONFLICT (lov_type, lov_code) DO NOTHING;

-- VIP statuses
INSERT INTO pms.lov_defaults (lov_type, lov_code, lov_value, sort_order) VALUES
('VIP_STATUS', 'NONE', 'None', 1),
('VIP_STATUS', 'BRONZE', 'Bronze', 2),
('VIP_STATUS', 'SILVER', 'Silver', 3),
('VIP_STATUS', 'GOLD', 'Gold', 4),
('VIP_STATUS', 'PLATINUM', 'Platinum', 5),
('VIP_STATUS', 'DIAMOND', 'Diamond', 6)
ON CONFLICT (lov_type, lov_code) DO NOTHING;


-- ═════════════════════════════════════════════════════════════════════════════
-- From migrations: guest-surfaces
-- ═══════════════════════════════════════════════════════════════════════════
-- Guest-app surfaces for Hotel8 apps (pms DESIGN.md §3 "Guest-app surfaces").

CREATE SCHEMA IF NOT EXISTS pms;

-- Digital keys — the physical/mobile key records the kiosk and eGuest issue
-- and manage. One reservation can hold several keys (guest count).
CREATE TABLE IF NOT EXISTS pms.digital_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    property_id     UUID NOT NULL REFERENCES pms.properties(id),
    reservation_id  UUID NOT NULL REFERENCES pms.reservations(id),
    room_number     TEXT,
    key_type        TEXT NOT NULL DEFAULT 'PHYSICAL',
    status          TEXT NOT NULL DEFAULT 'INACTIVE',
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    issued_count    INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pms_dk_property ON pms.digital_keys (property_id);
CREATE INDEX IF NOT EXISTS idx_pms_dk_res ON pms.digital_keys (reservation_id);

-- Stay feedback — one rating row per reservation (re-rating updates).
CREATE TABLE IF NOT EXISTS pms.feedback (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    property_id     UUID NOT NULL REFERENCES pms.properties(id),
    reservation_id  UUID NOT NULL REFERENCES pms.reservations(id),
    rating          INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment         TEXT,
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (reservation_id)
);
CREATE INDEX IF NOT EXISTS idx_pms_feedback_property ON pms.feedback (property_id);

ALTER TABLE pms.digital_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.digital_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.feedback FORCE ROW LEVEL SECURITY;

CREATE POLICY pms_dk_rls ON pms.digital_keys USING (property_id IN (SELECT id FROM pms.properties));
CREATE POLICY pms_fb_rls ON pms.feedback USING (property_id IN (SELECT id FROM pms.properties));


-- ═════════════════════════════════════════════════════════════════════════════
-- From migrations: corporate-kiosk
-- ═══════════════════════════════════════════════════════════════════════════
-- Staff, corporate, and kiosk surfaces for Hotel8:PMS (pms DESIGN.md §3
-- "Staff & corporate surfaces"): kiosk terminal config, corporate credit
-- methods, and company user bindings.

CREATE SCHEMA IF NOT EXISTS pms;

-- ── Kiosk terminal configuration — one row per property ─────────────────────
-- eKiosk reads this at bootstrap to gate its mode menu; the admin RFW
-- settings page edits it. Lockdown freezes the terminal at the attract loop.
CREATE TABLE IF NOT EXISTS pms.kiosk_config (
    property_id     UUID PRIMARY KEY REFERENCES pms.properties(id),
    env_id          UUID NOT NULL,
    enabled_modes   TEXT[] NOT NULL DEFAULT '{CHECK_IN,CHECK_OUT,COLLECT_KEY}',
    addon_package_codes TEXT[] NOT NULL DEFAULT '{}',
    max_keys_per_stay INTEGER NOT NULL DEFAULT 4,
    lockdown        BOOLEAN NOT NULL DEFAULT false,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pms_kiosk_cfg_env ON pms.kiosk_config (env_id);

-- ── Corporate payment methods (credit approval surface) ─────────────────────
-- eCorpBooking checkout surfaces POSTPAY/BILL_TO_COMPANY rows; hotel sales
-- (admin) manage the approval workflow. bill8 owns the actual token — PMS
-- stores the reference only, never PAN or token secrets (DESIGN.md §3).
CREATE TABLE IF NOT EXISTS pms.company_payment_methods (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    property_id     UUID NOT NULL REFERENCES pms.properties(id),
    company_profile_id UUID NOT NULL REFERENCES pms.guest_profiles(id),
    label           TEXT NOT NULL,
    payment_method_id TEXT,                    -- bill8 token reference (by-value, never a secret)
    approval        TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (approval IN ('PENDING','POSTPAY','BILL_TO_COMPANY','REJECTED')),
    credit_limit    NUMERIC(12,2),
    approved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (company_profile_id, label)
);
CREATE INDEX IF NOT EXISTS idx_pms_cpm_company ON pms.company_payment_methods (company_profile_id);
CREATE INDEX IF NOT EXISTS idx_pms_cpm_property ON pms.company_payment_methods (property_id);

-- ── Company user bindings (multi-company travelers) ──────────────────────────
-- One traveler can belong to many companies; each binding names the role the
-- traveler holds at that company. Sessions bind ONE active company per call.
CREATE TABLE IF NOT EXISTS pms.company_users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    property_id     UUID NOT NULL REFERENCES pms.properties(id),
    company_profile_id UUID NOT NULL REFERENCES pms.guest_profiles(id),
    traveler_profile_id UUID NOT NULL REFERENCES pms.guest_profiles(id),
    role_at_company TEXT NOT NULL DEFAULT 'TRAVELER'
                    CHECK (role_at_company IN ('ADMIN','BOOKING_AGENT','TRAVELER')),
    is_default      BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (company_profile_id, traveler_profile_id)
);
CREATE INDEX IF NOT EXISTS idx_pms_cu_company ON pms.company_users (company_profile_id);
CREATE INDEX IF NOT EXISTS idx_pms_cu_traveler ON pms.company_users (traveler_profile_id);

ALTER TABLE pms.kiosk_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.kiosk_config FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.company_payment_methods ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.company_payment_methods FORCE ROW LEVEL SECURITY;
ALTER TABLE pms.company_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.company_users FORCE ROW LEVEL SECURITY;

CREATE POLICY pms_kiosk_cfg_rls ON pms.kiosk_config USING (property_id IN (SELECT id FROM pms.properties));
CREATE POLICY pms_cpm_rls ON pms.company_payment_methods USING (property_id IN (SELECT id FROM pms.properties));
CREATE POLICY pms_cu_rls ON pms.company_users USING (property_id IN (SELECT id FROM pms.properties));

-- ═════════════════════════════════════════════════════════════════════════════
-- From migrations: guest-payment-methods
-- ═══════════════════════════════════════════════════════════════════════════
-- Guest payment methods (app-eguest payment-method management) — appended
-- guest-surface table for the signed-in session subject. bill8 owns the
-- instrument; PMS stores the token reference only (DESIGN.md §3 secrets rule).

CREATE TABLE IF NOT EXISTS pms.guest_payment_methods (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id              UUID NOT NULL,
    property_id         UUID NOT NULL REFERENCES pms.properties(id),
    sentin8_auth_user_id TEXT NOT NULL,
    label               TEXT NOT NULL,
    payment_method_id   TEXT NOT NULL,
    is_default          BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pms_gpm_property ON pms.guest_payment_methods (property_id);
CREATE INDEX IF NOT EXISTS idx_pms_gpm_user ON pms.guest_payment_methods (property_id, sentin8_auth_user_id);

ALTER TABLE pms.guest_payment_methods ENABLE ROW LEVEL SECURITY;
ALTER TABLE pms.guest_payment_methods FORCE ROW LEVEL SECURITY;

CREATE POLICY pms_gpm_rls ON pms.guest_payment_methods USING (property_id IN (SELECT id FROM pms.properties));
