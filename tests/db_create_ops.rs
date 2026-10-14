// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! DB-backed create-operation tests for Hotel8:PMS (pms DESIGN.md §9
//! "Integration (DB-backed)").
//!
//! Each create handler's SQL must round-trip against the live `hotel8`
//! database — typed date/enum/numeric binds verified on the real schema (the
//! audit this suite pins: text binds against date/enum columns are a 500).
//! The suite SKIPS (not fails) when `HOTEL8_PMS_TEST_DATABASE_URL` is unset
//! AND the provisioned default is unreachable. Each test runs inside ONE
//! explicit transaction (`set_config` is transaction-local — the same rule
//! the handlers follow); the transaction rolls back on drop, so no manual
//! cleanup rows escape a failed run.

use sqlx::Row;
use uuid::Uuid;

use hotel8_pms_server::handlers::set_tenant_context;

const ENV: uuid::Uuid = uuid::Uuid::nil();

fn db_url() -> Option<String> {
    // Test DSN: the service role (search_path pms, public) against the
    // vertical database — same shape the running service uses. The suite
    // runs when the URL env is set (`make test-rust` exports nothing; the
    // workspace DB suite sets it) OR when the vertical DB is reachable at
    // the provisioned default.
    if let Ok(u) = std::env::var("HOTEL8_PMS_TEST_DATABASE_URL") {
        if !u.is_empty() {
            return Some(u);
        }
    }
    // Provisioned default (created by `make vertical-init`): attempt a TCP
    // connect; unreachable DB → skip (None).
    match std::net::TcpStream::connect("127.0.0.1:5432") {
        Ok(_) => Some("postgres://hotel8_pms_service@localhost:5432/hotel8".to_string()),
        Err(_) => None,
    }
}

async fn connect() -> Option<sqlx::PgPool> {
    let url = db_url()?;
    // Role caps: the test uses its own small pool (max 2).
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&url)
        .await
        .ok()?;
    Some(pool)
}

/// Unique property fixture wired into the test env (RLS: rows in `pms`
/// resolve through the properties table).
async fn fixture_property(
    conn: &mut sqlx::PgConnection,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let code = format!("T{}", &Uuid::new_v4().simple().to_string()[..8]);
    let row = sqlx::query(
        "INSERT INTO pms.properties (env_id, property_code, property_name)
         VALUES ($1, $2, 'Type-cast Test Property') RETURNING id",
    )
    .bind(ENV)
    .bind(&code)
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.get("id"))
}

/// Create-op round-trips: date columns accept bound dates, enum columns
/// accept their labels, numerics round-trip — the exact set the master-plan
/// audit (H11.1) proved was text-binding-broken before the fixes.
mod create_ops {
    use super::*;

    async fn conn() -> Option<sqlx::PgPool> {
        connect().await
    }

    #[tokio::test]
    async fn create_rate_schedule_binds_typed_dates() {
        let Some(pool) = conn().await else { return };
        let mut conn = pool.begin().await.unwrap();
        set_tenant_context(&mut conn, ENV).await;
        let property_id = fixture_property(&mut conn).await.unwrap();

        // Rate plan fixture.
        let plan_id: Uuid = sqlx::query(
            "INSERT INTO pms.rate_plans (property_id, rate_plan_code, rate_plan_name, currency_code)
             VALUES ($1, 'TS', 'Type-cast Plan', 'USD') RETURNING id",
        )
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap()
        .get("id");

        // The EXACT INSERT shape the handler runs (rate_plans.rs) — typed
        // date binds must parse; a text bind would 500 (operator does not
        // exist: date = text).
        let room_type_id: Uuid = sqlx::query(
            "INSERT INTO pms.room_types (property_id, room_type_code, room_type_name, max_occupancy)
             VALUES ($1, 'TS', 'Suite', 2) RETURNING id",
        )
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap()
        .get("id");

        let row = sqlx::query(
            "INSERT INTO pms.rate_schedules (property_id, rate_plan_id, room_type_id, start_date, end_date, days_of_week, rate_amount, rate_amount_single, rate_amount_double, rate_amount_extra_adult, rate_amount_extra_child, package_code)
             SELECT $1, $2, $3, $4::date, $5::date, $6, $7::numeric, $8::numeric, $9::numeric, $10::numeric, $11::numeric, $12
             RETURNING id, start_date, end_date",
        )
        .bind(property_id)
        .bind(plan_id)
        .bind(room_type_id)
        .bind("2026-01-01")
        .bind("2026-12-31")
        .bind(serde_json::json!(["MON", "TUE"]))
        .bind("199.00")
        .bind("189.00")
        .bind("219.00")
        .bind("30.00")
        .bind("20.00")
        .bind(Option::<String>::None)
        .fetch_one(&mut *conn)
        .await;
        let row = row.expect("rate schedule INSERT with date casts must succeed");
        let start: chrono::NaiveDate = row.get("start_date");
        assert_eq!(start, chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap());

        // Cleanup: fixture cascade.
        sqlx::query("DELETE FROM pms.rate_schedules WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.rate_plans WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.room_types WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.properties WHERE id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_profile_binds_enum_casts() {
        let Some(pool) = conn().await else { return };
        let mut conn = pool.begin().await.unwrap();
        set_tenant_context(&mut conn, ENV).await;
        let property_id = fixture_property(&mut conn).await.unwrap();

        // The EXACT INSERT the handler runs (profiles.rs): enum labels bind
        // with the ::pms_profile_type / ::pms_vip_status casts.
        let row = sqlx::query(
            "INSERT INTO pms.guest_profiles (property_id, profile_type, vip_status, first_name, last_name)
             VALUES ($1, $2::pms.profile_type, $3::pms.vip_status, $4, $5)
             RETURNING id, profile_type::text AS profile_type",
        )
        .bind(property_id)
        .bind("GUEST")
        .bind("GOLD")
        .bind("Ada")
        .bind("Lovelace")
        .fetch_one(&mut *conn)
        .await;
        let row = row.expect("profile INSERT with enum casts must succeed");
        assert_eq!(row.get::<String, _>("profile_type"), "GUEST");

        sqlx::query("DELETE FROM pms.guest_profiles WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.properties WHERE id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_reservation_binds_dates_and_state() {
        let Some(pool) = conn().await else { return };
        let mut conn = pool.begin().await.unwrap();
        set_tenant_context(&mut conn, ENV).await;
        let property_id = fixture_property(&mut conn).await.unwrap();

        let rt_id: Uuid = sqlx::query(
            "INSERT INTO pms.room_types (property_id, room_type_code, room_type_name, max_occupancy)
             VALUES ($1, 'TR', 'Type Room', 2) RETURNING id",
        )
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap()
        .get("id");

        // The EXACT create_reservation INSERT (reservations.rs).
        let row = sqlx::query(
            "INSERT INTO pms.reservations (property_id, confirmation_number, guest_profile_id, room_type_id, rate_plan_id, arrival_date, departure_date, num_adults, num_children, num_rooms, status, guarantee_type, guarantee_code, special_requests, package_code, market_code, source_code, channel_code)
             VALUES ($1, $2, $3, $4, $5, $6::date, $7::date, $8, $9, $10, 'CONFIRMED', $11, $12, $13, $14, $15, $16, $17) RETURNING id, status::text AS status, arrival_date",
        )
        .bind(property_id)
        .bind("TCONF-1")
        .bind(Option::<Uuid>::None)
        .bind(rt_id)
        .bind(Option::<Uuid>::None)
        .bind("2026-03-01")
        .bind("2026-03-03")
        .bind(2_i32)
        .bind(0_i32)
        .bind(1_i32)
        .bind("CCG")
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .fetch_one(&mut *conn)
        .await;
        let row = row.expect("reservation INSERT with date casts must succeed");
        assert_eq!(row.get::<String, _>("status"), "CONFIRMED");

        sqlx::query("DELETE FROM pms.reservations WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.room_types WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.properties WHERE id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_block_and_event_bind_dates() {
        let Some(pool) = conn().await else { return };
        let mut conn = pool.begin().await.unwrap();
        set_tenant_context(&mut conn, ENV).await;
        let property_id = fixture_property(&mut conn).await.unwrap();

        // Block insert (blocks.rs shape — negotiated_rate is numeric-cast,
        // released_until/cutoff arrive as typed strings).
        let block = sqlx::query(
            "INSERT INTO pms.blocks (property_id, block_code, block_name, room_type_id, start_date, end_date, blocked_rooms, released_until, status, block_type, negotiated_rate, cutoff_date)
             VALUES ($1, $2, $3, $4, $5::date, $6::date, $7, $8, 'PROVISIONAL', $9, $10::numeric, $11::date) RETURNING id",
        )
        .bind(property_id)
        .bind("TBLK1")
        .bind("Type-cast Block")
        .bind(Option::<Uuid>::None)
        .bind("2026-05-01")
        .bind("2026-05-10")
        .bind(5_i32)
        .bind("0")
        .bind("ALLOTMENT")
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .fetch_one(&mut *conn)
        .await;
        if let Err(ref e) = block {
            println!("BLK ERR: {e}");
        }
        assert!(block.is_ok(), "block INSERT with date casts must succeed");

        // Event insert (events.rs shape — the audit's fixed text binds).
        let event = sqlx::query(
            "INSERT INTO pms.events (property_id, event_code, event_name, event_type, start_date, end_date, status, expected_attendees, banquet_order, contact_name, contact_phone, notes)
             VALUES ($1, $2, $3, $4, $5::date, $6::date, 'TENTATIVE', $7, $8, $9, $10, $11) RETURNING id",
        )
        .bind(property_id)
        .bind("TEVT1")
        .bind("Type-cast Event")
        .bind("MEETING")
        .bind("2026-06-01")
        .bind("2026-06-02")
        .bind(50_i32)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .fetch_one(&mut *conn)
        .await;
        assert!(
            event.is_ok(),
            "event INSERT with typed date binds must succeed"
        );

        sqlx::query("DELETE FROM pms.events WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.blocks WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.properties WHERE id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_room_and_property_roundtrip() {
        let Some(pool) = conn().await else { return };
        let mut conn = pool.begin().await.unwrap();
        set_tenant_context(&mut conn, ENV).await;
        let property_id = fixture_property(&mut conn).await.unwrap();

        let rt_id: Uuid = sqlx::query(
            "INSERT INTO pms.room_types (property_id, room_type_code, room_type_name, max_occupancy)
             VALUES ($1, 'TRM', 'Type Room', 2) RETURNING id",
        )
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap()
        .get("id");

        // Room insert (rooms.rs RoomCreate shape).
        let room = sqlx::query(
            "INSERT INTO pms.rooms (property_id, room_type_id, room_number, floor, building, front_office_status, housekeeping_status, is_smoking, max_occupancy, bed_type, features)
             VALUES ($1, $2, $3, $4, $5, 'VACANT', 'DIRTY', $6, $7, $8, $9) RETURNING id, room_number",
        )
        .bind(property_id)
        .bind(rt_id)
        .bind("1001")
        .bind("1")
        .bind(Option::<String>::None)
        .bind(false)
        .bind(2_i32)
        .bind("KING")
        .bind(serde_json::json!([]))
        .fetch_one(&mut *conn)
        .await;
        let room = room.expect("room INSERT must succeed");
        assert_eq!(room.get::<String, _>("room_number"), "1001");

        sqlx::query("DELETE FROM pms.rooms WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.room_types WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.properties WHERE id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn corporate_surfaces_roundtrip() {
        let Some(pool) = conn().await else { return };
        let mut conn = pool.begin().await.unwrap();
        set_tenant_context(&mut conn, ENV).await;
        let property_id = fixture_property(&mut conn).await.unwrap();

        // Company profile + payment method (approval workflow rows).
        let company_id: Uuid = sqlx::query(
            "INSERT INTO pms.guest_profiles (property_id, profile_type, first_name, last_name, company_name)
             VALUES ($1, $2::pms.profile_type, '', 'Acme Corp', 'Acme Corp') RETURNING id",
        )
        .bind(property_id)
        .bind("COMPANY")
        .fetch_one(&mut *conn)
        .await
        .unwrap()
        .get("id");

        let pm = sqlx::query(
            "INSERT INTO pms.company_payment_methods (env_id, property_id, company_profile_id, label, payment_method_id, approval, credit_limit)
             VALUES ($3, $1, $2, 'Corporate account', 'tok_test_123', 'BILL_TO_COMPANY', 5000::numeric)
             RETURNING id, approval",
        )
        .bind(property_id)
        .bind(company_id)
        .bind(ENV)
        .fetch_one(&mut *conn)
        .await;
        if let Err(ref e) = pm {
            println!("PM ERR: {e}");
        }
        assert!(pm.is_ok(), "company payment-method INSERT must succeed");

        // Traveler binding.
        let traveler_id: Uuid = sqlx::query(
            "INSERT INTO pms.guest_profiles (property_id, profile_type, first_name, last_name)
             VALUES ($1, $2::pms.profile_type, 'Trey', 'Traveler') RETURNING id",
        )
        .bind(property_id)
        .bind("GUEST")
        .fetch_one(&mut *conn)
        .await
        .unwrap()
        .get("id");
        let cu = sqlx::query(
            "INSERT INTO pms.company_users (env_id, property_id, company_profile_id, traveler_profile_id, role_at_company, is_default)
             VALUES ($4, $1, $2, $3, 'BOOKING_AGENT', true) RETURNING id",
        )
        .bind(property_id)
        .bind(company_id)
        .bind(traveler_id)
        .bind(ENV)
        .fetch_one(&mut *conn)
        .await;
        assert!(
            cu.is_ok(),
            "company user binding must succeed (unique pair)"
        );

        // Kiosk config default materialization.
        let kc = sqlx::query(
            "INSERT INTO pms.kiosk_config (property_id, env_id) VALUES ($1, $2)
             ON CONFLICT (property_id) DO NOTHING
             RETURNING property_id",
        )
        .bind(property_id)
        .bind(ENV)
        .fetch_one(&mut *conn)
        .await;
        assert!(kc.is_ok(), "kiosk config default row must materialize");

        sqlx::query("DELETE FROM pms.company_users WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.company_payment_methods WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.kiosk_config WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.guest_profiles WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.properties WHERE id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn corporate_provisioning_and_rate_mix_roundtrip() {
        // ECRP-3 + ECRP-5: first-admin provisioning state and the
        // company↔negotiated-rate link the corporate-availability filter
        // reads (`preferences.negotiated_rate_plan_ids`).
        let Some(pool) = conn().await else { return };
        let mut conn = pool.begin().await.unwrap();
        set_tenant_context(&mut conn, ENV).await;
        let property_id = fixture_property(&mut conn).await.unwrap();

        // Company with no IdP and no admin → requires provisioning.
        let company_id: Uuid = sqlx::query(
            "INSERT INTO pms.guest_profiles (property_id, profile_type, last_name, company_name)
             VALUES ($1, $2::pms.profile_type, 'No IdP Corp', 'No IdP Corp') RETURNING id",
        )
        .bind(property_id)
        .bind("COMPANY")
        .fetch_one(&mut *conn)
        .await
        .unwrap()
        .get("id");
        let probe = sqlx::query(
            "SELECT (preferences->>'sso_provider') IS NOT NULL AS has_idp,
                    (SELECT COUNT(*)::bigint FROM pms.company_users
                      WHERE property_id = $1 AND company_profile_id = $2 AND role_at_company = 'ADMIN') AS admin_count
             FROM pms.guest_profiles WHERE id = $2",
        )
        .bind(property_id)
        .bind(company_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        let has_idp: bool = probe.get("has_idp");
        let admin_count: i64 = probe.get("admin_count");
        assert!(
            !has_idp && admin_count == 0,
            "fresh no-IdP company requires provisioning"
        );

        // Provision: insert the admin traveler + binding + stamp.
        let traveler_id: Uuid = sqlx::query(
            "INSERT INTO pms.guest_profiles (property_id, profile_type, first_name, last_name, email)
             VALUES ($1, $2::pms.profile_type, 'Ada', 'Admin', 'ada@noidp.test') RETURNING id",
        )
        .bind(property_id)
        .bind("GUEST")
        .fetch_one(&mut *conn)
        .await
        .unwrap()
        .get("id");
        sqlx::query(
            "INSERT INTO pms.company_users (env_id, property_id, company_profile_id, traveler_profile_id, role_at_company, is_default)
             VALUES ($4, $1, $2, $3, 'ADMIN', true)",
        )
        .bind(property_id)
        .bind(company_id)
        .bind(traveler_id)
        .bind(ENV)
        .execute(&mut *conn)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE pms.guest_profiles SET preferences = COALESCE(preferences, '{}'::jsonb) || jsonb_build_object('provisioned_admin_at', to_jsonb(now())) WHERE id = $1",
        )
        .bind(company_id)
        .execute(&mut *conn)
        .await
        .unwrap();

        // Rate-mix link: negotiated plan + company preference binding.
        let plan_id: Uuid = sqlx::query(
            "INSERT INTO pms.rate_plans (property_id, rate_plan_code, rate_plan_name, rate_category, rate_class, currency_code, is_negotiated)
             VALUES ($1, 'CORP001', 'No IdP Corporate', 'CORPORATE', 'NEGOTIATED', 'USD', true) RETURNING id",
        )
        .bind(property_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap()
        .get("id");
        sqlx::query(
            "UPDATE pms.guest_profiles SET preferences = COALESCE(preferences, '{}'::jsonb)
                || jsonb_build_object('negotiated_rate_plan_ids',
                    COALESCE(preferences->'negotiated_rate_plan_ids', '[]'::jsonb) || to_jsonb($2::uuid))
             WHERE id = $1",
        )
        .bind(company_id)
        .bind(plan_id)
        .execute(&mut *conn)
        .await
        .unwrap();

        // The corporate-availability rate-mix filter selects exactly the
        // linked plan for the linked company (and nothing for others).
        let linked: Option<Uuid> = sqlx::query(
            "SELECT rp.id FROM pms.rate_plans rp
             WHERE rp.property_id = $1 AND rp.is_active = true AND rp.is_negotiated = true
               AND EXISTS (SELECT 1 FROM pms.guest_profiles gp
                            WHERE gp.id = $2 AND gp.profile_type = 'COMPANY'
                              AND gp.preferences->'negotiated_rate_plan_ids' ? rp.id::text)",
        )
        .bind(property_id)
        .bind(company_id)
        .fetch_optional(&mut *conn)
        .await
        .unwrap()
        .map(|r| r.get("id"));
        assert_eq!(
            linked,
            Some(plan_id),
            "rate-mix filter selects the linked plan"
        );

        // Post-provisioning state: no longer requires provisioning.
        let probe2 = sqlx::query(
            "SELECT COUNT(*)::bigint AS admin_count FROM pms.company_users
              WHERE property_id = $1 AND company_profile_id = $2 AND role_at_company = 'ADMIN'",
        )
        .bind(property_id)
        .bind(company_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        let admin_count2: i64 = probe2.get("admin_count");
        assert!(admin_count2 == 1, "provisioned company has one admin");

        sqlx::query("DELETE FROM pms.company_users WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.rate_plans WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.guest_profiles WHERE property_id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DELETE FROM pms.properties WHERE id = $1")
            .bind(property_id)
            .execute(&mut *conn)
            .await
            .unwrap();
    }
}
