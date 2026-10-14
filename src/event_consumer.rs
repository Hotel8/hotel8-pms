// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Bus consumer placeholder.
//!
//! PMS is primarily a producer (stream family `pms`). It subscribes to no
//! external family yet; cross-service reactions (loyalty awards, POS room
//! prep, upsell generation, distrib ARI, meta ARI) are consumed by the
//! owning services directly (see their `event_consumer.rs`). When PMS needs
//! to react to platform events (e.g. `sentin8:sys:service:updated` env-init),
//! mirror the loyalty consumer shape here.

/// Reserved consumer-group name for future PMS subscriptions.
#[allow(dead_code)]
pub const CONSUMER_GROUP: &str = "hotel8:pms:fanout";
