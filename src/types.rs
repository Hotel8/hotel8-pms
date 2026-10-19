// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Shared types for PMS handlers.

/// Resolve the property_id from the authenticated token's env ID.
///
/// In PMS, a Property maps to a Sentin8 environment. The JWT claims carry
/// `env_id` which is the single source of truth for tenant resolution.
/// There is no separate Chain entity - the organization *is* the chain.
#[allow(dead_code)]
pub fn resolve_property_id(token_env_id: uuid::Uuid) -> uuid::Uuid {
    token_env_id
}
