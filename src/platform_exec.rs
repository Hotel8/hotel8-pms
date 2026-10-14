// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Hotel8:PMS
// SPDX-License-Identifier: Apache-2.0

//! Outbound platform-service calls for PMS.
//!
//! Payment acceptance is a Bill8:Payments charge (single-use token
//! consumed to the method id); settlement is a Bill8:Ledger
//! balance-transaction. Every call presents the corresponding workload
//! CERTIFICATE in the TLS handshake (CERTFREE-4V — no M2M token
//! exists; the transports are built at boot and stored in the config);
//! failures are returned — never silently swallowed.

/// POST a charge to Bill8:Payments. Returns the immutable charge id.
///
/// `client` is the boot-built `pms-payments` certificate transport.
pub async fn process_payment(
    client: &reqwest::Client,
    payments_url: &str,
    payment_method_token: String,
    amount: f64,
    currency: &str,
) -> Result<uuid::Uuid, String> {
    // Single-use token → payment_method_id (bill8 tokens design PAY-10);
    // then the immutable charge with a folio-scoped idempotency key.
    let method_id = consume_token(client, payments_url, &payment_method_token).await?;
    let body = serde_json::json!({
        "payment_method_id": method_id,
        "amount": format!("{amount:.2}"),
        "currency": currency,
        "idempotency_key": format!("hotel8:pms:{payment_method_token}"),
    });
    let resp = client
        .post(format!(
            "{}/v1/charges",
            payments_url.trim_end_matches('/')
        ))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Payments HTTP: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Payments status {}", resp.status()));
    }
    let v: serde_json::Value = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    v.get("id")
        .and_then(|x| x.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| "Payments returned no id".to_string())
}

/// POST a double-entry movement to Bill8:Ledger. Returns the transaction id.
///
/// `client` is the boot-built `pms-ledger` certificate transport.
pub async fn post_to_ledger(
    client: &reqwest::Client,
    ledger_url: &str,
    batch_id: String,
    debit_balance_id: uuid::Uuid,
    credit_balance_id: uuid::Uuid,
    amount: String,
    currency: &str,
    source_id: uuid::Uuid,
) -> Result<uuid::Uuid, String> {
    let body = serde_json::json!({
        "debit_balance_id": debit_balance_id,
        "credit_balance_id": credit_balance_id,
        "amount": amount,
        "currency": currency,
        "transaction_type": "transfer",
        "source_type": "charge",
        "source_id": source_id,
        "idempotency_key": format!("hotel8:pms:{batch_id}"),
    });
    let resp = client
        .post(format!("{}/v1/balance-transactions", ledger_url.trim_end_matches('/')))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Ledger HTTP: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Ledger status {}", resp.status()));
    }
    let v: serde_json::Value = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    v.get("id")
        .and_then(|x| x.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| "Ledger returned no id".to_string())
}

/// A bill8 ledger balance as returned by `GET /v1/balances`.
#[derive(Debug, Clone)]
pub struct LedgerBalance {
    pub id: uuid::Uuid,
    /// Account the balance belongs to (unused today — kept for
    /// follow-ups that need the account reference).
    #[allow(dead_code)]
    pub account_id: uuid::Uuid,
    /// Balance name (`available` etc.).
    #[allow(dead_code)]
    pub name: String,
    /// ISO 4217 currency of the balance.
    #[allow(dead_code)]
    pub currency: String,
    /// Current balance amount (decimal string).
    #[allow(dead_code)]
    pub amount: String,
}

/// Ensure the env's folio-settlement account exists at Bill8:Ledger and
/// return its `available` balance ids keyed by currency (lazy provision:
/// the first settlement call in an env creates the account; replays are
/// no-ops — idempotent by the unique `(account, name, currency)` anchor).
/// The account is a bill8 `platform`-type account owned by the hotelling
/// env; money movement stays in Bill8:Ledger (never shadow-written here).
///
/// `client` is the boot-built `pms-ledger` certificate transport.
pub async fn ensure_settlement_balances(
    client: &reqwest::Client,
    ledger_url: &str,
    env_id: uuid::Uuid,
    currencies: &[&str],
) -> Result<Vec<LedgerBalance>, String> {
    let base = ledger_url.trim_end_matches('/');
    let display_name = format!("hotel8-pms-folio:{env_id}");

    // Find or create the folio account (list is env-scoped by the
    // certificate's tenancy — the display name is the idempotency anchor).
    let account_id = match list_account_by_name(client, base, &display_name).await? {
        Some(id) => id,
        None => {
            let resp = client
                .post(format!("{base}/v1/accounts"))
                .json(&serde_json::json!({
                    "account_type": "platform",
                    "display_name": display_name,
                }))
                .send()
                .await
                .map_err(|e| format!("Ledger account create HTTP: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("Ledger account create status {}", resp.status()));
            }
            let v: serde_json::Value = resp.json().await.map_err(|e| format!("decode: {e}"))?;
            v.get("id")
                .and_then(|x| x.as_str())
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .ok_or_else(|| "Ledger account create returned no id".to_string())?
        }
    };

    // Resolve the `available` balances for the requested currencies.
    list_available_balances(client, base, account_id, currencies).await
}

/// List the env's ledger accounts and match on display name (the public
/// read API — never a cross-schema read).
async fn list_account_by_name(
    client: &reqwest::Client,
    base: &str,
    display_name: &str,
) -> Result<Option<uuid::Uuid>, String> {
    let resp = client
        .get(format!("{base}/v1/accounts"))
        .send()
        .await
        .map_err(|e| format!("Ledger accounts list HTTP: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Ledger accounts list status {}", resp.status()));
    }
    let v: serde_json::Value = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    Ok(v.as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|r| r.get("display_name").and_then(|x| x.as_str()) == Some(display_name))
                .and_then(|r| r.get("id").and_then(|x| x.as_str()))
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
        }))
}

/// List an account's `available` balances filtered by currency.
async fn list_available_balances(
    client: &reqwest::Client,
    base: &str,
    account_id: uuid::Uuid,
    currencies: &[&str],
) -> Result<Vec<LedgerBalance>, String> {
    let resp = client
        .get(format!(
            "{base}/v1/balances?account_id={account_id}&name=available"
        ))
        .send()
        .await
        .map_err(|e| format!("Ledger balances list HTTP: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Ledger balances list status {}", resp.status()));
    }
    let v: serde_json::Value = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    let wanted: Vec<String> = currencies.iter().map(|c| c.to_string()).collect();
    let rows = v
        .as_array()
        .ok_or_else(|| "Ledger balances list: expected array".to_string())?;
    let mut out = Vec::new();
    for r in rows {
        let currency = r.get("currency").and_then(|x| x.as_str()).unwrap_or("");
        if !wanted.iter().any(|c| c == currency) {
            continue;
        }
        out.push(LedgerBalance {
            id: r
                .get("id")
                .and_then(|x| x.as_str())
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .ok_or_else(|| "balance row missing id".to_string())?,
            account_id: r
                .get("account_id")
                .and_then(|x| x.as_str())
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .ok_or_else(|| "balance row missing account_id".to_string())?,
            name: r.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            currency: currency.to_string(),
            amount: r.get("amount").and_then(|x| x.as_str()).unwrap_or("0").to_string(),
        });
    }
    Ok(out)
}

/// Consume a single-use payment token (bill8 PAY-10) to its method id.
async fn consume_token(
    client: &reqwest::Client,
    payments_url: &str,
    token_value: &str,
) -> Result<uuid::Uuid, String> {
    let resp = client
        .post(format!(
            "{}/v1/tokens/{}/consume",
            payments_url.trim_end_matches('/'),
            token_value
        ))
        .send()
        .await
        .map_err(|e| format!("Token consume HTTP: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("Token consume status {}", resp.status()));
    }
    let v: serde_json::Value = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    v.get("payment_method_id")
        .and_then(|x| x.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| "Token consume returned no payment_method_id".to_string())
}

/// Upload an image to Sentin8:Storage (design §4.3: object storage always
/// via Sentin8:Storage, never direct object stores). Returns the object key.
///
/// `storage` is the boot-built certificate-presenting Storage client
/// (the service's own `pms` workload identity).
pub async fn upload_image(
    storage: &sentin8_storage_sdk::client::StorageClient,
    org_id: &str,
    env_id: &str,
    object_key: &str,
    content_type: &str,
    data: Vec<u8>,
) -> Result<(), String> {
    storage
        .put(org_id, env_id, object_key, content_type, data)
        .await
        .map_err(|e| format!("Storage put failed: {e}"))
}

/// Send a transactional message through Sentin8:Post's send API
/// (`POST /v1/send` — alignment doc §12). DBX: a vertical never writes
/// another service's durability tables; the retired
/// `INSERT INTO sentin8.post_inbox` producer path is replaced by this
/// cross-service call (the `pms-post` workload certificate carries
/// `sentin8:post:send` via the registry map — CERTFREE-4V).
/// Returns the queued message id.
///
/// `client` is the boot-built `pms-post` certificate transport.
pub async fn post_send_email(
    client: &reqwest::Client,
    recipient_email: &str,
    subject: &str,
    body: &str,
    body_format: &str,
    metadata: serde_json::Value,
) -> Result<uuid::Uuid, String> {
    let post_url = sentin8::config::Sentin8Config::from_env().sentin8_post_url();
    let payload = serde_json::json!({
        "message_type": "email",
        "category": "transaction",
        "recipient_email": recipient_email,
        "subject": subject,
        "body": body,
        "body_format": body_format,
        "metadata": metadata,
    });
    let resp = client
        .post(format!("{}/v1/send", post_url.trim_end_matches('/')))
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Post HTTP: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let detail = resp.text().await.unwrap_or_default();
        return Err(format!("Post send failed ({status}): {detail}"));
    }
    let v: serde_json::Value = resp.json().await.map_err(|e| format!("decode: {e}"))?;
    v.get("id")
        .and_then(|x| x.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| "Post returned no id".to_string())
}
