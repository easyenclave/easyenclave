//! BTCPay Server payment provider.

use super::PaymentProvider;
use crate::billing::types::{Invoice, InvoiceStatus, PurchaseRequest};
use crate::config::BtcPayConfig;
use async_trait::async_trait;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, warn};

type HmacSha256 = Hmac<Sha256>;

pub struct BtcPayProvider {
    config: BtcPayConfig,
    client: reqwest::Client,
}

impl BtcPayProvider {
    pub fn new(config: BtcPayConfig, client: reqwest::Client) -> Self {
        Self { config, client }
    }
}

#[async_trait]
impl PaymentProvider for BtcPayProvider {
    async fn create_invoice(
        &self,
        request: &PurchaseRequest,
        amount_sats: u64,
    ) -> Result<Invoice, anyhow::Error> {
        let url = format!(
            "{}/api/v1/stores/{}/invoices",
            self.config.url.trim_end_matches('/'),
            self.config.store_id
        );

        // BTCPay Greenfield API expects amount in BTC denomination
        // We store sats internally and convert
        let amount_btc = amount_sats as f64 / 100_000_000.0;

        let body = serde_json::json!({
            "amount": amount_btc,
            "currency": "BTC",
            "metadata": {
                "listing_id": request.listing_id,
                "buyer": request.buyer,
                "hours": request.hours,
            },
        });

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("token {}", self.config.api_key))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("BTCPay returned {status}: {body}");
        }

        let btcpay_invoice: serde_json::Value = resp.json().await?;
        let invoice_id = btcpay_invoice["id"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let checkout_link = btcpay_invoice["checkoutLink"]
            .as_str()
            .map(|s| s.to_string());

        Ok(Invoice {
            id: invoice_id,
            listing_id: request.listing_id.clone(),
            buyer: request.buyer.clone(),
            amount_sats,
            status: InvoiceStatus::Pending,
            payment_url: checkout_link,
            created_at: Utc::now(),
            paid_at: None,
        })
    }

    async fn get_invoice(&self, invoice_id: &str) -> Result<Invoice, anyhow::Error> {
        let url = format!(
            "{}/api/v1/stores/{}/invoices/{invoice_id}",
            self.config.url.trim_end_matches('/'),
            self.config.store_id
        );

        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("token {}", self.config.api_key))
            .send()
            .await?;

        if !resp.status().is_success() {
            anyhow::bail!("BTCPay returned {}", resp.status());
        }

        let data: serde_json::Value = resp.json().await?;
        let status = match data["status"].as_str().unwrap_or("") {
            "Settled" | "Complete" => InvoiceStatus::Paid,
            "Expired" => InvoiceStatus::Expired,
            _ => InvoiceStatus::Pending,
        };

        let metadata = &data["metadata"];
        Ok(Invoice {
            id: invoice_id.to_string(),
            listing_id: metadata["listing_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            buyer: metadata["buyer"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            amount_sats: 0, // would need to convert back from BTC
            status,
            payment_url: data["checkoutLink"].as_str().map(|s| s.to_string()),
            created_at: Utc::now(),
            paid_at: if status == InvoiceStatus::Paid {
                Some(Utc::now())
            } else {
                None
            },
        })
    }

    async fn process_webhook(
        &self,
        payload: &[u8],
        signature: Option<&str>,
    ) -> Result<Invoice, anyhow::Error> {
        // Verify HMAC signature
        if let Some(sig) = signature {
            let mut mac = HmacSha256::new_from_slice(self.config.webhook_secret.as_bytes())?;
            mac.update(payload);

            let expected = hex::encode(mac.finalize().into_bytes());
            if expected != sig.trim_start_matches("sha256=") {
                anyhow::bail!("webhook signature mismatch");
            }
        } else {
            warn!("webhook received without signature");
        }

        let data: serde_json::Value = serde_json::from_slice(payload)?;
        let invoice_id = data["invoiceId"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing invoiceId in webhook"))?;

        debug!(invoice_id, "processing BTCPay webhook");
        self.get_invoice(invoice_id).await
    }
}
