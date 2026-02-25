//! PaymentProvider trait and implementations.

pub mod btcpay;
pub mod stub;

use super::types::{Invoice, PurchaseRequest};
use async_trait::async_trait;

/// Abstraction over payment providers.
#[async_trait]
pub trait PaymentProvider: Send + Sync {
    /// Create an invoice for a purchase.
    async fn create_invoice(
        &self,
        request: &PurchaseRequest,
        amount_sats: u64,
    ) -> Result<Invoice, anyhow::Error>;

    /// Check the status of an invoice.
    async fn get_invoice(&self, invoice_id: &str) -> Result<Invoice, anyhow::Error>;

    /// Process a webhook callback from the payment provider.
    async fn process_webhook(
        &self,
        payload: &[u8],
        signature: Option<&str>,
    ) -> Result<Invoice, anyhow::Error>;
}
