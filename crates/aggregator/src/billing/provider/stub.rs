//! Stub payment provider for development and testing.

use super::PaymentProvider;
use crate::billing::types::{Invoice, InvoiceStatus, PurchaseRequest};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// In-memory stub provider. Invoices are auto-paid.
pub struct StubProvider {
    invoices: Arc<RwLock<HashMap<String, Invoice>>>,
}

impl StubProvider {
    pub fn new() -> Self {
        Self {
            invoices: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for StubProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PaymentProvider for StubProvider {
    async fn create_invoice(
        &self,
        request: &PurchaseRequest,
        amount_sats: u64,
    ) -> Result<Invoice, anyhow::Error> {
        let invoice = Invoice {
            id: Uuid::new_v4().to_string(),
            listing_id: request.listing_id.clone(),
            buyer: request.buyer.clone(),
            amount_sats,
            status: InvoiceStatus::Paid, // auto-paid in stub
            payment_url: None,
            created_at: Utc::now(),
            paid_at: Some(Utc::now()),
        };

        self.invoices
            .write()
            .await
            .insert(invoice.id.clone(), invoice.clone());

        Ok(invoice)
    }

    async fn get_invoice(&self, invoice_id: &str) -> Result<Invoice, anyhow::Error> {
        self.invoices
            .read()
            .await
            .get(invoice_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("invoice not found: {invoice_id}"))
    }

    async fn process_webhook(
        &self,
        _payload: &[u8],
        _signature: Option<&str>,
    ) -> Result<Invoice, anyhow::Error> {
        anyhow::bail!("stub provider does not support webhooks")
    }
}
