//! Marketplace: listings, purchases, and assignments.

use super::provider::PaymentProvider;
use super::types::{Assignment, Invoice, Listing, PurchaseRequest};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

/// Manages marketplace listings and assignments.
pub struct Marketplace {
    provider: Arc<dyn PaymentProvider>,
    listings: Arc<RwLock<HashMap<String, Listing>>>,
    assignments: Arc<RwLock<HashMap<String, Assignment>>>,
}

impl Marketplace {
    pub fn new(provider: Arc<dyn PaymentProvider>) -> Self {
        Self {
            provider,
            listings: Arc::new(RwLock::new(HashMap::new())),
            assignments: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a listing.
    pub async fn add_listing(&self, listing: Listing) {
        self.listings
            .write()
            .await
            .insert(listing.id.clone(), listing);
    }

    /// Get all available listings.
    pub async fn list_available(&self) -> Vec<Listing> {
        self.listings
            .read()
            .await
            .values()
            .filter(|l| l.available)
            .cloned()
            .collect()
    }

    /// Purchase access to an agent.
    pub async fn purchase(&self, request: PurchaseRequest) -> Result<Invoice, anyhow::Error> {
        let listings = self.listings.read().await;
        let listing = listings
            .get(&request.listing_id)
            .ok_or_else(|| anyhow::anyhow!("listing not found"))?;

        if !listing.available {
            anyhow::bail!("listing not available");
        }

        let amount_sats = listing.price_sats_per_hour * request.hours as u64;
        let invoice = self.provider.create_invoice(&request, amount_sats).await?;

        info!(
            invoice_id = %invoice.id,
            listing_id = %request.listing_id,
            buyer = %request.buyer,
            amount_sats,
            "purchase invoice created"
        );

        // If auto-paid (stub), create assignment immediately
        if invoice.paid_at.is_some() {
            let assignment = Assignment {
                id: Uuid::new_v4().to_string(),
                invoice_id: invoice.id.clone(),
                agent_id: String::new(), // assigned later
                buyer: request.buyer,
                expires_at: Utc::now() + Duration::hours(request.hours as i64),
            };
            self.assignments
                .write()
                .await
                .insert(assignment.id.clone(), assignment);
        }

        Ok(invoice)
    }

    /// Get invoice status.
    pub async fn get_invoice(&self, invoice_id: &str) -> Result<Invoice, anyhow::Error> {
        self.provider.get_invoice(invoice_id).await
    }

    /// Get active assignments for a buyer.
    pub async fn buyer_assignments(&self, buyer: &str) -> Vec<Assignment> {
        self.assignments
            .read()
            .await
            .values()
            .filter(|a| a.buyer == buyer && a.expires_at > Utc::now())
            .cloned()
            .collect()
    }
}
