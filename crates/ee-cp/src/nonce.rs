use std::time::{Duration, Instant};

use dashmap::DashMap;

#[derive(Default)]
pub struct NonceStore {
    values: DashMap<String, Instant>,
}

impl NonceStore {
    pub fn issue(&self, ttl: Duration) -> String {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        self.values.insert(nonce.clone(), Instant::now() + ttl);
        nonce
    }

    pub fn consume(&self, nonce: &str) -> bool {
        match self.values.remove(nonce) {
            Some((_, expires_at)) => Instant::now() <= expires_at,
            None => false,
        }
    }

    pub fn cleanup(&self) {
        let now = Instant::now();
        self.values.retain(|_, expires_at| *expires_at > now);
    }
}
