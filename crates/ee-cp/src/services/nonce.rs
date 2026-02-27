use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct NonceService {
    ttl: Duration,
    inner: Arc<Mutex<HashMap<String, Instant>>>,
}

impl NonceService {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn issue(&self) -> String {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let expiry = Instant::now() + self.ttl;

        let mut guard = self.inner.lock().expect("nonce lock poisoned");
        guard.insert(nonce.clone(), expiry);
        nonce
    }

    pub fn consume(&self, nonce: &str) -> ConsumeResult {
        let mut guard = self.inner.lock().expect("nonce lock poisoned");
        match guard.remove(nonce) {
            Some(expiry) if expiry > Instant::now() => ConsumeResult::Ok,
            Some(_) => ConsumeResult::Expired,
            None => ConsumeResult::Missing,
        }
    }

    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut guard = self.inner.lock().expect("nonce lock poisoned");
        guard.retain(|_, expiry| *expiry > now);
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.ttl.as_secs()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumeResult {
    Ok,
    Missing,
    Expired,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{ConsumeResult, NonceService};

    #[test]
    fn nonce_is_single_use() {
        let svc = NonceService::new(Duration::from_secs(60));
        let nonce = svc.issue();

        assert_eq!(svc.consume(&nonce), ConsumeResult::Ok);
        assert_eq!(svc.consume(&nonce), ConsumeResult::Missing);
    }

    #[test]
    fn nonce_expires() {
        let svc = NonceService::new(Duration::from_millis(10));
        let nonce = svc.issue();
        std::thread::sleep(Duration::from_millis(20));

        assert_eq!(svc.consume(&nonce), ConsumeResult::Expired);
    }
}
