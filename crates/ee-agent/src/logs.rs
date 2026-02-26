use std::{collections::VecDeque, sync::Arc};

use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub struct LogBuffer {
    inner: Arc<Mutex<VecDeque<String>>>,
}

impl LogBuffer {
    pub async fn push(&self, line: impl Into<String>) {
        let mut guard = self.inner.lock().await;
        if guard.len() >= 1000 {
            let _ = guard.pop_front();
        }
        guard.push_back(line.into());
    }

    pub async fn snapshot(&self) -> Vec<String> {
        self.inner.lock().await.iter().cloned().collect()
    }
}
