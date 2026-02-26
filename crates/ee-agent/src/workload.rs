use std::sync::Arc;

use ee_common::error::AppResult;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub struct WorkloadManager {
    current: Arc<Mutex<Option<String>>>,
}

impl WorkloadManager {
    pub async fn deploy(&self, image: &str) -> AppResult<()> {
        let mut current = self.current.lock().await;
        *current = Some(image.to_owned());
        Ok(())
    }

    pub async fn undeploy(&self) -> AppResult<()> {
        let mut current = self.current.lock().await;
        *current = None;
        Ok(())
    }

    pub async fn current(&self) -> Option<String> {
        self.current.lock().await.clone()
    }
}
