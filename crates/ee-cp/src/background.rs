use std::time::Duration;

use tokio::time;

use crate::state::SharedState;

pub fn spawn(state: SharedState) {
    let nonce_state = state.clone();
    tokio::spawn(async move {
        let mut ticker = time::interval(Duration::from_secs(30));
        loop {
            ticker.tick().await;
            nonce_state.nonces.cleanup();
        }
    });
}
