use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

const CHANNEL_CAPACITY: usize = 1024;

#[derive(Clone)]
pub struct Broker {
    channels: Arc<RwLock<HashMap<String, broadcast::Sender<Message>>>>,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub channel: String,
    pub payload: String,
}

impl Broker {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn subscribe(&self, channel: &str) -> broadcast::Receiver<Message> {
        let mut channels = self.channels.write().await;
        let tx = channels
            .entry(channel.to_string())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0);
        tx.subscribe()
    }

    pub async fn publish(&self, channel: &str, payload: String) -> i64 {
        let channels = self.channels.read().await;
        if let Some(tx) = channels.get(channel) {
            let msg = Message {
                channel: channel.to_string(),
                payload,
            };
            tx.send(msg).unwrap_or(0) as i64
        } else {
            0
        }
    }
}
