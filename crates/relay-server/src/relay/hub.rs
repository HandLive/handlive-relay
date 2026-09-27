//! The instance's view of its relay connections (decision C5).
//!
//! - `registry`: device_id → the local connection currently serving it.
//! - A bus task owns the Redis pub/sub connection: it subscribes to
//!   `dev:<device_id>` while a device is connected here, hands published
//!   messages to that connection, and after a lost Redis connection
//!   reconnects, subscribes again and asks every connection to resync (a
//!   restarted Redis has lost all presence keys).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::StreamExt;
use redis::aio::{ConnectionManager, PubSubSink, PubSubStream};
use tokio::sync::{Notify, mpsc, oneshot};
use uuid::Uuid;

use crate::relay::bus::{BusMessage, channel_device, device_channel};

/// How long a new connection waits for its subscription.
const SUBSCRIBE_TIMEOUT: Duration = Duration::from_secs(5);
const RECONNECT_MIN: Duration = Duration::from_millis(200);
const RECONNECT_MAX: Duration = Duration::from_secs(5);

/// What the hub hands to a connection task.
#[derive(Debug)]
pub enum Delivery {
    Bus(BusMessage),
    /// Redis came back after a loss: re-assert presence and reload peers.
    Resync,
}

/// The handle of one local connection.
pub struct LocalConn {
    pub conn_id: Uuid,
    pub tx: mpsc::UnboundedSender<Delivery>,
    /// Bytes waiting in `tx`; over the limit the connection is dropped.
    pub queued: Arc<AtomicUsize>,
    pub kill: Arc<Notify>,
}

enum BusRequest {
    Subscribe {
        device_id: Uuid,
        done: oneshot::Sender<bool>,
    },
    Unsubscribe {
        device_id: Uuid,
    },
}

pub struct Hub {
    publisher: ConnectionManager,
    registry: Mutex<HashMap<Uuid, LocalConn>>,
    requests: mpsc::UnboundedSender<BusRequest>,
    max_queued_bytes: usize,
}

impl Hub {
    /// Open the pub/sub connection and start the bus task.
    pub async fn start(
        client: redis::Client,
        publisher: ConnectionManager,
        max_queued_bytes: usize,
    ) -> Result<Arc<Self>, String> {
        let pubsub = client
            .get_async_pubsub()
            .await
            .map_err(|e| format!("redis pubsub: {e}"))?;
        let (requests, rx) = mpsc::unbounded_channel();
        let hub = Arc::new(Self {
            publisher,
            registry: Mutex::new(HashMap::new()),
            requests,
            max_queued_bytes,
        });
        let (sink, stream) = pubsub.split();
        tokio::spawn(run_bus(hub.clone(), client, sink, stream, rx));
        Ok(hub)
    }

    fn registry(&self) -> MutexGuard<'_, HashMap<Uuid, LocalConn>> {
        self.registry.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Make `conn` the device's local connection; returns the one it replaces.
    pub fn register(&self, device_id: Uuid, conn: LocalConn) -> Option<LocalConn> {
        self.registry().insert(device_id, conn)
    }

    /// Forget the connection if it is still the current one.
    pub fn unregister(&self, device_id: &Uuid, conn_id: &Uuid) -> bool {
        let mut registry = self.registry();
        if registry
            .get(device_id)
            .is_some_and(|c| c.conn_id == *conn_id)
        {
            registry.remove(device_id);
            return true;
        }
        false
    }

    fn is_registered(&self, device_id: &Uuid) -> bool {
        self.registry().contains_key(device_id)
    }

    /// Subscribe to `dev:<device_id>`; `false` when Redis did not confirm.
    pub async fn subscribe(&self, device_id: Uuid) -> bool {
        let (done, wait) = oneshot::channel();
        if self
            .requests
            .send(BusRequest::Subscribe { device_id, done })
            .is_err()
        {
            return false;
        }
        matches!(
            tokio::time::timeout(SUBSCRIBE_TIMEOUT, wait).await,
            Ok(Ok(true))
        )
    }

    /// Unsubscribe unless another local connection serves the device.
    pub fn unsubscribe(&self, device_id: Uuid) {
        let _ = self.requests.send(BusRequest::Unsubscribe { device_id });
    }

    /// Publish to `dev:<device_id>`; returns how many instances received it
    /// (0 = the device is connected nowhere).
    pub async fn publish(&self, device_id: &Uuid, msg: &BusMessage) -> redis::RedisResult<u64> {
        let mut conn = self.publisher.clone();
        redis::cmd("PUBLISH")
            .arg(device_channel(device_id))
            .arg(msg.encode())
            .query_async(&mut conn)
            .await
    }

    /// Hand a published message to the local connection of its device.
    fn dispatch(&self, device_id: &Uuid, msg: BusMessage) {
        let registry = self.registry();
        let Some(conn) = registry.get(device_id) else {
            return;
        };
        let len = msg.queued_len();
        let queued = conn.queued.fetch_add(len, Ordering::AcqRel) + len;
        if queued > self.max_queued_bytes {
            conn.kill.notify_one();
            return;
        }
        if conn.tx.send(Delivery::Bus(msg)).is_err() {
            conn.queued.fetch_sub(len, Ordering::AcqRel);
        }
    }

    fn broadcast_resync(&self) {
        for conn in self.registry().values() {
            let _ = conn.tx.send(Delivery::Resync);
        }
    }

    fn registered_devices(&self) -> Vec<Uuid> {
        self.registry().keys().copied().collect()
    }
}

async fn run_bus(
    hub: Arc<Hub>,
    client: redis::Client,
    mut sink: PubSubSink,
    mut stream: PubSubStream,
    mut requests: mpsc::UnboundedReceiver<BusRequest>,
) {
    let mut subscribed: HashSet<Uuid> = HashSet::new();
    loop {
        tokio::select! {
            request = requests.recv() => match request {
                None => return,
                Some(BusRequest::Subscribe { device_id, done }) => {
                    let ok = subscribed.contains(&device_id)
                        || match sink.subscribe(device_channel(&device_id)).await {
                            Ok(()) => subscribed.insert(device_id),
                            Err(e) => {
                                log::warn!("relay subscribe failed: {e}");
                                false
                            }
                        };
                    let _ = done.send(ok);
                }
                Some(BusRequest::Unsubscribe { device_id }) => {
                    if !hub.is_registered(&device_id)
                        && subscribed.remove(&device_id)
                        && let Err(e) = sink.unsubscribe(device_channel(&device_id)).await
                    {
                        log::warn!("relay unsubscribe failed: {e}");
                    }
                }
            },
            msg = stream.next() => match msg {
                Some(msg) => {
                    let device = channel_device(msg.get_channel_name().as_bytes());
                    let decoded = BusMessage::decode(msg.get_payload_bytes());
                    if let (Some(device), Some(decoded)) = (device, decoded) {
                        hub.dispatch(&device, decoded);
                    }
                }
                None => {
                    log::warn!("redis pubsub connection lost; reconnecting");
                    (sink, stream) = reconnect(&client).await;
                    subscribed.clear();
                    for device_id in hub.registered_devices() {
                        if sink.subscribe(device_channel(&device_id)).await.is_ok() {
                            subscribed.insert(device_id);
                        }
                    }
                    hub.broadcast_resync();
                    log::info!("redis pubsub restored: {} subscriptions", subscribed.len());
                }
            },
        }
    }
}

async fn reconnect(client: &redis::Client) -> (PubSubSink, PubSubStream) {
    let mut wait = RECONNECT_MIN;
    loop {
        match client.get_async_pubsub().await {
            Ok(pubsub) => return pubsub.split(),
            Err(e) => {
                log::warn!("redis pubsub reconnect failed: {e}");
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(RECONNECT_MAX);
            }
        }
    }
}
