//! One `/v1/relay` connection (CONN-03 API 4): opening, the event loop and
//! cleanup. Frames from the device are handled in `inbound`, messages for it
//! in `outbound`.
//!
//! Close codes (spec 0.8.3): 1000 the device removed itself, 4400 protocol
//! error, 4409 replaced by a newer connection, 4411 idle, 4500 internal.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use actix_web::web;
use actix_ws::{AggregatedMessage, AggregatedMessageStream, CloseCode, CloseReason, Session};
use tokio::sync::{Notify, mpsc};
use tokio::time::{MissedTickBehavior, interval_at, sleep_until};
use uuid::Uuid;

use crate::relay::bandwidth::TokenBucket;
use crate::relay::bus::BusMessage;
use crate::relay::hub::{Delivery, LocalConn};
use crate::relay::{presence, wire};
use crate::state::AppState;
use crate::store::pairs;

/// A write to a device that takes longer than this ends the connection.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Least time between two peer reloads caused by an unknown peer.
const MISS_RELOAD_GAP: Duration = Duration::from_secs(1);

pub const CLOSE_NORMAL: u16 = 1000;
pub const CLOSE_BAD_REQUEST: u16 = 4400;
pub const CLOSE_REPLACED: u16 = 4409;
pub const CLOSE_IDLE: u16 = 4411;
pub const CLOSE_INTERNAL: u16 = 4500;

/// Why the loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum End {
    /// The device closed or the socket is gone: nothing more to send.
    Gone,
    /// The device sent a close frame: answer it.
    ClientClosed,
    /// Close with this code.
    Close(u16),
}

/// A frame held back by the bandwidth limit.
pub(super) struct Pending {
    pub to: Uuid,
    pub bus: BusMessage,
    pub bytes: usize,
    pub deadline: Instant,
}

pub(super) struct Conn {
    pub state: web::Data<AppState>,
    pub device_id: Uuid,
    pub conn_id: Uuid,
    pub session: Session,
    /// Valid pairs `(pair_id, peer_device_id)` and the reachable peers.
    pub pairs: Vec<(Uuid, Uuid)>,
    pub peers: HashSet<Uuid>,
    pub buckets: HashMap<Uuid, TokenBucket>,
    pub pending: Option<Pending>,
    pub last_miss_reload: Option<Instant>,
}

/// Serve one upgraded connection until it ends, then clean up.
pub async fn run(
    state: web::Data<AppState>,
    device_id: Uuid,
    session: Session,
    mut stream: AggregatedMessageStream,
) {
    let conn_id = Uuid::new_v4();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let queued = Arc::new(AtomicUsize::new(0));
    let kill = Arc::new(Notify::new());
    let local = LocalConn {
        conn_id,
        tx,
        queued: queued.clone(),
        kill: kill.clone(),
    };
    if let Some(previous) = state.hub.register(device_id, local) {
        let _ = previous
            .tx
            .send(Delivery::Bus(BusMessage::Replace { conn_id }));
    }
    let mut conn = Conn {
        state,
        device_id,
        conn_id,
        session,
        pairs: Vec::new(),
        peers: HashSet::new(),
        buckets: HashMap::new(),
        pending: None,
        last_miss_reload: None,
    };
    let end = match conn.open().await {
        Ok(()) => conn.serve(&mut stream, &mut rx, &queued, &kill).await,
        Err(code) => End::Close(code),
    };
    conn.finish(end).await;
}

impl Conn {
    /// Subscribe, take over from older connections, publish presence and
    /// send the opening messages (CONN-03 API 4).
    async fn open(&mut self) -> Result<(), u16> {
        let state = self.state.clone();
        if !state.hub.subscribe(self.device_id).await {
            return Err(CLOSE_INTERNAL);
        }
        let replace = BusMessage::Replace {
            conn_id: self.conn_id,
        };
        let instance = &state.settings.instance_id;
        // Presence first: an older connection on another instance that is
        // told to close then finds the presence taken and stays silent.
        let setup = async {
            presence::claim(&state.redis, &self.device_id, instance).await?;
            state
                .hub
                .publish(&self.device_id, &replace)
                .await
                .map(|_| ())
        };
        if let Err(e) = setup.await {
            log::warn!("relay connection setup failed: {e}");
            return Err(CLOSE_INTERNAL);
        }
        if !self.reload_peers().await {
            return Err(CLOSE_INTERNAL);
        }
        let online = self.peer_presence(&self.pairs.clone()).await;
        for ((pair_id, peer), online) in self.pairs.clone().iter().zip(online) {
            self.send_text(wire::presence_message(pair_id, peer, online))
                .await
                .map_err(|_| CLOSE_INTERNAL)?;
        }
        let revoked = pairs::recently_revoked(&state.db, self.device_id)
            .await
            .map_err(|e| log::warn!("revoked pairs lookup failed: {e}"))
            .unwrap_or_default();
        let notices = presence::take_revoked_notices(&state.redis, &self.device_id)
            .await
            .map_err(|e| log::warn!("revoked notices lookup failed: {e}"))
            .unwrap_or_default();
        for (pair_id, by) in revoked.iter().chain(notices.iter()) {
            self.send_text(wire::pair_revoked_message(pair_id, by))
                .await
                .map_err(|_| CLOSE_INTERNAL)?;
        }
        self.announce(true).await;
        Ok(())
    }

    async fn serve(
        &mut self,
        stream: &mut AggregatedMessageStream,
        rx: &mut mpsc::UnboundedReceiver<Delivery>,
        queued: &AtomicUsize,
        kill: &Notify,
    ) -> End {
        let settings = self.state.settings.clone();
        let start = tokio::time::Instant::now();
        let mut ping = interval_at(start + settings.ping_interval, settings.ping_interval);
        let mut refresh = interval_at(start + settings.presence_refresh, settings.presence_refresh);
        ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
        refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut last_rx = Instant::now();
        loop {
            let deadline = self.pending.as_ref().map(|p| p.deadline);
            let result = tokio::select! {
                biased;
                _ = kill.notified() => Some(End::Close(CLOSE_INTERNAL)),
                delivery = rx.recv() => match delivery {
                    None => Some(End::Close(CLOSE_INTERNAL)),
                    Some(delivery) => {
                        if let Delivery::Bus(msg) = &delivery {
                            queued.fetch_sub(msg.queued_len(), Ordering::AcqRel);
                        }
                        self.on_delivery(delivery).await
                    }
                },
                _ = sleep_until(deadline.unwrap_or_else(Instant::now).into()), if deadline.is_some() => {
                    match self.pending.take() {
                        Some(p) => self.publish_forward(p).await,
                        None => None,
                    }
                },
                msg = stream.recv(), if deadline.is_none() => {
                    last_rx = Instant::now();
                    match msg {
                        None => Some(End::Gone),
                        Some(Err(_)) => Some(End::Close(CLOSE_BAD_REQUEST)),
                        Some(Ok(msg)) => self.on_client_message(msg).await,
                    }
                },
                _ = ping.tick() => {
                    if last_rx.elapsed() >= settings.idle_timeout {
                        Some(End::Close(CLOSE_IDLE))
                    } else if self.session.ping(b"").await.is_err() {
                        Some(End::Gone)
                    } else {
                        None
                    }
                },
                _ = refresh.tick() => self.refresh_presence().await,
            };
            if let Some(end) = result {
                return end;
            }
        }
    }

    async fn on_client_message(&mut self, msg: AggregatedMessage) -> Option<End> {
        match msg {
            AggregatedMessage::Text(text) => self.handle_text(&text).await,
            AggregatedMessage::Binary(bytes) => self.handle_binary(&bytes).await,
            AggregatedMessage::Ping(bytes) => {
                self.session.pong(&bytes).await.err().map(|_| End::Gone)
            }
            AggregatedMessage::Pong(_) => None,
            AggregatedMessage::Close(_) => Some(End::ClientClosed),
        }
    }

    /// Renew presence; a newer connection elsewhere means this one is stale.
    pub(super) async fn refresh_presence(&mut self) -> Option<End> {
        let state = self.state.clone();
        match presence::refresh(&state.redis, &self.device_id, &state.settings.instance_id).await {
            Ok(true) => None,
            Ok(false) => Some(End::Close(CLOSE_REPLACED)),
            Err(e) => {
                log::warn!("presence refresh failed: {e}");
                None
            }
        }
    }

    /// Reload the valid pairs from the database; `false` on a database error.
    pub(super) async fn reload_peers(&mut self) -> bool {
        match pairs::active_peers(&self.state.db, self.device_id).await {
            Ok(pairs) => {
                self.peers = pairs.iter().map(|(_, peer)| *peer).collect();
                self.buckets.retain(|peer, _| self.peers.contains(peer));
                self.pairs = pairs;
                true
            }
            Err(e) => {
                log::warn!("peer lookup failed: {e}");
                false
            }
        }
    }

    /// Whether `peer` may exchange frames with this device, reloading the
    /// pairs (at most once a second) when it is unknown.
    pub(super) async fn is_peer(&mut self, peer: &Uuid) -> bool {
        if self.peers.contains(peer) {
            return true;
        }
        let now = Instant::now();
        if self
            .last_miss_reload
            .is_some_and(|t| now.duration_since(t) < MISS_RELOAD_GAP)
        {
            return false;
        }
        self.last_miss_reload = Some(now);
        self.reload_peers().await && self.peers.contains(peer)
    }

    /// Online state of the peers of `pairs` (offline when Redis fails).
    pub(super) async fn peer_presence(&self, pairs: &[(Uuid, Uuid)]) -> Vec<bool> {
        let peers: Vec<Uuid> = pairs.iter().map(|(_, peer)| *peer).collect();
        presence::online(&self.state.redis, &peers)
            .await
            .unwrap_or_else(|_| vec![false; peers.len()])
    }

    /// Tell every peer that this device came online or went offline.
    async fn announce(&self, online: bool) {
        for (pair_id, peer) in &self.pairs {
            let text = wire::presence_message(pair_id, &self.device_id, online);
            if let Err(e) = self
                .state
                .hub
                .publish(peer, &BusMessage::Control { text })
                .await
            {
                log::warn!("presence publish failed: {e}");
            }
        }
    }

    pub(super) async fn send_text(&mut self, text: String) -> Result<(), ()> {
        match tokio::time::timeout(WRITE_TIMEOUT, self.session.text(text)).await {
            Ok(Ok(())) => Ok(()),
            _ => Err(()),
        }
    }

    pub(super) async fn send_binary(&mut self, bytes: Vec<u8>) -> Result<(), ()> {
        match tokio::time::timeout(WRITE_TIMEOUT, self.session.binary(bytes)).await {
            Ok(Ok(())) => Ok(()),
            _ => Err(()),
        }
    }

    /// Send the relay `error` op; a failed write ends the connection.
    pub(super) async fn send_error(
        &mut self,
        err: wire::RelayError,
        to: Option<&Uuid>,
    ) -> Option<End> {
        self.send_text(wire::error_message(err, to))
            .await
            .err()
            .map(|_| End::Gone)
    }

    /// Leave the registry, drop presence if it is still ours and tell the
    /// peers, then close the socket.
    async fn finish(self, end: End) {
        let state = self.state.clone();
        if state.hub.unregister(&self.device_id, &self.conn_id) {
            state.hub.unsubscribe(self.device_id);
            let released =
                presence::release(&state.redis, &self.device_id, &state.settings.instance_id).await;
            if matches!(released, Ok(true)) {
                self.announce(false).await;
            }
        }
        let reason = match end {
            End::Gone => return,
            End::ClientClosed => None,
            End::Close(code) => Some(CloseReason {
                code: CloseCode::Other(code),
                description: None,
            }),
        };
        let reason = reason.or(Some(CloseReason {
            code: CloseCode::Normal,
            description: None,
        }));
        let _ = tokio::time::timeout(WRITE_TIMEOUT, self.session.close(reason)).await;
    }
}
