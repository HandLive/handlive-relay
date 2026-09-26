//! Frames from the device (CONN-03 API 6, PAIR-01 API 7): routing wrappers,
//! `HR` binary frames and the `rv_join` / `rv_msg` control ops.
//!
//! Only the wrapper is read: `env` is copied without being parsed (except
//! the `type` of rendezvous envelopes), and nothing about it is logged.

use std::time::Instant;

use serde_json::value::RawValue;
use uuid::Uuid;

use crate::relay::bandwidth::TokenBucket;
use crate::relay::bus::BusMessage;
use crate::relay::connection::{Conn, End, Pending};
use crate::relay::rendezvous::{self, Join};
use crate::relay::wire::{self, RelayError};

impl Conn {
    pub(super) async fn handle_text(&mut self, text: &str) -> Option<End> {
        let Some(inbound) = wire::parse_inbound(text) else {
            return self.send_error(RelayError::BadRequest, None).await;
        };
        if text.len() > wire::MAX_FRAME_BYTES {
            let to = inbound.to;
            return self
                .send_error(RelayError::PayloadTooLarge, to.as_ref())
                .await;
        }
        match inbound.op.as_deref() {
            Some("rv_join") => self.rv_join(inbound.rv_id.as_deref()).await,
            Some("rv_msg") => self.rv_msg(inbound.rv_id.as_deref(), inbound.env).await,
            Some(_) => self.send_error(RelayError::BadRequest, None).await,
            None => match (inbound.to, inbound.env) {
                (Some(to), _) if !wire::is_device_id(&to) => {
                    self.send_error(RelayError::BadRequest, None).await
                }
                (Some(to), Some(env)) if wire::is_object(env) => {
                    let bus = BusMessage::ForwardText {
                        from: self.device_id,
                        text: wire::forwarded_text(&self.device_id, env),
                    };
                    self.forward(to, bus, text.len()).await
                }
                // A malformed wrapper never echoes its `to` (CONN-03 API 6 logic 1).
                _ => self.send_error(RelayError::BadRequest, None).await,
            },
        }
    }

    pub(super) async fn handle_binary(&mut self, frame: &[u8]) -> Option<End> {
        let Some(to) = wire::parse_hr(frame).filter(wire::is_device_id) else {
            return self.send_error(RelayError::BadRequest, None).await;
        };
        if frame.len() > wire::MAX_FRAME_BYTES {
            return self
                .send_error(RelayError::PayloadTooLarge, Some(&to))
                .await;
        }
        let bus = BusMessage::ForwardBinary {
            from: self.device_id,
            frame: wire::rewrite_hr(frame, &self.device_id),
        };
        self.forward(to, bus, frame.len()).await
    }

    /// Check the pair, then publish now or after the bandwidth wait.
    async fn forward(&mut self, to: Uuid, bus: BusMessage, bytes: usize) -> Option<End> {
        if !self.is_peer(&to).await {
            return self.send_error(RelayError::NotPaired, Some(&to)).await;
        }
        let now = Instant::now();
        let rate = self.state.settings.pair_bandwidth_bytes_per_sec;
        let wait = self
            .buckets
            .entry(to)
            .or_insert_with(|| TokenBucket::new(rate, now))
            .take(bytes, now);
        let pending = Pending {
            to,
            bus,
            bytes,
            deadline: now + wait,
        };
        if wait.is_zero() {
            self.publish_forward(pending).await
        } else {
            self.pending = Some(pending);
            None
        }
    }

    /// Publish a forwarded frame to `dev:<to>`; nobody subscribed means the
    /// peer is not connected (CONN-03 API 6 logic 3).
    pub(super) async fn publish_forward(&mut self, p: Pending) -> Option<End> {
        let state = self.state.clone();
        match state.hub.publish(&p.to, &p.bus).await {
            Ok(0) => self.send_error(RelayError::NotConnected, Some(&p.to)).await,
            Ok(_) => {
                state.usage.add_envelope(self.device_id, p.bytes);
                None
            }
            Err(e) => {
                log::warn!("relay publish failed: {e}");
                self.send_error(RelayError::NotConnected, Some(&p.to)).await
            }
        }
    }

    async fn rv_join(&mut self, rv_id: Option<&str>) -> Option<End> {
        let Some(rv_id) = rv_id.and_then(rendezvous::canonical_rv_id) else {
            return self.send_error(RelayError::BadRequest, None).await;
        };
        let state = self.state.clone();
        let joined = match rendezvous::join(&state.redis, &rv_id, &self.device_id).await {
            Ok(Join::Joined { newly, members }) => (newly, members),
            Ok(Join::Full) => return self.send_error(RelayError::BadRequest, None).await,
            Err(e) => {
                log::warn!("rendezvous join failed: {e}");
                return self.send_error(RelayError::NotConnected, None).await;
            }
        };
        let (newly, members) = joined;
        let peer_present = members.len() == 2;
        if let Err(end) = self
            .send_text(wire::rv_joined_message(&rv_id, peer_present))
            .await
        {
            return Some(end);
        }
        if peer_present && newly {
            let text = wire::rv_joined_message(&rv_id, true);
            for other in members.iter().filter(|m| **m != self.device_id) {
                let control = BusMessage::Control { text: text.clone() };
                if let Err(e) = state.hub.publish(other, &control).await {
                    log::warn!("rendezvous notify failed: {e}");
                }
            }
        }
        None
    }

    async fn rv_msg(&mut self, rv_id: Option<&str>, env: Option<&RawValue>) -> Option<End> {
        let (Some(rv_id), Some(env)) = (rv_id.and_then(rendezvous::canonical_rv_id), env) else {
            return self.send_error(RelayError::BadRequest, None).await;
        };
        if !wire::is_object(env) || !rendezvous::rendezvous_allows(env) {
            return self.send_error(RelayError::BadRequest, None).await;
        }
        let state = self.state.clone();
        let members = match rendezvous::members(&state.redis, &rv_id).await {
            Ok(members) => members,
            Err(e) => {
                log::warn!("rendezvous lookup failed: {e}");
                return self.send_error(RelayError::NotConnected, None).await;
            }
        };
        if !members.contains(&self.device_id) {
            return self.send_error(RelayError::BadRequest, None).await;
        }
        let Some(other) = members.into_iter().find(|m| *m != self.device_id) else {
            return self.send_error(RelayError::NotConnected, None).await;
        };
        let control = BusMessage::Control {
            text: wire::rv_msg_message(&rv_id, env),
        };
        match state.hub.publish(&other, &control).await {
            Ok(0) => self.send_error(RelayError::NotConnected, None).await,
            Ok(_) => None,
            Err(e) => {
                log::warn!("rendezvous publish failed: {e}");
                self.send_error(RelayError::NotConnected, None).await
            }
        }
    }
}
