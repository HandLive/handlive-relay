//! Messages for the device, published by any relay instance on
//! `dev:<device_id>` (CONN-03 API 4–6, PAIR-03 API 4, SET-02 API 2).

use std::collections::HashSet;

use uuid::Uuid;

use crate::relay::bus::BusMessage;
use crate::relay::connection::{CLOSE_REPLACED, Conn, End};
use crate::relay::hub::Delivery;
use crate::relay::wire;

impl Conn {
    pub(super) async fn on_delivery(&mut self, delivery: Delivery) -> Option<End> {
        let msg = match delivery {
            Delivery::Resync => return self.resync().await,
            Delivery::Bus(msg) => msg,
        };
        let written = match msg {
            // A frame from a device that is not (or no longer) a valid peer
            // is dropped: the pair check holds on both ends.
            BusMessage::ForwardText { from, text } => {
                if !self.is_peer(&from).await {
                    return None;
                }
                self.send_text(text).await
            }
            BusMessage::ForwardBinary { from, frame } => {
                if !self.is_peer(&from).await {
                    return None;
                }
                self.send_binary(frame).await
            }
            BusMessage::Control { text } => self.send_text(text).await,
            BusMessage::PairRevoked { pair_id, by } => {
                self.reload_peers().await;
                self.send_text(wire::pair_revoked_message(&pair_id, &by))
                    .await
            }
            BusMessage::PairsChanged => self.pairs_changed().await,
            BusMessage::Replace { conn_id } if conn_id != self.conn_id => {
                return Some(End::Close(CLOSE_REPLACED));
            }
            BusMessage::Replace { .. } => Ok(()),
            BusMessage::Close { code } => return Some(End::Close(code)),
        };
        written.err()
    }

    /// Reload the pairs and send `presence` for each pair that appeared.
    async fn pairs_changed(&mut self) -> Result<(), End> {
        let before: HashSet<Uuid> = self.pairs.iter().map(|(pair_id, _)| *pair_id).collect();
        if !self.reload_peers().await {
            return Ok(());
        }
        let added: Vec<(Uuid, Uuid)> = self
            .pairs
            .iter()
            .filter(|(pair_id, _)| !before.contains(pair_id))
            .copied()
            .collect();
        let online = self.peer_presence(&added).await;
        for ((pair_id, peer), online) in added.iter().zip(online) {
            self.send_text(wire::presence_message(pair_id, peer, online))
                .await?;
        }
        Ok(())
    }

    /// After Redis lost its data: re-assert presence and reload the pairs.
    async fn resync(&mut self) -> Option<End> {
        if let Some(end) = self.refresh_presence().await {
            return Some(end);
        }
        self.reload_peers().await;
        None
    }
}
