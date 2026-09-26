//! The relay channel `GET /v1/relay` (CONN-03 API 4–6, PAIR-01 API 7,
//! PAIR-03 API 4): routing between devices of a valid pair, presence,
//! rendezvous and revocation notices, across instances through Redis (C5).

pub mod bandwidth;
pub mod bus;
pub mod connection;
pub mod hub;
mod inbound;
mod outbound;
pub mod presence;
pub mod rendezvous;
pub mod wire;
