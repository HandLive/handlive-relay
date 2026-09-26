//! Shared application state and connection setup.

use std::sync::Arc;

use redis::aio::ConnectionManager;
use ring::rand::SystemRandom;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::config::{Config, RelaySettings};
use crate::jwt::JwtKeys;
use crate::relay::hub::Hub;
use crate::usage::Usage;

pub struct AppState {
    pub db: PgPool,
    pub redis: ConnectionManager,
    pub jwt: JwtKeys,
    pub rng: SystemRandom,
    pub hub: Arc<Hub>,
    pub usage: Usage,
    pub settings: RelaySettings,
}

impl AppState {
    /// Connect to PostgreSQL and Redis and start the relay bus task on the
    /// current runtime. Does not run migrations.
    pub async fn connect(config: &Config) -> Result<Self, String> {
        let jwt = JwtKeys::from_secret(&config.jwt_secret)?;
        let db = PgPoolOptions::new()
            .max_connections(10)
            .connect(&config.database_url)
            .await
            .map_err(|e| format!("postgres connect: {e}"))?;
        let client = redis::Client::open(config.redis_url.as_str())
            .map_err(|e| format!("redis url: {e}"))?;
        let redis = ConnectionManager::new(client.clone())
            .await
            .map_err(|e| format!("redis connect: {e}"))?;
        let hub = Hub::start(client, redis.clone(), config.settings.max_queued_bytes).await?;
        Ok(Self {
            db,
            redis,
            jwt,
            rng: SystemRandom::new(),
            hub,
            usage: Usage::default(),
            settings: config.settings.clone(),
        })
    }
}
