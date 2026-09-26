//! HTTP clients for the push providers: rustls with the ring provider and
//! the operating system's trust store; APNs speaks HTTP/2 only.

use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

fn builder() -> reqwest::ClientBuilder {
    // Installing twice is harmless; the first provider stays.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
}

/// APNs requires HTTP/2 (ALPN `h2` over TLS; prior knowledge over `http://`
/// for local test servers).
pub fn apns_client() -> Result<reqwest::Client, String> {
    builder()
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("apns http client: {e}"))
}
