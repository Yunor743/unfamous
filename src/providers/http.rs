//! Shared HTTP plumbing: timeouts, retry with jittered backoff, rate
//! limiting, and HTTP status to provider outcome mapping.

use std::time::Duration;

use rand::Rng;

#[derive(Debug, Clone)]
pub enum HttpOutcome {
    Ok(Vec<u8>),
    NotFound,
    AuthFailure,
    RateLimited,
    Transient(String),
    Fatal(String),
}

#[derive(Debug)]
pub struct RateLimiter {
    limit: u32,
    state: tokio::sync::Mutex<RateState>,
}

#[derive(Debug, Clone)]
struct RateState {
    window_start: std::time::Instant,
    used: u32,
}

impl RateLimiter {
    #[must_use]
    pub fn new(limit_per_minute: u32) -> Self {
        Self {
            limit: limit_per_minute.max(1),
            state: tokio::sync::Mutex::new(RateState {
                window_start: std::time::Instant::now(),
                used: 0,
            }),
        }
    }

    /// Reserve one slot, sleeping until the current minute window allows it.
    pub async fn acquire(&self) {
        loop {
            let wait = {
                let mut state = self.state.lock().await;
                let elapsed = state.window_start.elapsed();
                if elapsed >= Duration::from_secs(60) {
                    state.window_start = std::time::Instant::now();
                    state.used = 0;
                }
                if state.used < self.limit {
                    state.used += 1;
                    None
                } else {
                    Some(
                        Duration::from_secs(60).checked_sub(elapsed).unwrap()
                            + Duration::from_millis(50),
                    )
                }
            };
            match wait {
                None => return,
                Some(d) => tokio::time::sleep(d).await,
            }
        }
    }
}

#[must_use]
pub fn build_client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("unfamous/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("static reqwest client configuration")
}

/// Map a transport or HTTP status into a provider-agnostic outcome.
fn classify_response(status: u16) -> HttpOutcome {
    match status {
        200..=299 => HttpOutcome::Ok(Vec::new()),
        404 => HttpOutcome::NotFound,
        401 | 403 => HttpOutcome::AuthFailure,
        429 => HttpOutcome::RateLimited,
        500..=599 => HttpOutcome::Transient(format!("HTTP {status}")),
        _ => HttpOutcome::Fatal(format!("unexpected HTTP status {status}")),
    }
}

pub async fn send_with_retry(
    limiter: &RateLimiter,
    retries: u32,
    request: impl Fn() -> reqwest::RequestBuilder,
) -> HttpOutcome {
    let mut attempt = 0u32;
    loop {
        limiter.acquire().await;
        let result = send_once(request()).await;
        match result {
            HttpOutcome::Transient(_) | HttpOutcome::RateLimited if attempt < retries => {
                attempt += 1;
                let base = 2u64.saturating_pow(attempt);
                let jitter = rand::thread_rng().gen_range(0..=500);
                tokio::time::sleep(Duration::from_millis(base * 250 + jitter)).await;
            }
            other => return other,
        }
    }
}

async fn send_once(request: reqwest::RequestBuilder) -> HttpOutcome {
    match request.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let outcome = classify_response(status);
            match outcome {
                HttpOutcome::Ok(_) => match resp.bytes().await {
                    Ok(body) => HttpOutcome::Ok(body.to_vec()),
                    Err(e) => HttpOutcome::Transient(format!("body read failed: {e}")),
                },
                other => other,
            }
        }
        Err(e) => {
            if e.is_timeout() {
                HttpOutcome::Transient(format!("request timeout: {e}"))
            } else if e.is_connect() || e.is_request() {
                HttpOutcome::Transient(format!("connection failure: {e}"))
            } else {
                HttpOutcome::Fatal(format!("request failed: {e}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_classification() {
        assert!(matches!(classify_response(200), HttpOutcome::Ok(_)));
        assert!(matches!(classify_response(404), HttpOutcome::NotFound));
        assert!(matches!(classify_response(401), HttpOutcome::AuthFailure));
        assert!(matches!(classify_response(429), HttpOutcome::RateLimited));
        assert!(matches!(classify_response(503), HttpOutcome::Transient(_)));
        assert!(matches!(classify_response(418), HttpOutcome::Fatal(_)));
    }

    #[tokio::test]
    async fn rate_limiter_admits_below_limit() {
        let limiter = RateLimiter::new(10);
        for _ in 0..10 {
            limiter.acquire().await;
        }
    }
}
