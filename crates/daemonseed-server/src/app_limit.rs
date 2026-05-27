//! Per-connection request rate limiting as a tower middleware (ISC-S17 / M9).
//!
//! [`RequestRateLayer`] wraps the application service served over a single
//! Authenticated connection and charges one [`ConnectionLimiter`] request token
//! per inbound RPC ([`ConnectionLimiter::try_request_at`]). When the bucket is
//! empty the middleware does **not** return a status — it resolves to an error,
//! which the underlying h2 server treats as a connection-level failure and
//! drops the connection (the peer sees only a reset). This is the **uniform
//! close** of ISC-A-S12: identical to an identity-proof failure or a per-key cap
//! trip, the peer cannot tell which budget it exhausted, or whether a limiter
//! was involved at all.
//!
//! The layer is request-agnostic (generic over the request type), so it composes
//! over tonic's routed service without depending on the HTTP/body types. The
//! limiter is owned per-connection: [`crate::public_space::serve_application`]
//! constructs one `Arc<Mutex<ConnectionLimiter>>` per invocation (one
//! connection) and shares it between this layer and the CoT subscribe handler.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use tower::{Layer, Service};

use crate::rate_limit::ConnectionLimiter;

/// Boxed error that drops the connection when returned from the service (the
/// uniform close, ISC-A-S12). Carries no reason — nothing is written to the wire.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A tower [`Layer`] charging one request token per RPC against a shared
/// per-connection [`ConnectionLimiter`] (ISC-S17 request-rate budget).
#[derive(Clone)]
pub struct RequestRateLayer {
    limiter: Arc<Mutex<ConnectionLimiter>>,
}

impl RequestRateLayer {
    /// Wrap services so each request charges the shared limiter.
    pub fn new(limiter: Arc<Mutex<ConnectionLimiter>>) -> Self {
        Self { limiter }
    }
}

impl<S> Layer<S> for RequestRateLayer {
    type Service = RequestRateService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestRateService {
            inner,
            limiter: Arc::clone(&self.limiter),
        }
    }
}

/// The service produced by [`RequestRateLayer`]. Charges the token bucket before
/// delegating; on an empty bucket it errors (dropping the connection) rather
/// than calling the inner service.
#[derive(Clone)]
pub struct RequestRateService<S> {
    inner: S,
    limiter: Arc<Mutex<ConnectionLimiter>>,
}

impl<S, R> Service<R> for RequestRateService<S>
where
    S: Service<R>,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
    S::Response: 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: R) -> Self::Future {
        // Charge one request token. A poisoned mutex means a prior panic on this
        // connection — fail closed (drop) rather than serve unmetered.
        let admitted = self
            .limiter
            .lock()
            .map(|mut l| l.try_request_at(Instant::now()).is_ok())
            .unwrap_or(false);
        if admitted {
            let fut = self.inner.call(req);
            Box::pin(async move { fut.await.map_err(Into::into) })
        } else {
            // Uniform close (ISC-A-S12): error the connection, no wire reason.
            Box::pin(async move { Err("rate".into()) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::RateLimitConfig;

    /// A trivial inner service that always succeeds, to exercise the layer.
    #[derive(Clone)]
    struct Ok200;
    impl Service<()> for Ok200 {
        type Response = ();
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send>>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _req: ()) -> Self::Future {
            Box::pin(async { Ok(()) })
        }
    }

    fn limiter(burst: u32) -> Arc<Mutex<ConnectionLimiter>> {
        Arc::new(Mutex::new(ConnectionLimiter::new(RateLimitConfig {
            req_burst: burst,
            // No refill within the test window — exercise the burst cap exactly.
            req_per_sec: 0,
            ..RateLimitConfig::default()
        })))
    }

    /// The layer admits up to `req_burst` requests, then errors (drops the
    /// connection) on the next one (ISC-29 / ISC-A-S12).
    #[tokio::test]
    async fn admits_burst_then_drops() {
        let mut svc = RequestRateLayer::new(limiter(3)).layer(Ok200);
        for i in 0..3 {
            std::future::poll_fn(|cx| svc.poll_ready(cx))
                .await
                .expect("ready");
            assert!(svc.call(()).await.is_ok(), "request {i} within burst");
        }
        // The 4th request finds an empty bucket → error (connection drop).
        assert!(
            svc.call(()).await.is_err(),
            "request past the burst drops the connection"
        );
    }

    /// The error carries no descriptive reason — nothing a peer could read to
    /// learn which budget tripped (ISC-A-S12).
    #[tokio::test]
    async fn drop_error_leaks_no_budget() {
        let mut svc = RequestRateLayer::new(limiter(0)).layer(Ok200);
        let err = svc.call(()).await.unwrap_err();
        let msg = err.to_string().to_lowercase();
        for forbidden in [
            "bucket",
            "token",
            "subscription",
            "limit",
            "budget",
            "bandwidth",
        ] {
            assert!(
                !msg.contains(forbidden),
                "error leaks '{forbidden}': {msg:?}"
            );
        }
    }
}
