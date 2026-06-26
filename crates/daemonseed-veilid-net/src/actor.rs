//! The [`VeilidNet`] actor — a spawned task owning the `VeilidAPI` +
//! `RoutingContext`, driven through a command channel via [`VeilidNetHandle`].
//! Inbound `VeilidUpdate`s are mapped to typed [`VeilidNetEvent`]s on a
//! separate stream the app/UI consumes.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use veilid_core::{
    api_startup, RouteBlob, RouteId, RoutingContext, SafetySelection, Sequencing, Target,
    VeilidAPI, VeilidConfig, VeilidUpdate,
};

use crate::config::VeilidNetConfig;
use crate::error::{Result, VeilidNetError};
use crate::event::VeilidNetEvent;
use crate::identity;

/// Veilid's `app_message` / `app_call` payload cap (bytes). Sealed envelopes
/// must fit; file-share chunks re-chunk to this in Phase 3.
pub const APP_MESSAGE_CAP: usize = 32768;

/// Commands the [`VeilidNetHandle`] sends to the actor task. Each carries a
/// `oneshot` reply so the caller awaits the result.
enum Command {
    Attach {
        timeout_secs: u64,
        reply: oneshot::Sender<Result<()>>,
    },
    NewInboundRoute {
        reply: oneshot::Sender<Result<RouteBlob>>,
    },
    ImportRoute {
        blob: Vec<u8>,
        reply: oneshot::Sender<Result<RouteId>>,
    },
    SendSealed {
        route: RouteId,
        sealed: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

/// A cloneable handle to the running actor. Every transport operation goes
/// through here; the actor task serializes access to the single `VeilidAPI`.
/// This is the shape the app/UI drives (the `AppSession` replacement).
#[derive(Clone)]
pub struct VeilidNetHandle {
    cmd_tx: mpsc::Sender<Command>,
}

impl VeilidNetHandle {
    /// Send a command and await its `oneshot` reply, surfacing a clean error if
    /// the actor task is gone.
    async fn send<T>(&self, make: impl FnOnce(oneshot::Sender<T>) -> Command) -> Result<T> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(make(tx))
            .await
            .map_err(|_| VeilidNetError::Actor("actor task is gone".into()))?;
        rx.await
            .map_err(|_| VeilidNetError::Actor("actor dropped the reply".into()))
    }

    /// Attach and wait until the node is public-internet-ready (D4).
    pub async fn attach_and_wait(&self, timeout_secs: u64) -> Result<()> {
        self.send(|reply| Command::Attach {
            timeout_secs,
            reply,
        })
        .await?
    }

    /// Allocate a private inbound route. The returned blob is what a peer
    /// addresses — it never exposes our node id or IP (anti-dox receiver side).
    pub async fn new_inbound_route(&self) -> Result<RouteBlob> {
        self.send(|reply| Command::NewInboundRoute { reply })
            .await?
    }

    /// Import a peer's private-route blob, returning the route id to send to.
    pub async fn import_route(&self, blob: Vec<u8>) -> Result<RouteId> {
        self.send(|reply| Command::ImportRoute { blob, reply })
            .await?
    }

    /// Send a SEALED message over a private route (the proven 1:1 path).
    /// `sealed` is daemonseed's opaque AES-256-GCM envelope; this layer never
    /// holds the plaintext or the content key.
    pub async fn send_sealed(&self, route: RouteId, sealed: Vec<u8>) -> Result<()> {
        self.send(|reply| Command::SendSealed {
            route,
            sealed,
            reply,
        })
        .await?
    }

    /// Shut the node down cleanly.
    pub async fn shutdown(&self) {
        let _ = self.send(|reply| Command::Shutdown { reply }).await;
    }

    // ── Phase 2+ surface (not built yet; mechanics characterized in Phase 0) ──
    // Signposts only: these return Unimplemented without touching the actor, so
    // the command set stays the Phase-1 proven path.

    /// Publish a sealed message to a circle's DHT rendezvous record (`SMPL`,
    /// owner derived from the circle `cot_key`). **Phase 2.**
    pub async fn publish_circle(&self, _circle_cot_key: &[u8], _sealed: Vec<u8>) -> Result<()> {
        Err(VeilidNetError::Unimplemented(
            "circles (DHT/SMPL) — Phase 2",
        ))
    }

    /// Watch a circle's DHT record for member writes (eventual, ~tens of
    /// seconds — fine for membership/announcements, not typing). **Phase 2.**
    pub async fn subscribe_circle(&self, _circle_cot_key: &[u8]) -> Result<()> {
        Err(VeilidNetError::Unimplemented("circle subscribe — Phase 2"))
    }

    /// Announce a public share; chunks served owner-on-demand, re-chunked to
    /// ≤32 KiB. **Phase 3.**
    pub async fn publish_share(&self) -> Result<()> {
        Err(VeilidNetError::Unimplemented("public shares — Phase 3"))
    }

    /// Member-plane presence heartbeat over the sealed circle. **Phase 4.**
    pub async fn presence(&self) -> Result<()> {
        Err(VeilidNetError::Unimplemented("presence — Phase 4"))
    }
}

/// Brings up the daemonseed Veilid transport node.
///
/// Phase 1 implements the PROVEN 1:1 path: identity-bound node, private routes,
/// sealed `app_message`. Circles (DHT/`SMPL`), shares, presence, and
/// announcements are Phase 2+ ([`VeilidNetHandle`] signposts them).
pub struct VeilidNet;

impl VeilidNet {
    /// Bring up the node with a daemonseed-derived identity (D3), spawn the
    /// actor task, and return a [`VeilidNetHandle`] plus a stream of typed
    /// events. Does NOT attach — call [`VeilidNetHandle::attach_and_wait`].
    pub async fn start(
        cfg: VeilidNetConfig,
    ) -> Result<(VeilidNetHandle, mpsc::UnboundedReceiver<VeilidNetEvent>)> {
        std::fs::create_dir_all(&cfg.storage_dir).ok();

        let (ev_tx, ev_rx) = mpsc::unbounded_channel::<VeilidNetEvent>();
        let update_callback: Arc<dyn Fn(VeilidUpdate) + Send + Sync> =
            Arc::new(move |u: VeilidUpdate| {
                if let Some(ev) = map_update(u) {
                    let _ = ev_tx.send(ev);
                }
            });

        let mut vcfg = VeilidConfig::new(
            "daemonseed_veilid_net",
            "daemonseed",
            "net",
            Some(&cfg.storage_dir),
            None,
        );
        vcfg.namespace = cfg.namespace.clone();
        vcfg.protected_store.always_use_insecure_storage = true;
        vcfg.protected_store.allow_insecure_fallback = true;
        // D4: public network — no network_key_password. Override bootstrap only
        // if the caller baked one in (the fra1 seed).
        if !cfg.bootstrap.is_empty() {
            vcfg.network.routing_table.bootstrap = cfg.bootstrap.clone();
        }
        // D3: pin the daemonseed-derived node identity.
        let (pks, sks) = identity::identity_groups(&cfg.identity_seed)?;
        vcfg.network.routing_table.public_keys = pks;
        vcfg.network.routing_table.secret_keys = sks;

        let api = api_startup(update_callback, vcfg)
            .await
            .map_err(|e| VeilidNetError::Startup(e.to_string()))?;
        // Phase 1 uses the spike-proven Unsafe routing context (no safety
        // route). D5 — turning the safety route ON with cfg.hop_count — is the
        // planned dial-up once the productized path is green live; cfg.hop_count
        // is carried for it.
        let rc = api
            .routing_context()
            .and_then(|rc| rc.with_safety(SafetySelection::Unsafe(Sequencing::PreferOrdered)))
            .map_err(|e| VeilidNetError::Routing(e.to_string()))?;

        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(64);
        tokio::spawn(actor_loop(api, rc, cmd_rx));
        Ok((VeilidNetHandle { cmd_tx }, ev_rx))
    }
}

/// The actor task: owns the `VeilidAPI` + `RoutingContext` and processes
/// commands until `Shutdown` or the command channel closes.
async fn actor_loop(api: VeilidAPI, rc: RoutingContext, mut cmd_rx: mpsc::Receiver<Command>) {
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            Command::Attach {
                timeout_secs,
                reply,
            } => {
                let _ = reply.send(attach_and_wait(&api, timeout_secs).await);
            }
            Command::NewInboundRoute { reply } => {
                let res = api
                    .new_private_route()
                    .await
                    .map_err(|e| VeilidNetError::Routing(e.to_string()));
                let _ = reply.send(res);
            }
            Command::ImportRoute { blob, reply } => {
                let res = api
                    .import_remote_private_route(blob)
                    .map_err(|e| VeilidNetError::Routing(e.to_string()));
                let _ = reply.send(res);
            }
            Command::SendSealed {
                route,
                sealed,
                reply,
            } => {
                let _ = reply.send(send_sealed(&rc, route, sealed).await);
            }
            Command::Shutdown { reply } => {
                api.shutdown().await;
                let _ = reply.send(());
                return;
            }
        }
    }
    // Channel closed without an explicit Shutdown — clean up the node.
    api.shutdown().await;
}

/// Attach and poll until public-internet-ready or the deadline elapses.
async fn attach_and_wait(api: &VeilidAPI, timeout_secs: u64) -> Result<()> {
    api.attach()
        .await
        .map_err(|e| VeilidNetError::Startup(e.to_string()))?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let attachment = api
            .get_state()
            .await
            .map_err(|e| VeilidNetError::Startup(e.to_string()))?
            .attachment;
        if attachment.public_internet_ready {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(VeilidNetError::NotReady);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Send a sealed envelope over a private route, enforcing the `app_message` cap.
async fn send_sealed(rc: &RoutingContext, route: RouteId, sealed: Vec<u8>) -> Result<()> {
    if sealed.len() > APP_MESSAGE_CAP {
        return Err(VeilidNetError::Send(format!(
            "sealed {} bytes exceeds the {APP_MESSAGE_CAP}-byte app_message cap (re-chunk)",
            sealed.len()
        )));
    }
    rc.app_message(Target::RouteId(route), sealed)
        .await
        .map_err(|e| VeilidNetError::Send(e.to_string()))
}

/// Map a raw `VeilidUpdate` to a typed event (`None` = ignored).
fn map_update(u: VeilidUpdate) -> Option<VeilidNetEvent> {
    match u {
        VeilidUpdate::AppMessage(m) => Some(VeilidNetEvent::Inbound {
            bytes: m.message().to_vec(),
        }),
        VeilidUpdate::Attachment(a) => Some(VeilidNetEvent::Attachment {
            public_internet_ready: a.public_internet_ready,
        }),
        VeilidUpdate::RouteChange(_) => Some(VeilidNetEvent::RouteChanged),
        VeilidUpdate::ValueChange(_) => Some(VeilidNetEvent::ValueChanged),
        _ => None,
    }
}
