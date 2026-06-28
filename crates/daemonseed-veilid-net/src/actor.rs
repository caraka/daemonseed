//! The [`VeilidNet`] actor — a spawned task owning the `VeilidAPI` +
//! `RoutingContext`, driven through a command channel via [`VeilidNetHandle`].
//! Inbound `VeilidUpdate`s are mapped to typed [`VeilidNetEvent`]s on a
//! separate stream the app/UI consumes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use veilid_core::{
    api_startup, OperationId, RecordKey, RouteBlob, RouteId, RoutingContext, Target, VeilidAPI,
    VeilidConfig, VeilidUpdate,
};

use daemonseed_core::public_room::PublicRoomKey;
use daemonseed_core::share_envelope::ManifestEntry;
use daemonseed_core::share_serve::ShareContent;
use daemonseed_core::storage::cas::ChunkAddr;

use crate::config::VeilidNetConfig;
use crate::error::{Result, VeilidNetError};
use crate::event::VeilidNetEvent;
use crate::{discovery, identity, rendezvous, share};

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
    // One generic command pair drives every shared-owner rendezvous — circles
    // (Phase 2) and the lobby / public rooms + share discovery (Phase 3/4). The
    // ONLY difference is which `owner_seed` the caller derives; the engine treats
    // the payload as opaque sealed bytes regardless of feature.
    PublishRendezvous {
        owner_seed: [u8; 32],
        sealed: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    SubscribeRendezvous {
        owner_seed: [u8; 32],
        reply: oneshot::Sender<Result<()>>,
    },
    // ── Public-share content (Phase 3) ──
    /// Register an indexed share to serve owner-on-demand (`share_id` → content
    /// + the `PublicRoomKey` bytes responses seal under).
    ServeShare {
        share_id: String,
        content: Arc<ShareContent>,
        room_key: [u8; 32],
        reply: oneshot::Sender<Result<()>>,
    },
    /// Make one outbound `app_call` over a peer's private route (the fetch
    /// side's per-fragment round-trip). Spawned so a long fetch never blocks the
    /// actor loop.
    AppCall {
        route: RouteId,
        request: Vec<u8>,
        reply: oneshot::Sender<Result<Vec<u8>>>,
    },
    /// An inbound `app_call` forwarded from the update pump — the serve side
    /// answers it against the served-share registry via `app_call_reply`.
    InboundAppCall {
        call_id: OperationId,
        message: Vec<u8>,
    },
    /// Announce a public share to the lobby with an anti-swap SIGNED route advert
    /// (D-3.5). The actor allocates a private inbound route, asks `signer` to sign
    /// `share_id ‖ route_blob`, wraps it with the sealed announcement into a
    /// `DiscoveryEnvelope`, and publishes it on the lobby rendezvous; it remembers
    /// the advert so a `RouteChanged` can re-allocate + re-sign + re-publish.
    PublishShare {
        owner_seed: [u8; 32],
        share_id: String,
        sealed_announcement: Vec<u8>,
        signer: Arc<dyn discovery::RouteAdvertSigner>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Stop serving a share and drop its advert (the teeth of unpublish): removes
    /// it from the serve registry so inbound fetch `app_call`s for it are no longer
    /// answered, and from the advert set so a `RouteChanged` never re-publishes it.
    StopServe {
        share_id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// A private route died/rotated (from the update pump). Re-publish every active
    /// share advert with a fresh route + signature so discovery never points at a
    /// dead route. Coalesced against bursts; fire-and-forget.
    RouteMaintenance,
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

    // ── Circles (Phase 2): shared-owner DFLT rendezvous + append-ring fan-out ──

    /// Publish a SEALED message to a circle (Phase 2). `owner_seed` is the
    /// circle's deterministic Veilid rendezvous-owner seed
    /// (`daemonseed_core::circle::key::derive_circle_veilid_owner_seed`); the
    /// actor opens/creates the shared-owner DFLT record at the derived
    /// rendezvous address and writes `sealed` into this member's append-ring.
    /// `sealed` is the opaque circle envelope — this layer never holds the key
    /// or plaintext.
    pub async fn publish_circle(&self, owner_seed: [u8; 32], sealed: Vec<u8>) -> Result<()> {
        self.send(|reply| Command::PublishRendezvous {
            owner_seed,
            sealed,
            reply,
        })
        .await?
    }

    /// Subscribe to a circle (Phase 2): open the same rendezvous record, watch
    /// it for member writes, and sweep it once for the bounded login backlog.
    /// Inbound circle messages arrive as [`VeilidNetEvent::Inbound`] on the
    /// event stream (eventual — watch latency is tens of seconds). `owner_seed`
    /// is the circle's rendezvous-owner seed, as for [`Self::publish_circle`].
    pub async fn subscribe_circle(&self, owner_seed: [u8; 32]) -> Result<()> {
        self.send(|reply| Command::SubscribeRendezvous { owner_seed, reply })
            .await?
    }

    // ── Lobby / public rooms + share discovery (Phase 3/4) ──────────────────
    // The SAME shared-owner DFLT rendezvous engine as a circle — only the owner
    // derivation differs. `owner_seed` is the public-room rendezvous-owner seed
    // (`daemonseed_core::public_room::derive_room_veilid_owner_seed`), which is
    // WORLD-derivable, so the room is an open rendezvous. A public-share
    // announcement is just a `ShareAnnouncement` sealed under the room's
    // `PublicRoomKey` and published here — discovery rides the lobby record.

    /// Publish a SEALED payload to a public room / lobby (Phase 3/4). Mechanics
    /// are identical to [`Self::publish_circle`]; the difference is only that
    /// `owner_seed` is a public-room rendezvous-owner seed and `sealed` is sealed
    /// under the room's `PublicRoomKey` (a room message, or a `ShareAnnouncement`
    /// for share discovery). This layer never holds the key or plaintext.
    pub async fn publish_room(&self, owner_seed: [u8; 32], sealed: Vec<u8>) -> Result<()> {
        self.send(|reply| Command::PublishRendezvous {
            owner_seed,
            sealed,
            reply,
        })
        .await?
    }

    /// Subscribe to a public room / lobby (Phase 3/4): open the room's
    /// rendezvous record, watch it, and sweep it for the bounded backlog —
    /// identical to [`Self::subscribe_circle`] but for a public-room
    /// `owner_seed`. Inbound sealed room messages / share announcements arrive as
    /// [`VeilidNetEvent::Inbound`]; the app opens them under the `PublicRoomKey`.
    pub async fn subscribe_room(&self, owner_seed: [u8; 32]) -> Result<()> {
        self.send(|reply| Command::SubscribeRendezvous { owner_seed, reply })
            .await?
    }

    // ── Public-share CONTENT transfer (Phase 3): owner-on-demand over app_call ──

    /// Register an indexed share to serve owner-on-demand. The actor answers
    /// inbound fragment `app_call`s for `share_id` from `content`, sealing each
    /// response under `room_key` (the share's `PublicRoomKey` bytes). The sharer
    /// must stay online to serve (ISC-A-S21); discovery (`publish_room`) is what
    /// advertises it.
    pub async fn serve_share(
        &self,
        share_id: String,
        content: Arc<ShareContent>,
        room_key: [u8; 32],
    ) -> Result<()> {
        self.send(|reply| Command::ServeShare {
            share_id,
            content,
            room_key,
            reply,
        })
        .await?
    }

    /// Fetch + reassemble + open a share's manifest from the sharer reachable at
    /// private-route `route`. `room_key` is the share's `PublicRoomKey` bytes.
    pub async fn fetch_manifest(
        &self,
        route: RouteId,
        share_id: &str,
        room_key: [u8; 32],
    ) -> Result<Vec<ManifestEntry>> {
        let rk = PublicRoomKey::from_bytes(room_key);
        let this = self.clone();
        share::fetch_manifest(share_id, &rk, move |req| {
            let this = this.clone();
            let route = route.clone();
            async move { this.app_call(route, req).await }
        })
        .await
    }

    /// Fetch + reassemble + open + SHA-384-VERIFY one content chunk (ISC-S28 /
    /// ISC-A-S20) from the sharer at private-route `route`.
    pub async fn fetch_chunk(
        &self,
        route: RouteId,
        share_id: &str,
        chunk_addr: ChunkAddr,
        room_key: [u8; 32],
    ) -> Result<Vec<u8>> {
        let rk = PublicRoomKey::from_bytes(room_key);
        let this = self.clone();
        share::fetch_chunk(share_id, &chunk_addr, &rk, move |req| {
            let this = this.clone();
            let route = route.clone();
            async move { this.app_call(route, req).await }
        })
        .await
    }

    /// One outbound `app_call` over a peer's private route (a fetch fragment
    /// round-trip).
    async fn app_call(&self, route: RouteId, request: Vec<u8>) -> Result<Vec<u8>> {
        self.send(|reply| Command::AppCall {
            route,
            request,
            reply,
        })
        .await?
    }

    /// Announce a public share to the lobby with a SIGNED route advert (D-3.5 /
    /// [`crate::discovery`]). Allocates a private inbound route, has `signer` sign
    /// the route advert (`share_id ‖ route_blob`), wraps it with `sealed_announcement`
    /// (the core sealed `ShareAnnouncement`) into a [`crate::DiscoveryEnvelope`], and
    /// publishes it on the lobby rendezvous identified by `owner_seed`
    /// (`daemonseed_core::public_room::derive_room_veilid_owner_seed`). The advert is
    /// remembered and re-published on `RouteChanged`. Pair with [`Self::serve_share`],
    /// which registers the content this route serves.
    pub async fn publish_share(
        &self,
        owner_seed: [u8; 32],
        share_id: String,
        sealed_announcement: Vec<u8>,
        signer: Arc<dyn discovery::RouteAdvertSigner>,
    ) -> Result<()> {
        self.send(|reply| Command::PublishShare {
            owner_seed,
            share_id,
            sealed_announcement,
            signer,
            reply,
        })
        .await?
    }

    /// Stop serving a previously [`Self::serve_share`]d share and drop its advert.
    /// The teeth of unpublish: after this the owner no longer answers fetch
    /// `app_call`s for `share_id` (a holder of a stale route gets nothing), and a
    /// `RouteChanged` will not re-publish its advert. Pair with a withdraw
    /// announcement, which removes the share from listeners' discovery catalogs.
    pub async fn stop_serve(&self, share_id: String) -> Result<()> {
        self.send(|reply| Command::StopServe { share_id, reply })
            .await?
    }

    /// Member-plane presence heartbeat over a room/circle record. **Phase 4.**
    pub async fn presence(&self) -> Result<()> {
        Err(VeilidNetError::Unimplemented("presence — Phase 4"))
    }
}

/// Brings up the daemonseed Veilid transport node.
///
/// Phase 1 implements the PROVEN 1:1 path: identity-bound node, private routes,
/// sealed `app_message`. Phase 2 adds circles (shared-owner DFLT rendezvous +
/// append-ring fan-out). Shares, presence, and announcements are Phase 3+
/// ([`VeilidNetHandle`] signposts them).
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
        let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(64);
        let ev_tx_cb = ev_tx.clone();
        let cmd_tx_cb = cmd_tx.clone();
        let update_callback: Arc<dyn Fn(VeilidUpdate) + Send + Sync> =
            Arc::new(move |u: VeilidUpdate| match u {
                // Inbound app_calls are the share-serve request path: forward
                // them to the actor, which holds the VeilidAPI + the served-share
                // registry and answers via app_call_reply.
                VeilidUpdate::AppCall(call) => {
                    let _ = cmd_tx_cb.try_send(Command::InboundAppCall {
                        call_id: call.id(),
                        message: call.message().to_vec(),
                    });
                }
                // A private route died/rotated: drive an advert refresh in the
                // actor (which holds the signer + advert set) AND surface the event.
                VeilidUpdate::RouteChange(_) => {
                    let _ = cmd_tx_cb.try_send(Command::RouteMaintenance);
                    let _ = ev_tx_cb.send(VeilidNetEvent::RouteChanged);
                }
                other => {
                    if let Some(ev) = map_update(other) {
                        let _ = ev_tx_cb.send(ev);
                    }
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
        // Distinct listen ports let several nodes coexist on one host (tests).
        if let Some(addr) = &cfg.listen_address {
            vcfg.network.protocol.udp.listen_address = addr.clone();
            vcfg.network.protocol.tcp.listen_address = addr.clone();
            vcfg.network.protocol.ws.listen_address = addr.clone();
        }
        // D4: public network — no network_key_password. Override bootstrap only
        // if the caller baked one in (the fra1 seed).
        if !cfg.bootstrap.is_empty() {
            vcfg.network.routing_table.bootstrap = cfg.bootstrap.clone();
        }
        // D3: pin the daemonseed-derived node identity.
        let (pks, sks) = identity::identity_groups(&cfg.identity_seed)?;
        vcfg.network.routing_table.public_keys = pks;
        vcfg.network.routing_table.secret_keys = sks;

        crate::vtrace!(
            "start: namespace={:?} listen={:?} store={} bootstrap_overrides={}",
            vcfg.namespace,
            cfg.listen_address,
            cfg.storage_dir,
            cfg.bootstrap.len()
        );
        let api = api_startup(update_callback, vcfg)
            .await
            .map_err(|e| VeilidNetError::Startup(e.to_string()))?;
        crate::vtrace!("start: api_startup ok; node identity assigned");
        // Phase 1 uses Veilid's DEFAULT routing context, which already carries a
        // 1-hop safety route. Sends ride the receiver's private route
        // (Target::RouteId), so no safety override is needed. D5 — raising the
        // hop count via with_safety(Safe { hop_count: cfg.hop_count }) — is the
        // planned dial-up; cfg.hop_count is carried for it. (An explicit Unsafe
        // context would need veilid-core's footgun-nodeid-target feature — the
        // anti-dox NodeId path we deliberately avoid.)
        let rc = api
            .routing_context()
            .map_err(|e| VeilidNetError::Routing(e.to_string()))?;

        // This node's pubkey spreads it across the circle record's subkey
        // regions (Phase 2 fan-out).
        let node_pub = identity::node_public_bytes(&cfg.identity_seed);

        tokio::spawn(actor_loop(api, rc, cmd_rx, ev_tx, node_pub));
        Ok((VeilidNetHandle { cmd_tx }, ev_rx))
    }
}

/// The actor task: owns the `VeilidAPI` + `RoutingContext` and processes
/// commands until `Shutdown` or the command channel closes. Holds an event
/// sender (for background rendezvous sweeps), this node's pubkey (region
/// assignment), and a per-rendezvous append-ring write cursor.
async fn actor_loop(
    api: VeilidAPI,
    rc: RoutingContext,
    mut cmd_rx: mpsc::Receiver<Command>,
    ev_tx: mpsc::UnboundedSender<VeilidNetEvent>,
    node_pub: [u8; 32],
) {
    // Per-rendezvous local write cursor: which ring slot this node writes next
    // (keyed by record, so circles and rooms share the same map).
    let mut ring_seq: HashMap<RecordKey, u32> = HashMap::new();
    // Shares this node serves owner-on-demand (Phase 3), keyed by share_id.
    let mut shares: HashMap<String, share::ServedShare> = HashMap::new();
    // Active share adverts (Phase 3 discovery), keyed by share_id, so a
    // RouteChanged can re-allocate + re-sign + re-publish each one.
    let mut share_adverts: HashMap<String, AdvertState> = HashMap::new();
    // Coalesce RouteChanged bursts into at most one advert refresh per interval.
    let mut last_advert_refresh: Option<tokio::time::Instant> = None;

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
            Command::PublishRendezvous {
                owner_seed,
                sealed,
                reply,
            } => {
                let _ = reply.send(
                    publish_rendezvous(&api, &rc, &node_pub, &mut ring_seq, owner_seed, sealed)
                        .await,
                );
            }
            Command::SubscribeRendezvous { owner_seed, reply } => {
                let _ = reply.send(subscribe_rendezvous(&api, &rc, &ev_tx, owner_seed).await);
            }
            Command::ServeShare {
                share_id,
                content,
                room_key,
                reply,
            } => {
                shares.insert(
                    share_id,
                    share::ServedShare::new(content, PublicRoomKey::from_bytes(room_key)),
                );
                let _ = reply.send(Ok(()));
            }
            Command::AppCall {
                route,
                request,
                reply,
            } => {
                // Spawn so a multi-fragment fetch never blocks the actor loop.
                let rc2 = rc.clone();
                tokio::spawn(async move {
                    let r = rc2
                        .app_call(Target::RouteId(route), request)
                        .await
                        .map_err(|e| VeilidNetError::Send(e.to_string()));
                    let _ = reply.send(r);
                });
            }
            Command::InboundAppCall { call_id, message } => {
                // Answer the fragment request against the served-share registry
                // and reply over the same private route the call arrived on.
                let response = share::serve(&mut shares, &message);
                if let Err(e) = api.app_call_reply(call_id, response).await {
                    crate::vtrace!("inbound app_call: reply failed ({e})");
                }
            }
            Command::PublishShare {
                owner_seed,
                share_id,
                sealed_announcement,
                signer,
                reply,
            } => {
                let advert = AdvertState {
                    owner_seed,
                    sealed_announcement,
                    signer,
                };
                let res =
                    publish_one_advert(&api, &rc, &node_pub, &mut ring_seq, &share_id, &advert)
                        .await;
                if res.is_ok() {
                    share_adverts.insert(share_id, advert);
                }
                let _ = reply.send(res);
            }
            Command::StopServe { share_id, reply } => {
                // De-register from BOTH the serve registry (inbound fetch
                // app_calls for it are no longer answered) and the advert set (a
                // RouteChanged will not re-publish a dead advert). The route blob
                // still routes to this node until released, but the share is
                // unserved — a holder of a stale route gets a not-found, never bytes.
                shares.remove(&share_id);
                share_adverts.remove(&share_id);
                let _ = reply.send(Ok(()));
            }
            Command::RouteMaintenance => {
                let now = tokio::time::Instant::now();
                let due = last_advert_refresh
                    .is_none_or(|t| now.duration_since(t) >= ADVERT_REFRESH_MIN_INTERVAL);
                if due && !share_adverts.is_empty() {
                    last_advert_refresh = Some(now);
                    refresh_share_adverts(&api, &rc, &node_pub, &mut ring_seq, &share_adverts)
                        .await;
                }
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

/// Open/create the rendezvous record (a circle's, or a public room's / lobby's)
/// and write `sealed` into this node's append-ring slot, advancing the local
/// cursor. Identical for every consumer — only the caller's `owner_seed` differs.
async fn publish_rendezvous(
    api: &VeilidAPI,
    rc: &RoutingContext,
    node_pub: &[u8; 32],
    ring_seq: &mut HashMap<RecordKey, u32>,
    owner_seed: [u8; 32],
    sealed: Vec<u8>,
) -> Result<()> {
    crate::vtrace!("publish_rendezvous: open_or_create rendezvous");
    let owner = identity::rendezvous_owner_keypair(&owner_seed)?;
    let key = rendezvous::open_or_create(api, rc, &owner).await?;
    let base = rendezvous::member_base_subkey(node_pub);
    let seq = {
        let cur = ring_seq.entry(key.clone()).or_insert(0);
        let s = *cur;
        *cur = cur.wrapping_add(1);
        s
    };
    crate::vtrace!("publish_rendezvous: key={key:?} ring base={base} seq={seq}");
    let r = rendezvous::publish(rc, &key, &owner, base, seq, sealed).await;
    crate::vtrace!(
        "publish_rendezvous: write {}",
        if r.is_ok() { "ok" } else { "ERR" }
    );
    r
}

/// Open/create the rendezvous record, register a watch, and kick off a one-shot
/// background sweep for the bounded login backlog. Inbound items flow out as
/// [`VeilidNetEvent::Inbound`]. Used for circles and public rooms / lobby alike.
async fn subscribe_rendezvous(
    api: &VeilidAPI,
    rc: &RoutingContext,
    ev_tx: &mpsc::UnboundedSender<VeilidNetEvent>,
    owner_seed: [u8; 32],
) -> Result<()> {
    crate::vtrace!("subscribe_rendezvous: open_or_create rendezvous");
    let owner = identity::rendezvous_owner_keypair(&owner_seed)?;
    let key = rendezvous::open_or_create(api, rc, &owner).await?;
    crate::vtrace!("subscribe_rendezvous: record open key={key:?}; registering watch");
    rc.watch_dht_values(key.clone(), None, None, None)
        .await
        .map_err(|e| VeilidNetError::Routing(e.to_string()))?;
    crate::vtrace!("subscribe_rendezvous: watch ok; spawning backlog sweep -> Ok");
    tokio::spawn(rendezvous::sweep(rc.clone(), key, ev_tx.clone()));
    Ok(())
}

/// Min interval between RouteChanged-triggered advert refreshes — coalesces route
/// churn bursts (NAT flaps cluster) into at most one re-publish wave, breaking the
/// churn → republish → load → churn reinforcing loop.
const ADVERT_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// A remembered public-share advert: enough to re-allocate a route, re-sign, and
/// re-publish it on RouteChanged. Holds the signing CAPABILITY, never key material.
struct AdvertState {
    owner_seed: [u8; 32],
    sealed_announcement: Vec<u8>,
    signer: Arc<dyn discovery::RouteAdvertSigner>,
}

/// Allocate a fresh private inbound route, sign the route advert with the sharer's
/// capability, wrap it with the sealed announcement into a `DiscoveryEnvelope`, and
/// publish it on the lobby rendezvous. The signed `share_id ‖ route_blob` is the
/// anti-swap binding (D-3.5); this layer never holds the announcer's key.
async fn publish_one_advert(
    api: &VeilidAPI,
    rc: &RoutingContext,
    node_pub: &[u8; 32],
    ring_seq: &mut HashMap<RecordKey, u32>,
    share_id: &str,
    advert: &AdvertState,
) -> Result<()> {
    let route = api
        .new_private_route()
        .await
        .map_err(|e| VeilidNetError::Routing(e.to_string()))?;
    let route_sig = advert.signer.sign_route_advert(share_id, &route.blob)?;
    let envelope = discovery::DiscoveryEnvelope {
        sealed_announcement: advert.sealed_announcement.clone(),
        route_blob: route.blob,
        route_sig,
    }
    .encode();
    crate::vtrace!(
        "publish_one_advert: share_id={share_id} envelope={} bytes",
        envelope.len()
    );
    publish_rendezvous(api, rc, node_pub, ring_seq, advert.owner_seed, envelope).await
}

/// Re-publish every active share advert with a fresh route + signature (called on
/// RouteChanged). A failure on one advert is logged and skipped — the others still
/// refresh.
async fn refresh_share_adverts(
    api: &VeilidAPI,
    rc: &RoutingContext,
    node_pub: &[u8; 32],
    ring_seq: &mut HashMap<RecordKey, u32>,
    adverts: &HashMap<String, AdvertState>,
) {
    crate::vtrace!("refresh_share_adverts: {} advert(s)", adverts.len());
    for (share_id, st) in adverts {
        if let Err(e) = publish_one_advert(api, rc, node_pub, ring_seq, share_id, st).await {
            crate::vtrace!("refresh_share_adverts: {share_id} ERR ({e})");
        }
    }
}

/// Attach and poll until public-internet-ready or the deadline elapses.
async fn attach_and_wait(api: &VeilidAPI, timeout_secs: u64) -> Result<()> {
    crate::vtrace!("attach: calling api.attach()");
    api.attach()
        .await
        .map_err(|e| VeilidNetError::Startup(e.to_string()))?;
    crate::vtrace!(
        "attach: api.attach() ok; waiting up to {timeout_secs}s for public_internet_ready"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    // Log only when the snapshot changes — the peer counts distinguish a
    // bootstrap/NAT-discovery stall (peers stay 0) from a DHT-cold-but-reachable
    // node, the two competing Branch-1 causes.
    let mut last = String::new();
    loop {
        let attachment = api
            .get_state()
            .await
            .map_err(|e| VeilidNetError::Startup(e.to_string()))?
            .attachment;
        let snap = format!(
            "state={:?} public={} local={} peers(reliable={:?} live={:?})",
            attachment.state,
            attachment.public_internet_ready,
            attachment.local_network_ready,
            attachment.reliable_peer_count,
            attachment.live_peer_count
        );
        if snap != last {
            crate::vtrace!("attach: {snap}");
            last = snap;
        }
        if attachment.public_internet_ready {
            crate::vtrace!("attach: public_internet_ready -> Ok");
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            crate::vtrace!("attach: deadline elapsed -> NotReady (last {last})");
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
        // `RouteChange` is intercepted in the update callback (it drives advert
        // refresh + emits `RouteChanged` directly), so it never reaches here.
        // A watched rendezvous record changed. We only watch rendezvous records
        // (circles + public rooms / lobby), so a value-bearing change is an
        // inbound sealed item — surface its bytes (the app opens it with the
        // circle key or `PublicRoomKey`). An empty change (no value) means the
        // watch died; report it as ValueChanged.
        VeilidUpdate::ValueChange(vc) => match vc.value {
            Some(v) => Some(VeilidNetEvent::Inbound {
                bytes: v.data().to_vec(),
            }),
            None => Some(VeilidNetEvent::ValueChanged),
        },
        _ => None,
    }
}
