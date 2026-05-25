//! Public-space application service (M6) — the FIRST post-Authenticated
//! gRPC-over-h2 service in the protocol.
//!
//! ## Where this sits in the connection lifecycle
//!
//! Everything up to and including the identity-proof exchange runs as
//! length-prefixed prost frames on the raw TLS stream (see [`crate::hello`]
//! and [`crate::identity_proof`]). Once the per-connection driver advances the
//! type-state to [`daemonseed_core::connection::Authenticated`], that
//! connection *is* an application byte-stream (it impls `AsyncRead` +
//! `AsyncWrite`). This module serves the [`PublicSpace`] gRPC service over that
//! byte-stream. Earlier milestones deliberately dropped the `Authenticated`
//! connection ("M5+ serves the application stream"); M6 is where it gets
//! served.
//!
//! ## Why a single-connection tonic server (the retired risk)
//!
//! tonic's [`Server`](tonic::transport::Server) is normally driven by a TCP
//! listener. Here there is exactly one, already-TLS-terminated, already-
//! identity-proven connection. [`serve_public_space`] adapts it via
//! tonic's `serve_with_incoming` fed a one-element stream
//! ([`tokio_stream::once`]). The connection IO must
//! impl [`tonic::transport::server::Connected`]; that trait and the concrete
//! transport types are both foreign, so [`ServedConn`] is a local newtype that
//! supplies the impl (orphan rule). Its `ConnectInfo` is `()` because the peer
//! identity is already established by the identity-proof phase — tonic's
//! connect-info would be redundant.
//!
//! ## Trust model
//!
//! The relay is verify-and-serve only (ISC-A-S3): it never originates a post or
//! MOTD. Every artifact — loaded from disk at startup or arriving via
//! `UploadPost` — is verified against the signer whitelist (ISC-S8) and its
//! ML-DSA-87 signature before it is stored or served. All of that logic lives
//! in [`PublicSpaceState`] and, beneath it, `daemonseed_core::public_space`,
//! which the clients run too — so the server can never serve content a client
//! would reject. This [`PublicSpace`] impl is a thin tonic adapter over that
//! state: read RPCs return cloned snapshots; write RPCs delegate and map typed
//! errors to gRPC statuses (ISC-S7 / S8 / S9 / S10 / C19 / F25).

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

use daemonseed_core::public_space::{
    ArtifactError, CONTENT_ADDRESS_LEN, Whitelist, WhitelistEntry, WhitelistParseError,
    verify_artifact,
};
use daemonseed_proto::v1 as wire;
use daemonseed_proto::v1::public_space_server::{PublicSpace, PublicSpaceServer};
use oxicrypt_ml_dsa as ml_dsa;
use prost::Message;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status};

// ── Signer-whitelist file loading (ISC-S8 / ISC-13 / ISC-14) ─────────────

/// Load the operator's signer whitelist from its plaintext file (ISC-S8).
///
/// One entry per line; blank / whitespace-only lines are ignored. Each
/// non-blank line is parsed by `WhitelistEntry::from_str` — a malformed line
/// is a hard error carrying its 1-based line number (ISC-S8: a typo must never
/// silently de-authorize a signer). The whitelist is changed only by editing
/// this file and reloading; there is no in-band mutation path (ISC-13), so
/// removing a line and reloading revokes that signer (ISC-14).
pub fn load_whitelist(path: &Path) -> Result<Whitelist, WhitelistLoadError> {
    let contents = std::fs::read_to_string(path).map_err(|source| WhitelistLoadError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    let mut entries = Vec::new();
    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let entry = line
            .parse::<WhitelistEntry>()
            .map_err(|source| WhitelistLoadError::Parse {
                line: idx + 1,
                source,
            })?;
        entries.push(entry);
    }
    Ok(Whitelist::from_entries(entries))
}

/// Failure loading the signer-whitelist file.
#[derive(Debug)]
pub enum WhitelistLoadError {
    /// Reading the whitelist file from disk failed.
    Read { path: PathBuf, source: io::Error },
    /// A non-blank line failed to parse (1-based line number).
    Parse {
        line: usize,
        source: WhitelistParseError,
    },
}

impl fmt::Display for WhitelistLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "failed to read whitelist {}: {source}", path.display())
            }
            Self::Parse { line, source } => {
                write!(f, "whitelist line {line}: {source}")
            }
        }
    }
}

impl Error for WhitelistLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
        }
    }
}

// ── In-RAM public-space state ────────────────────────────────────────────

/// A post held in RAM, with the metadata `ListPosts` needs (topic +
/// timestamp) decoded once at load/upload so reads never re-parse the
/// signed payload.
#[derive(Clone)]
struct StoredPost {
    artifact: wire::SignedArtifact,
    content_address: [u8; CONTENT_ADDRESS_LEN],
    topic: String,
    signed_timestamp_ms: i64,
}

impl StoredPost {
    fn to_wire(&self) -> wire::Post {
        wire::Post {
            artifact: Some(self.artifact.clone()),
            content_address: self.content_address.to_vec(),
        }
    }
}

/// The relevant slice of `ServerConfig` for building public-space state,
/// borrowed so the runtime can pass config fields without this module
/// depending on the whole `ServerConfig`.
pub struct PublicSpaceConfig<'a> {
    pub posts_dir: Option<&'a Path>,
    pub motd_path: Option<&'a Path>,
    pub whitelist_path: Option<&'a Path>,
    pub taxonomy: &'a [String],
    pub topics: &'a [String],
}

/// Failure building [`PublicSpaceState`] at startup.
#[derive(Debug)]
pub enum LoadError {
    /// The signer-whitelist file failed to load (ISC-S8).
    Whitelist(WhitelistLoadError),
    /// The posts directory could not be read.
    PostsDir { path: PathBuf, source: io::Error },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Whitelist(e) => write!(f, "{e}"),
            Self::PostsDir { path, source } => {
                write!(f, "failed to read posts dir {}: {source}", path.display())
            }
        }
    }
}

impl Error for LoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Whitelist(e) => Some(e),
            Self::PostsDir { source, .. } => Some(source),
        }
    }
}

/// Server-wide public-space state (ISC-S7 / S8 / S9 / S10), shared across
/// every connection's [`PublicSpaceService`] via `Arc`.
///
/// The relay is verify-and-serve only (ISC-A-S3): posts and the MOTD are
/// loaded into RAM only after their signatures verify against the signer
/// whitelist; nothing here is ever server-originated. `posts` / `motd` are the
/// only runtime-mutable fields, behind `RwLock`s; everything else is fixed at
/// load.
pub struct PublicSpaceState {
    /// Authorizes announcement-post signers (operator entries + F17).
    post_whitelist: Whitelist,
    /// Operator entries in wire form, published to clients (ISC-S8 / ISC-6).
    /// Excludes F17 and the server key — only the operator-configured signers.
    published_entries: Vec<wire::SignerWhitelistEntry>,
    /// Operator-defined rating labels (ISC-S10); published, never enforced.
    taxonomy: Vec<String>,
    /// Operator-defined topic set (ISC-S7 / ISC-19); posts to other topics are
    /// rejected.
    topics: Vec<String>,
    /// Verified posts, keyed by content address (ISC-16 / ISC-18).
    posts: RwLock<BTreeMap<[u8; CONTENT_ADDRESS_LEN], StoredPost>>,
    /// Single-slot validated MOTD, or `None` to hide the area (ISC-22 / ISC-24).
    motd: RwLock<Option<wire::SignedArtifact>>,
    /// Where `UploadPost` / `DeletePost` write (signer-writable; ISC-A-S8).
    posts_dir: Option<PathBuf>,
    /// F25 public-share listing (content/transfer is M8; empty for M6).
    public_shares: Vec<wire::PublicShareListing>,
}

impl PublicSpaceState {
    /// Build state from disk: load + verify the whitelist, posts, and MOTD.
    ///
    /// `server_pubkey` is the relay's own ML-DSA-87 signing key, accepted as a
    /// MOTD signer in addition to the whitelist (ISC-26). Invalid post files
    /// and an invalid/missing MOTD are skipped (verify-and-serve, ISC-A-S3);
    /// only a broken whitelist or an unreadable posts dir fails the load.
    pub fn load(
        cfg: &PublicSpaceConfig,
        server_pubkey: &[u8; ml_dsa::PK_LEN],
    ) -> Result<Self, LoadError> {
        let operator_entries: Vec<WhitelistEntry> = match cfg.whitelist_path {
            Some(p) => load_whitelist(p)
                .map_err(LoadError::Whitelist)?
                .entries()
                .to_vec(),
            None => Vec::new(),
        };

        let post_whitelist = Whitelist::from_entries(operator_entries.clone());

        let mut motd_entries = operator_entries.clone();
        motd_entries.push(WhitelistEntry::FullKey(Box::new(*server_pubkey)));
        let motd_whitelist = Whitelist::from_entries(motd_entries);

        let published_entries = operator_entries.iter().map(entry_to_wire).collect();

        let posts = match cfg.posts_dir {
            Some(dir) => load_posts(dir, &post_whitelist)?,
            None => BTreeMap::new(),
        };

        let motd = cfg.motd_path.and_then(|p| load_motd(p, &motd_whitelist));

        Ok(Self {
            post_whitelist,
            published_entries,
            taxonomy: cfg.taxonomy.to_vec(),
            topics: cfg.topics.to_vec(),
            posts: RwLock::new(posts),
            motd: RwLock::new(motd),
            posts_dir: cfg.posts_dir.map(Path::to_path_buf),
            public_shares: Vec::new(),
        })
    }

    /// An empty public space — no signers, posts, MOTD, or topics. Used by a
    /// relay with no public-space config and by tests that don't exercise it.
    pub fn empty() -> Self {
        Self {
            post_whitelist: Whitelist::from_entries(Vec::new()),
            published_entries: Vec::new(),
            taxonomy: Vec::new(),
            topics: Vec::new(),
            posts: RwLock::new(BTreeMap::new()),
            motd: RwLock::new(None),
            posts_dir: None,
            public_shares: Vec::new(),
        }
    }

    /// The current validated MOTD, or `None` (ISC-S9 / ISC-3).
    pub fn get_motd(&self) -> Option<wire::SignedArtifact> {
        self.motd.read().expect("motd lock poisoned").clone()
    }

    /// Posts, ordered by signed timestamp within each topic (ISC-S7 / ISC-4).
    /// `topic = None` returns all topics; otherwise only the named topic.
    pub fn list_posts(&self, topic: Option<&str>) -> Vec<wire::Post> {
        let posts = self.posts.read().expect("posts lock poisoned");
        let mut selected: Vec<&StoredPost> = posts
            .values()
            .filter(|p| topic.is_none_or(|t| p.topic == t))
            .collect();
        // Order by topic, then by signed timestamp within the topic (ISC-4).
        selected.sort_by(|a, b| {
            a.topic
                .cmp(&b.topic)
                .then(a.signed_timestamp_ms.cmp(&b.signed_timestamp_ms))
        });
        selected.iter().map(|p| p.to_wire()).collect()
    }

    /// The operator rating taxonomy (ISC-S10 / ISC-5). Published, not enforced.
    pub fn taxonomy(&self) -> wire::RatingTaxonomy {
        wire::RatingTaxonomy {
            labels: self.taxonomy.clone(),
        }
    }

    /// The published operator whitelist entries (ISC-S8 / ISC-6).
    pub fn signer_whitelist(&self) -> Vec<wire::SignerWhitelistEntry> {
        self.published_entries.clone()
    }

    /// The public-share listing (ISC-C19 / F25). Empty in M6 — content/transfer
    /// lands at M8.
    pub fn public_shares(&self) -> Vec<wire::PublicShareListing> {
        self.public_shares.clone()
    }

    /// Verify + store a signed announcement post (ISC-S7 / ISC-7 / ISC-A-S3).
    ///
    /// Rejects an unknown signer or bad signature (`Unauthorized`), a payload
    /// that isn't a well-formed `PostPayload` (`Malformed`), or a topic outside
    /// the operator set (`BadTopic`, ISC-19 — signers cannot create topics).
    /// On success the signed bytes are persisted verbatim to `posts_dir` under
    /// their content address (never re-encoded — D-M6-7) and held in RAM;
    /// returns the content address.
    pub fn upload_post(
        &self,
        artifact: wire::SignedArtifact,
    ) -> Result<[u8; CONTENT_ADDRESS_LEN], UploadError> {
        let posts_dir = self
            .posts_dir
            .as_ref()
            .ok_or(UploadError::StorageDisabled)?;

        let address = verify_artifact(
            &artifact.signed_payload,
            &artifact.signer_pubkey,
            &artifact.signature,
            &self.post_whitelist,
        )
        .map_err(upload_artifact_err)?;
        let addr = *address.as_bytes();

        let payload = wire::PostPayload::decode(artifact.signed_payload.as_slice())
            .map_err(|_| UploadError::Malformed)?;
        // ISC-19: signers post into operator-defined topics; they cannot create
        // new ones.
        if !self.topics.iter().any(|t| t == &payload.topic) {
            return Err(UploadError::BadTopic);
        }

        // Persist the signed bytes verbatim (D-M6-7), then hold in RAM.
        std::fs::create_dir_all(posts_dir).map_err(UploadError::Io)?;
        std::fs::write(posts_dir.join(hex::encode(addr)), artifact.encode_to_vec())
            .map_err(UploadError::Io)?;

        let stored = StoredPost {
            content_address: addr,
            topic: payload.topic,
            signed_timestamp_ms: payload.signed_timestamp_ms,
            artifact,
        };
        self.posts
            .write()
            .expect("posts lock poisoned")
            .insert(addr, stored);
        Ok(addr)
    }

    /// Delete a post the caller previously signed (ISC-S7 / ISC-8 / ISC-20).
    ///
    /// The delete request is itself a signed artifact; its signer must be
    /// whitelisted AND must be the original author of the target post (matched
    /// by content address). Removes the post from RAM and deletes its file.
    pub fn delete_post(&self, delete_artifact: wire::SignedArtifact) -> Result<(), DeleteError> {
        let posts_dir = self
            .posts_dir
            .as_ref()
            .ok_or(DeleteError::StorageDisabled)?;

        verify_artifact(
            &delete_artifact.signed_payload,
            &delete_artifact.signer_pubkey,
            &delete_artifact.signature,
            &self.post_whitelist,
        )
        .map_err(delete_artifact_err)?;

        let payload = wire::PostDeletePayload::decode(delete_artifact.signed_payload.as_slice())
            .map_err(|_| DeleteError::Malformed)?;
        let addr: [u8; CONTENT_ADDRESS_LEN] = payload
            .content_address
            .as_slice()
            .try_into()
            .map_err(|_| DeleteError::Malformed)?;

        {
            let mut posts = self.posts.write().expect("posts lock poisoned");
            match posts.get(&addr) {
                None => return Err(DeleteError::NotFound),
                // ISC-20 / ISC-8: only the original author may delete.
                Some(target) if target.artifact.signer_pubkey != delete_artifact.signer_pubkey => {
                    return Err(DeleteError::Unauthorized);
                }
                Some(_) => {}
            }
            posts.remove(&addr);
        }

        // RAM is the source of truth; a missing file is not an error.
        match std::fs::remove_file(posts_dir.join(hex::encode(addr))) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(DeleteError::Io(e)),
        }
    }
}

/// Map a core artifact-verification failure to an upload rejection.
fn upload_artifact_err(e: ArtifactError) -> UploadError {
    match e {
        ArtifactError::UnknownSigner | ArtifactError::BadSignature => UploadError::Unauthorized,
        ArtifactError::Module(m) => UploadError::Module(m),
    }
}

/// Map a core artifact-verification failure to a delete rejection.
fn delete_artifact_err(e: ArtifactError) -> DeleteError {
    match e {
        ArtifactError::UnknownSigner | ArtifactError::BadSignature => DeleteError::Unauthorized,
        ArtifactError::Module(m) => DeleteError::Module(m),
    }
}

/// Failure of [`PublicSpaceState::upload_post`].
#[derive(Debug)]
pub enum UploadError {
    /// Signer not whitelisted or signature invalid (→ gRPC PermissionDenied).
    Unauthorized,
    /// Topic is not in the operator's configured set (→ InvalidArgument).
    BadTopic,
    /// The signed payload is not a well-formed `PostPayload` (→ InvalidArgument).
    Malformed,
    /// The relay has no `posts_dir` configured (→ FailedPrecondition).
    StorageDisabled,
    /// Persisting the post to disk failed (→ Internal).
    Io(io::Error),
    /// The crypto module was not operational (→ Internal).
    Module(oxicrypt_module::Error),
}

/// Failure of [`PublicSpaceState::delete_post`].
#[derive(Debug)]
pub enum DeleteError {
    /// Signer not whitelisted, signature invalid, or not the post's author
    /// (→ PermissionDenied).
    Unauthorized,
    /// The signed payload is not a well-formed `PostDeletePayload`, or its
    /// content address is malformed (→ InvalidArgument).
    Malformed,
    /// No post exists at the target content address (→ NotFound).
    NotFound,
    /// The relay has no `posts_dir` configured (→ FailedPrecondition).
    StorageDisabled,
    /// Removing the post file failed (→ Internal).
    Io(io::Error),
    /// The crypto module was not operational (→ Internal).
    Module(oxicrypt_module::Error),
}

/// Map a core [`WhitelistEntry`] to its wire form for publishing (ISC-6).
fn entry_to_wire(entry: &WhitelistEntry) -> wire::SignerWhitelistEntry {
    use wire::signer_whitelist_entry::Entry;
    let inner = match entry {
        WhitelistEntry::FullKey(key) => Entry::FullPubkey(key.to_vec()),
        WhitelistEntry::Handle(handle) => Entry::Handle(handle.to_string()),
    };
    wire::SignerWhitelistEntry { entry: Some(inner) }
}

/// Load + verify every post file in `dir` into a content-addressed map. A file
/// that fails to decode or verify is skipped (verify-and-serve, ISC-A-S3); a
/// missing dir yields an empty map (created on first upload).
fn load_posts(
    dir: &Path,
    whitelist: &Whitelist,
) -> Result<BTreeMap<[u8; CONTENT_ADDRESS_LEN], StoredPost>, LoadError> {
    let mut posts = BTreeMap::new();
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(posts),
        Err(source) => {
            return Err(LoadError::PostsDir {
                path: dir.to_path_buf(),
                source,
            });
        }
    };

    for entry in read_dir.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        if let Some(post) = verify_stored_post(&bytes, whitelist) {
            posts.insert(post.content_address, post);
        }
    }
    Ok(posts)
}

/// Decode + verify one stored post's bytes (an encoded `SignedArtifact`) into a
/// [`StoredPost`], or `None` if it doesn't decode, doesn't verify against the
/// whitelist, or its inner payload isn't a well-formed `PostPayload`.
fn verify_stored_post(bytes: &[u8], whitelist: &Whitelist) -> Option<StoredPost> {
    let artifact = wire::SignedArtifact::decode(bytes).ok()?;
    let address = verify_artifact(
        &artifact.signed_payload,
        &artifact.signer_pubkey,
        &artifact.signature,
        whitelist,
    )
    .ok()?;
    let payload = wire::PostPayload::decode(artifact.signed_payload.as_slice()).ok()?;
    Some(StoredPost {
        content_address: *address.as_bytes(),
        topic: payload.topic,
        signed_timestamp_ms: payload.signed_timestamp_ms,
        artifact,
    })
}

/// Read + verify the single MOTD file. Missing, unreadable, undecodable, or
/// signature-invalid all collapse to `None` (hide the area, ISC-24).
fn load_motd(path: &Path, whitelist: &Whitelist) -> Option<wire::SignedArtifact> {
    let bytes = std::fs::read(path).ok()?;
    let artifact = wire::SignedArtifact::decode(bytes.as_slice()).ok()?;
    verify_artifact(
        &artifact.signed_payload,
        &artifact.signer_pubkey,
        &artifact.signature,
        whitelist,
    )
    .ok()?;
    // Confirm the inner payload is a well-formed MOTD before serving it.
    wire::MotdPayload::decode(artifact.signed_payload.as_slice()).ok()?;
    Some(artifact)
}

/// The tonic adapter over [`PublicSpaceState`]. Each connection's service
/// shares the one server-wide state via `Arc`, so posts uploaded on one
/// connection are visible to every other.
///
/// Methods are thin: read RPCs return cloned snapshots; write RPCs delegate to
/// the state's verify-and-store logic and map its typed errors to gRPC
/// statuses. All trust decisions live in [`PublicSpaceState`] (and, beneath it,
/// `daemonseed_core::public_space`), never here.
#[derive(Clone)]
pub struct PublicSpaceService {
    state: Arc<PublicSpaceState>,
}

impl PublicSpaceService {
    /// Wrap shared public-space state for serving over one connection.
    pub fn new(state: Arc<PublicSpaceState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl PublicSpace for PublicSpaceService {
    async fn get_motd(
        &self,
        _request: Request<wire::GetMotdRequest>,
    ) -> Result<Response<wire::GetMotdResponse>, Status> {
        Ok(Response::new(wire::GetMotdResponse {
            motd: self.state.get_motd(),
        }))
    }

    async fn list_posts(
        &self,
        request: Request<wire::ListPostsRequest>,
    ) -> Result<Response<wire::ListPostsResponse>, Status> {
        let topic = request.into_inner().topic;
        Ok(Response::new(wire::ListPostsResponse {
            posts: self.state.list_posts(topic.as_deref()),
        }))
    }

    async fn get_taxonomy(
        &self,
        _request: Request<wire::GetTaxonomyRequest>,
    ) -> Result<Response<wire::GetTaxonomyResponse>, Status> {
        Ok(Response::new(wire::GetTaxonomyResponse {
            taxonomy: Some(self.state.taxonomy()),
        }))
    }

    async fn get_signer_whitelist(
        &self,
        _request: Request<wire::GetSignerWhitelistRequest>,
    ) -> Result<Response<wire::GetSignerWhitelistResponse>, Status> {
        Ok(Response::new(wire::GetSignerWhitelistResponse {
            entries: self.state.signer_whitelist(),
        }))
    }

    async fn upload_post(
        &self,
        request: Request<wire::UploadPostRequest>,
    ) -> Result<Response<wire::UploadPostResponse>, Status> {
        let artifact = request
            .into_inner()
            .artifact
            .ok_or_else(|| Status::invalid_argument("missing artifact"))?;
        let address = self.state.upload_post(artifact).map_err(upload_status)?;
        Ok(Response::new(wire::UploadPostResponse {
            content_address: address.to_vec(),
        }))
    }

    async fn delete_post(
        &self,
        request: Request<wire::DeletePostRequest>,
    ) -> Result<Response<wire::DeletePostResponse>, Status> {
        let delete_artifact = request
            .into_inner()
            .delete_artifact
            .ok_or_else(|| Status::invalid_argument("missing delete_artifact"))?;
        self.state
            .delete_post(delete_artifact)
            .map_err(delete_status)?;
        Ok(Response::new(wire::DeletePostResponse {}))
    }

    async fn list_public_shares(
        &self,
        _request: Request<wire::ListPublicSharesRequest>,
    ) -> Result<Response<wire::ListPublicSharesResponse>, Status> {
        Ok(Response::new(wire::ListPublicSharesResponse {
            shares: self.state.public_shares(),
        }))
    }
}

/// Map an [`UploadError`] to a gRPC status. `Io` / `Module` collapse to
/// `internal` so a persistence or crypto-module fault never leaks detail.
fn upload_status(e: UploadError) -> Status {
    match e {
        UploadError::Unauthorized => Status::permission_denied("signer not authorized"),
        UploadError::BadTopic => Status::invalid_argument("topic not in operator set"),
        UploadError::Malformed => Status::invalid_argument("malformed post payload"),
        UploadError::StorageDisabled => Status::failed_precondition("post storage not configured"),
        UploadError::Io(_) | UploadError::Module(_) => Status::internal("upload failed"),
    }
}

/// Map a [`DeleteError`] to a gRPC status.
fn delete_status(e: DeleteError) -> Status {
    match e {
        DeleteError::Unauthorized => Status::permission_denied("not authorized to delete"),
        DeleteError::Malformed => Status::invalid_argument("malformed delete request"),
        DeleteError::NotFound => Status::not_found("no such post"),
        DeleteError::StorageDisabled => Status::failed_precondition("post storage not configured"),
        DeleteError::Io(_) | DeleteError::Module(_) => Status::internal("delete failed"),
    }
}

/// Adapts a single already-established, authenticated transport into something
/// tonic will serve.
///
/// `tonic`'s incoming-connection IO must impl [`Connected`]; the trait is
/// foreign and the wrapped transport types (`Connection<Authenticated, _>`, the
/// concrete `TlsStream`, or a test duplex half) are foreign too, so the impl
/// has to live on a local newtype. `ConnectInfo = ()` — the peer is already
/// authenticated, so tonic's per-connection info is redundant here.
#[derive(Debug)]
pub struct ServedConn<S>(pub S);

impl<S: Send + 'static> Connected for ServedConn<S> {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl<S: AsyncRead + Unpin> AsyncRead for ServedConn<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ServedConn<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

/// Serve [`PublicSpace`] over a single already-Authenticated transport until
/// the peer closes the connection.
///
/// The caller passes the connection only after the identity-proof exchange has
/// advanced it to `Authenticated` (daemonseed-core type-state), so reaching
/// application traffic without a verified peer is a compile error upstream
/// (ISC-C23). `S` is any authenticated transport: in production a
/// `Connection<Authenticated, TlsStream<TcpStream>>`; in tests an in-memory
/// duplex half.
pub async fn serve_public_space<S>(
    stream: S,
    service: PublicSpaceService,
) -> Result<(), tonic::transport::Error>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let incoming = tokio_stream::once(Ok::<_, io::Error>(ServedConn(stream)));
    tonic::transport::Server::builder()
        .add_service(PublicSpaceServer::new(service))
        .serve_with_incoming(incoming)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemonseed_core::identity::keys::SignKeypair;
    use daemonseed_core::public_space::content_address;
    use daemonseed_proto::v1::public_space_client::PublicSpaceClient;
    use hyper_util::rt::TokioIo;
    use tempfile::TempDir;
    use tonic::transport::Endpoint;

    fn ensure_module() {
        oxitls_rustls_provider::testing::ensure_module_operational();
    }

    fn keypair(seed_byte: u8) -> SignKeypair {
        ensure_module();
        SignKeypair::from_ml_dsa_seed(&[seed_byte; 32]).unwrap()
    }

    // ── Whitelist file loading (ISC-S8 / ISC-13 / ISC-14) ────────────────

    #[test]
    fn load_whitelist_reads_full_key_and_handle_lines() {
        let signer = keypair(21);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("signers.txt");
        // Full-key line, a blank line, and a handle line.
        let contents = format!(
            "{}\n\nrelay-bear#aabbccddeeff\n",
            hex::encode(signer.public_key())
        );
        std::fs::write(&path, contents).unwrap();

        let wl = load_whitelist(&path).unwrap();
        assert!(wl.authorizes(signer.public_key()).unwrap());
        assert_eq!(
            wl.entries().len(),
            2,
            "blank line ignored; F17 not in entries()"
        );
    }

    #[test]
    fn load_whitelist_malformed_line_errors_with_line_number() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("signers.txt");
        std::fs::write(&path, "good-signer#aabbccddeeff\nbad#xyz\n").unwrap();

        match load_whitelist(&path) {
            Err(WhitelistLoadError::Parse { line: 2, .. }) => {}
            other => panic!("expected Parse error at line 2, got {other:?}"),
        }
    }

    /// ISC-13 / ISC-14: the only way to change the whitelist is to edit the
    /// file and reload; removing an entry then reloading revokes that signer.
    #[test]
    fn whitelist_reload_revokes_removed_entry() {
        let signer = keypair(22);
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("signers.txt");
        std::fs::write(&path, format!("{}\n", hex::encode(signer.public_key()))).unwrap();

        let before = load_whitelist(&path).unwrap();
        assert!(before.authorizes(signer.public_key()).unwrap());

        std::fs::write(&path, "").unwrap(); // operator removes the entry
        let after = load_whitelist(&path).unwrap();
        assert!(
            !after.authorizes(signer.public_key()).unwrap(),
            "reload after removal revokes authorship (ISC-14)"
        );
    }

    // ── State loading + reads (ISC-3/4/5/6/16/18/22/24/26 / A-S3) ─────────

    fn signed_artifact(signer: &SignKeypair, signed_payload: Vec<u8>) -> wire::SignedArtifact {
        let signature = signer.sign(&signed_payload).unwrap().to_vec();
        wire::SignedArtifact {
            signed_payload,
            signer_pubkey: signer.public_key().to_vec(),
            signature,
        }
    }

    fn post_artifact(
        signer: &SignKeypair,
        topic: &str,
        body: &str,
        ts: i64,
    ) -> (wire::SignedArtifact, [u8; CONTENT_ADDRESS_LEN]) {
        let payload = wire::PostPayload {
            topic: topic.to_owned(),
            body: body.to_owned(),
            signed_timestamp_ms: ts,
        };
        let art = signed_artifact(signer, payload.encode_to_vec());
        let addr = *content_address(&art.signed_payload).unwrap().as_bytes();
        (art, addr)
    }

    fn write_post(dir: &Path, art: &wire::SignedArtifact, addr: &[u8; CONTENT_ADDRESS_LEN]) {
        std::fs::write(dir.join(hex::encode(addr)), art.encode_to_vec()).unwrap();
    }

    fn motd_artifact(signer: &SignKeypair, text: &str, ts: i64) -> wire::SignedArtifact {
        let payload = wire::MotdPayload {
            text: text.to_owned(),
            signed_timestamp_ms: ts,
        };
        signed_artifact(signer, payload.encode_to_vec())
    }

    fn write_signer_file(path: &Path, signer: &SignKeypair) {
        std::fs::write(path, format!("{}\n", hex::encode(signer.public_key()))).unwrap();
    }

    /// (topic, timestamp) of each returned post, for order assertions.
    fn post_order(posts: &[wire::Post]) -> Vec<(String, i64)> {
        posts
            .iter()
            .map(|p| {
                let pl = wire::PostPayload::decode(
                    p.artifact.as_ref().unwrap().signed_payload.as_slice(),
                )
                .unwrap();
                (pl.topic, pl.signed_timestamp_ms)
            })
            .collect()
    }

    /// ISC-16/18/4/3: posts persist as files, load into RAM verified, and
    /// list_posts orders them by signed timestamp within each topic.
    #[test]
    fn load_serves_verified_posts_ordered_within_topic() {
        let signer = keypair(31);
        let server = keypair(99);
        let dir = TempDir::new().unwrap();
        let posts_dir = dir.path().join("posts");
        std::fs::create_dir(&posts_dir).unwrap();
        let wl_path = dir.path().join("signers.txt");
        write_signer_file(&wl_path, &signer);

        for (topic, body, ts) in [("a", "second", 200), ("a", "first", 100), ("b", "only", 50)] {
            let (art, addr) = post_artifact(&signer, topic, body, ts);
            write_post(&posts_dir, &art, &addr);
        }

        let cfg = PublicSpaceConfig {
            posts_dir: Some(&posts_dir),
            motd_path: None,
            whitelist_path: Some(&wl_path),
            taxonomy: &[],
            topics: &[],
        };
        let state = PublicSpaceState::load(&cfg, server.public_key()).unwrap();

        assert_eq!(
            post_order(&state.list_posts(None)),
            vec![
                ("a".to_owned(), 100),
                ("a".to_owned(), 200),
                ("b".to_owned(), 50)
            ]
        );
        assert_eq!(
            post_order(&state.list_posts(Some("a"))),
            vec![("a".to_owned(), 100), ("a".to_owned(), 200)]
        );
    }

    /// ISC-A-S3: a post file that doesn't verify (wrong/absent signature) is
    /// not served — the server serves only what it can verify.
    #[test]
    fn load_skips_unverifiable_post() {
        let signer = keypair(32);
        let server = keypair(99);
        let dir = TempDir::new().unwrap();
        let posts_dir = dir.path().join("posts");
        std::fs::create_dir(&posts_dir).unwrap();
        let wl_path = dir.path().join("signers.txt");
        write_signer_file(&wl_path, &signer);

        let (good, good_addr) = post_artifact(&signer, "a", "real", 1);
        write_post(&posts_dir, &good, &good_addr);
        // A garbage file at a plausible address — never decodes/verifies.
        std::fs::write(
            posts_dir.join(hex::encode([0xAAu8; CONTENT_ADDRESS_LEN])),
            b"junk",
        )
        .unwrap();

        let cfg = PublicSpaceConfig {
            posts_dir: Some(&posts_dir),
            motd_path: None,
            whitelist_path: Some(&wl_path),
            taxonomy: &[],
            topics: &[],
        };
        let state = PublicSpaceState::load(&cfg, server.public_key()).unwrap();
        assert_eq!(
            state.list_posts(None).len(),
            1,
            "only the verifiable post is served"
        );
    }

    /// ISC-3/22: a validated MOTD is served; ISC-24: a missing file hides it.
    #[test]
    fn motd_loaded_when_present_and_hidden_when_absent() {
        let signer = keypair(33);
        let server = keypair(99);
        let dir = TempDir::new().unwrap();
        let wl_path = dir.path().join("signers.txt");
        write_signer_file(&wl_path, &signer);
        let motd_path = dir.path().join("motd.signed");

        let cfg_absent = PublicSpaceConfig {
            posts_dir: None,
            motd_path: Some(&motd_path),
            whitelist_path: Some(&wl_path),
            taxonomy: &[],
            topics: &[],
        };
        let absent = PublicSpaceState::load(&cfg_absent, server.public_key()).unwrap();
        assert!(
            absent.get_motd().is_none(),
            "missing MOTD hides the area (ISC-24)"
        );

        std::fs::write(
            &motd_path,
            motd_artifact(&signer, "welcome", 7).encode_to_vec(),
        )
        .unwrap();
        let present = PublicSpaceState::load(&cfg_absent, server.public_key()).unwrap();
        assert!(
            present.get_motd().is_some(),
            "validated MOTD served (ISC-3/22)"
        );
    }

    /// ISC-26: the MOTD accepts the server's own key as signer, even when that
    /// key is not in the operator whitelist.
    #[test]
    fn motd_accepts_server_key_signer() {
        let operator_signer = keypair(34);
        let server = keypair(99);
        let dir = TempDir::new().unwrap();
        let wl_path = dir.path().join("signers.txt");
        write_signer_file(&wl_path, &operator_signer); // server key NOT listed
        let motd_path = dir.path().join("motd.signed");
        // MOTD signed by the SERVER key.
        std::fs::write(
            &motd_path,
            motd_artifact(&server, "server says hi", 9).encode_to_vec(),
        )
        .unwrap();

        let cfg = PublicSpaceConfig {
            posts_dir: None,
            motd_path: Some(&motd_path),
            whitelist_path: Some(&wl_path),
            taxonomy: &[],
            topics: &[],
        };
        let state = PublicSpaceState::load(&cfg, server.public_key()).unwrap();
        assert!(
            state.get_motd().is_some(),
            "server-signed MOTD accepted (ISC-26)"
        );
    }

    /// ISC-5/6/29: taxonomy + operator whitelist are published; the M6
    /// public-share listing surface exists and is empty.
    #[test]
    fn taxonomy_whitelist_and_shares_published() {
        let signer = keypair(35);
        let server = keypair(99);
        let dir = TempDir::new().unwrap();
        let wl_path = dir.path().join("signers.txt");
        write_signer_file(&wl_path, &signer);

        let taxonomy = vec!["PG13".to_owned(), "R".to_owned()];
        let cfg = PublicSpaceConfig {
            posts_dir: None,
            motd_path: None,
            whitelist_path: Some(&wl_path),
            taxonomy: &taxonomy,
            topics: &[],
        };
        let state = PublicSpaceState::load(&cfg, server.public_key()).unwrap();

        assert_eq!(
            state.taxonomy().labels,
            taxonomy,
            "taxonomy published (ISC-5)"
        );
        assert_eq!(
            state.signer_whitelist().len(),
            1,
            "operator entry published (ISC-6)"
        );
        assert!(
            state.public_shares().is_empty(),
            "F25 listing empty in M6 (ISC-29)"
        );
    }

    // ── Upload / delete (ISC-7/8/19/20 / A-S3) ───────────────────────────

    /// Build a loaded state with `posts_dir`, the given whitelisted signers,
    /// and the given topic set. Posts dir is `<dir>/posts`.
    fn state_with(dir: &Path, signers: &[&SignKeypair], topics: &[String]) -> PublicSpaceState {
        let server = keypair(99);
        let posts_dir = dir.join("posts");
        std::fs::create_dir_all(&posts_dir).unwrap();
        let wl_path = dir.join("signers.txt");
        let mut contents = String::new();
        for s in signers {
            contents.push_str(&hex::encode(s.public_key()));
            contents.push('\n');
        }
        std::fs::write(&wl_path, contents).unwrap();
        let cfg = PublicSpaceConfig {
            posts_dir: Some(&posts_dir),
            motd_path: None,
            whitelist_path: Some(&wl_path),
            taxonomy: &[],
            topics,
        };
        PublicSpaceState::load(&cfg, server.public_key()).unwrap()
    }

    fn delete_artifact(
        signer: &SignKeypair,
        addr: &[u8; CONTENT_ADDRESS_LEN],
    ) -> wire::SignedArtifact {
        let payload = wire::PostDeletePayload {
            content_address: addr.to_vec(),
            signed_timestamp_ms: 1,
        };
        signed_artifact(signer, payload.encode_to_vec())
    }

    /// ISC-7/16: a whitelisted post in a known topic is accepted, persisted to
    /// disk under its content address, and served.
    #[test]
    fn upload_accepts_and_persists_whitelisted_post() {
        let signer = keypair(41);
        let topics = vec!["announcements".to_owned()];
        let dir = TempDir::new().unwrap();
        let state = state_with(dir.path(), &[&signer], &topics);

        let (art, addr) = post_artifact(&signer, "announcements", "hello", 1);
        let returned = state.upload_post(art).unwrap();

        assert_eq!(returned, addr, "returns the content address");
        assert_eq!(state.list_posts(None).len(), 1, "served from RAM");
        assert!(
            dir.path().join("posts").join(hex::encode(addr)).exists(),
            "persisted to disk under content address (ISC-16)"
        );
    }

    /// ISC-7: a post from a non-whitelisted signer is rejected.
    #[test]
    fn upload_rejects_unknown_signer() {
        let whitelisted = keypair(42);
        let stranger = keypair(43);
        let topics = vec!["announcements".to_owned()];
        let dir = TempDir::new().unwrap();
        let state = state_with(dir.path(), &[&whitelisted], &topics);

        let (art, _) = post_artifact(&stranger, "announcements", "hi", 1);
        assert!(matches!(
            state.upload_post(art),
            Err(UploadError::Unauthorized)
        ));
        assert_eq!(state.list_posts(None).len(), 0);
    }

    /// ISC-19: a signer cannot post into a topic outside the operator set.
    #[test]
    fn upload_rejects_unknown_topic() {
        let signer = keypair(44);
        let topics = vec!["announcements".to_owned()];
        let dir = TempDir::new().unwrap();
        let state = state_with(dir.path(), &[&signer], &topics);

        let (art, _) = post_artifact(&signer, "off-topic", "hi", 1);
        assert!(matches!(state.upload_post(art), Err(UploadError::BadTopic)));
    }

    /// ISC-8/20: a signer can delete their own post; the file is removed too.
    #[test]
    fn delete_removes_own_post() {
        let signer = keypair(45);
        let topics = vec!["announcements".to_owned()];
        let dir = TempDir::new().unwrap();
        let state = state_with(dir.path(), &[&signer], &topics);

        let (art, addr) = post_artifact(&signer, "announcements", "bye soon", 1);
        state.upload_post(art).unwrap();
        assert_eq!(state.list_posts(None).len(), 1);

        state.delete_post(delete_artifact(&signer, &addr)).unwrap();
        assert_eq!(state.list_posts(None).len(), 0, "removed from RAM");
        assert!(
            !dir.path().join("posts").join(hex::encode(addr)).exists(),
            "file deleted"
        );
    }

    /// ISC-20: a whitelisted signer cannot delete another signer's post.
    #[test]
    fn delete_rejects_other_signers_post() {
        let author = keypair(46);
        let other = keypair(47);
        let topics = vec!["announcements".to_owned()];
        let dir = TempDir::new().unwrap();
        let state = state_with(dir.path(), &[&author, &other], &topics);

        let (art, addr) = post_artifact(&author, "announcements", "mine", 1);
        state.upload_post(art).unwrap();

        let result = state.delete_post(delete_artifact(&other, &addr));
        assert!(matches!(result, Err(DeleteError::Unauthorized)));
        assert_eq!(state.list_posts(None).len(), 1, "post survives");
    }

    /// Deleting an address with no post is NotFound.
    #[test]
    fn delete_rejects_unknown_address() {
        let signer = keypair(48);
        let topics = vec!["announcements".to_owned()];
        let dir = TempDir::new().unwrap();
        let state = state_with(dir.path(), &[&signer], &topics);

        let result = state.delete_post(delete_artifact(&signer, &[0x11u8; CONTENT_ADDRESS_LEN]));
        assert!(matches!(result, Err(DeleteError::NotFound)));
    }

    /// ISC-2 end-to-end: tonic serves the real PublicSpace service over ONE
    /// already-established `AsyncRead + AsyncWrite` connection (here an
    /// in-memory duplex half standing in for the post-Authenticated TLS
    /// stream), and a client reaches the RPCs and gets real data — an uploaded
    /// post comes back over the wire with the server-asserted content address
    /// the client can re-derive, and the MOTD is empty.
    #[tokio::test]
    async fn serves_public_space_over_single_duplex_connection() {
        let signer = keypair(50);
        let topics = vec!["announcements".to_owned()];
        let dir = TempDir::new().unwrap();
        let state = Arc::new(state_with(dir.path(), &[&signer], &topics));
        let (art, addr) = post_artifact(&signer, "announcements", "over the wire", 1);
        state.upload_post(art).unwrap();

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(serve_public_space(
            server_io,
            PublicSpaceService::new(state),
        ));

        // One-shot connector hands the client-side duplex half to tonic.
        let mut client_io = Some(client_io);
        let channel = Endpoint::try_from("http://[::1]:50051")
            .unwrap()
            .connect_with_connector(tower::service_fn(move |_| {
                let io = client_io.take().expect("connector invoked exactly once");
                async move { Ok::<_, io::Error>(TokioIo::new(io)) }
            }))
            .await
            .expect("in-memory connect over duplex");

        let mut client = PublicSpaceClient::new(channel);

        let motd = client
            .get_motd(wire::GetMotdRequest {})
            .await
            .expect("GetMotd routes")
            .into_inner()
            .motd;
        assert!(motd.is_none(), "no MOTD configured");

        let posts = client
            .list_posts(wire::ListPostsRequest { topic: None })
            .await
            .expect("ListPosts routes")
            .into_inner()
            .posts;
        assert_eq!(posts.len(), 1, "uploaded post served over the wire");
        assert_eq!(
            posts[0].content_address,
            addr.to_vec(),
            "server-asserted address is the client-re-derivable content address"
        );

        // Dropping the client closes the connection; the single-connection
        // server future then resolves.
        drop(client);
        let _ = server.await;
    }
}
