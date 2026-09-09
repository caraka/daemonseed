# Changelog

All notable changes to daemonseed are recorded here, one entry per release.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html) on
the wire protocol (the `0.x` crate versions are tag-driven; `Cargo.toml` stays
`0.1.0`).

**This file plus the SSH-signed git tags are the canonical record of milestone
history** — what shipped, when, under which tag. Each entry corresponds to one
signed tag (`git tag --verify vX.Y.Z`). Nothing else in the repository
duplicates this record: `ISA.md` is the frozen design contract (principles,
boundaries, criteria — not history), live ISC coverage comes from
`cargo xtask isc-coverage`, and in-progress / next-milestone planning lives in
the maintainer's own planning notes, never committed here.

Milestone identifiers (`Mn`) are the internal planning labels; the release tag
is the durable anchor.

## [Unreleased]

Changes that have landed on `main` since the last tag accumulate here; at the
next release this block is renamed to its version + date and a fresh
`[Unreleased]` is opened (see `AGENTS.md` doc-sync). Planning for *unstarted*
work lives in the maintainer's own planning notes, not here.

### Added

- `daemonseed-tui`: a direct-message pane, opened and closed with `[c]` from any pane that does not
  turn a printable key into text, and closed with `Esc`. It lists the pending contact requests and
  then the correspondences, newest first by the last driver event that named one, with both counts
  in its title. `[a]`, `[d]` and `[b]` on a selected request send one `DmCommand::Accept`,
  `Decline` or `Block`, which the binary forwards to the DM driver; `App::dm_pane_open`,
  `App::dm_sel`, `App::dm_requests`, `App::dm_correspondences`, `App::take_pending_dm`,
  `MainFocus::consumes_text`, `app::dm_fingerprint`, `DmCorrespondence::last_activity` and
  `DmState::activity_seq` (#236). Each action sets a one-shot status line and answers a request
  once — a later press on the same request queues nothing. `DmEvent::Message` now folds, creating
  the correspondence row and stamping its recency (#236).
- `daemonseed-core`: `Collection::sweep_give_ups`, `RECEIVE_GIVE_UP_MS` and `AGE_STEP_CAP_MS`
  (`dm::collect`) — the receiving side abandons a gap that has stood below the highest settled
  position for the sender's `GIVE_UP` plus the longest `RESEED_LADDER` rung, advancing the contiguous
  cursor over it and folding the beyond-prefix runs into the prefix. The age accumulates across
  sweeps, each adding at most `AGE_STEP_CAP_MS`. The driver sweeps on the probe cadence and publishes
  an acknowledgement for the moved cursor whether or not the standalone cadence has a live pending
  message (#235).
- `daemonseed-core`: `ProjectAnnounceSeed`, `ProjectAnnounceSeedText`, `ProjectAnnounceSeedSource` and
  `SeedOrigin` — the operator instance's project-announce seed, loaded at runtime from
  `DAEMONSEED_PROJECT_ANNOUNCE_SEED` (read first) or `<profile-root>/project-announce.seed`
  (owner-readable only on Unix), 64 hex characters, and refused unless it derives the baked
  `project_announce_pubkey()`; `PROJECT_ANNOUNCE_SEED_ENV`, `PROJECT_ANNOUNCE_SEED_FILENAME`,
  `PROJECT_ANNOUNCE_SEED_LEN`; `ProjectAnnounceSeedError`, `SeedHexError`.
- `daemonseed-veilid-net`: `OperatorCredential` — the signing keypair and announce owner seed an
  operator instance holds for the session, built from a loaded seed and refused unless the derived
  keys are `project_announce_pubkey()` and `PROJECT_ANNOUNCE_OWNER_PUBKEY`; `OperatorCredentialError`.
  An example,
  `project_announce_pubkeys`, derives the two public keys a seed bakes (seed on standard input,
  never printed).
- `daemonseed-veilid-net`: `DmPageWatch` and `VeilidNetHandle::watch_dm_page` — a DHT watch on one
  receiving channel page, resolving `Changed` on a value change and `Lost` on expiry, on an absent
  record, or when the record is closed or evicted. The watch is cancelled once it resolves
  `Changed` and once its lease expires. The DM driver holds a watch on the current and next
  receiving page and sweeps that page on a change, at most six times per page per probe interval;
  a change inside that floor, or one arriving while that page's sweep is in flight, is swept by the
  next tick clear of it. Value changes on channel-page records are never surfaced as
  `VeilidNetEvent::Inbound` or `VeilidNetEvent::ValueChanged`. The 30-second probe cadence is
  unchanged and collects every page whether or not a watch is standing (#234).
- `ISC-A-S27`: no byte in the source tree derives the project-announce signing key or the announce
  owner key.
- `.github/workflows/ci.yml` — the Definition-of-Done gate on every pull request and on `main`,
  one job per gate group.
- `cargo xtask gate` — runs the Definition-of-Done gate, `--group <preflight|dev-suite|release-suite>`
  for one group and `--list` for the step table. A test step reporting zero passing tests is red.
- A `cargo doc --workspace --no-deps` step under `RUSTDOCFLAGS=-D warnings` in the gate table.
- Coverage for the first-contact teardown across a re-establishment: a re-seeded introduction from
  an established correspondent leaves a resumed channel and its queue alone, and a fresh
  first-contact entry from that correspondent ends every pending entry under
  `TeardownCause::CorrespondentStateLost`. The direction the teardown names is read off the key
  schedule a completed re-establishment restores (#261).
- Coverage that the entries such a teardown ends stop re-seeding: no further page is published for
  them across the first rungs of `RESEED_LADDER`, and their failure reaches the user once (#261).
- `DmEvent::Roster { correspondents: Vec<Correspondent> }`, emitted once before the DM driver's
  first tick: every correspondence on disk under `CorrespondentState::Established`, `Pending` or
  `Blocked`. `DmEvent::BlockListUnreadable` rides alongside it where the block-list record would not
  read. Both front ends fold it onto `DmCorrespondence::state`; nothing renders it.
- `crates/daemonseed-veilid-net/tests/two_node_dm_restart.rs` — a two-node network oracle,
  `#[ignore]`: a sender that restarts between its knock and the acceptance composes a frame its
  correspondent opens, and a correspondence whose stores both restarted and then re-established on
  one committed root refuses a `DmCommand::Send` with `RefusalReason::NotEstablishedThisSession`,
  spending no sequence number (#401, #402).
- A `DmCommand::Send` on a correspondence whose channel was resumed by a completed
  re-establishment is refused with `RefusalReason::NotEstablishedThisSession`, before the outbox is
  asked and before the ratchet steps. Content frames on a resumed channel are unbuilt (#401, #402).
- `daemonseed_core::identity::keys::SignKeypair::from_halves(&pk, &sk)` and
  `daemonseed_core::dm::persist::PendingHandshake::signing_pc()`, which return the
  per-correspondent keypair a stored record holds. A correspondence rebuilt at load takes it from
  the resume record, and one whose first-contact entry is unanswered takes it from the provisional
  record when its handshake is re-armed (#401, #402).
- `daemonseed_core::dm::domain` — `DM_REEST_ROOT`, `DM_REEST_NEXT` and `DM_REEST_CHAN_ID`, the
  domain labels for the retained re-establishment root, its successor, and a resumed channel's
  identifier (#404).
- `daemonseed_core::dm::firstcontact::ChannelRoots` — an `rs0` field carrying the retained
  re-establishment root, the fourth Expand sibling of the `ss0` extraction (#404).
- `daemonseed_core::dm::resume` — `Rerooted` and `reroot(&CommittedRoot, &[u8; SHARED_SECRET_LEN])`,
  yielding the successor retained root, the re-rooted ratchet root and the resumed channel's
  identifier from one call. `Rerooted::chan_id()` returns the identifier (#404).
- `daemonseed_core::dm::reest` — `mint_ephemeral()`, `answer(&CommittedRoot, &ek)` and
  `complete(&CommittedRoot, EphemeralDecapKey, &ct)`, the ML-KEM operations a re-establishment
  performs. The shared secret does not leave the crate (#404).
- `daemonseed_core::dm::resume::OwnSlot` — an `eph_dk` field holding the secret half of the
  ephemeral its `RE-EST` published, sealed and zeroized with the slot. `OwnSlot::new` takes it
  (#404).
- `daemonseed_core::dm::ratchet` — `Ratchet::reestablished` and `ReconnectSide`, opening a ratchet
  on a re-rooted root with the clear generation and the send sequence continuing. It takes the
  agreed generation, one number on both sides. Both `ReconnectSide` variants carry
  `last_persisted_generation`; a generation that is not ahead of it is refused with
  `RatchetError::ReestablishedGenerationNotAhead { generation, persisted }` on either side (#404).
- `daemonseed_core::dm::ratchet::Ratchet::can_send() -> bool` — whether a chain is in hand to mint
  from, or a peer ephemeral to open one against (#404).
- `daemonseed_core::dm::reest::agreed_generation(own_floor: u32, peer_floor: u32) -> u32` — the clear
  ratchet generation a resumed channel opens at, one past the higher of the two floors, saturating at
  `u32::MAX` (#404).
- `daemonseed_core::dm::resume::AcceptanceSlot` carries the floor generation the answer advertised:
  `AcceptanceSlot::accept` takes it and `AcceptanceSlot::advertised_floor()` reads it. The at-rest v2
  body gains the field inside its fixed-width run, so a v2 record written before it existed fails to
  decode as `ResumeError::Truncated`; no released build wrote one.
  `ResumeError::AcceptanceFloorWithoutAttempt` refuses a floor beside an empty slot (#404).
- `daemonseed_core::dm::outbox` — `Outbox::sweep_dead_chain(u32)`, `Outbox::next_send_seq()`,
  `Outbox::last_clear_gen()` and `OutboxEntry::sealed_under_gen()` (#404).
- `daemonseed_core::dm::resume` — `ResumeRecord::commit_reestablished(Rerooted, u32, i64) ->
  Zeroizing<[u8; ROOT_KEY_LEN]>`, returning the resumed channel's identifier, and
  `ResumeRecord::reroot_ratchet_gen()`; `ReEstState` gains `reroot_ratchet_gen` (#404).
- `daemonseed_core::dm::reest` — the three A9 channel re-establishment legs. A leg is one
  AES-256-GCM envelope over a plaintext padded to 8192 bytes, `LEG_LEN` on the wire for all three
  kinds, with no clear kind, generation, seq, attempt or direction field and no AAD. The seal key is
  `K(RS_n, gen, seq, attempt, leg, dir)` under `DM_REEST_SALT` / `DM_REEST_LEG`; the plaintext
  carries the leg's payload followed by an ML-DSA-87 signature over `DM_REEST_SIG`, the same five
  values and the payload, signed under `S_pc` and verified under the peer's `PK_pc`. `seal_re_est` takes a
  `FreshAttempt`; `seal_re_ack` takes a `ReAckAuthority` minted only by `OpenedReEst::answer` and the
  answering party's floor generation, read back by `OpenedReAck::floor_gen()`; `seal_re_confirm` takes
  an `Attempt` and the agreed generation, read back by `OpenedReConfirm::agreed_gen()`. Both fields
  are big-endian `u32`s inside the payload the leg's signature covers and the leg's AEAD, and
  `LEG_LEN` is unchanged. `scan_re_est` / `scan_re_ack` / `scan_re_confirm` recover a
  leg by bounded trial decryption over the attempt window `[last_seen, last_seen + MAX_GAP]`.
  `tiebreak_winner` is the contest coin, the least-significant bit of the first byte expanded under
  `DM_REEST_TIEBREAK`; `contest_outcome` is the local contest check. `ReEstGate::admit` evaluates
  duplicate detection before the response budget. `AttemptBudget` is the toward-`C` count, exhausted
  at `ATTEMPT_CEILING`. `ATTEMPT_CEILING` is 8 and `MAX_GAP` equals it; both are placeholders for the
  design's tunable `C`. (#404)
- `DM_REEST_SALT`, `DM_REEST_LEG`, `DM_REEST_TIEBREAK` and `DM_REEST_SIG` in
  `daemonseed_core::dm::domain` — the re-establishment label family. (#404)
- `daemonseed_core::dm::resume::ResumeRecord::open_attempt(seq, SealedReEst, EphemeralDecapKey)` —
  occupy the own-initiation slot at `reconnect_gen + 1` and advance the attempt counter in one act.
  Refused on an occupied slot (`ResumeError::AttemptAlreadyOpen`) and on an attempt that does not
  advance the counter (#404).
- `daemonseed_core::dm::resume::OwnSlot` — a `seq` field carrying the outbox position its sealed
  `RE-EST` was addressed to; `OwnSlot::new` takes it and `OwnSlot::seq()` reads it. `seq` is bound
  into the leg's seal key and signature preimage, so a re-emit has no other way to reach the position
  the peer reads (#404).
- `daemonseed_core::dm::resume::ResumeRecord::abandon_attempt()` — empty the own-initiation slot
  while the attempt counter stands still, which is A3.8's give-up. `commit_resume` admits an empty
  slot at an unchanged generation exactly when the counter has not moved; a slot emptied under a
  fresh attempt is still `ResumeError::OwnSlotAbandonedWithoutAcceptance` (#404).
- `daemonseed_core::dm::outbox::OutboxTarget::ReEstablishmentLeg` — a channel-paged entry the
  dead-chain sweep and the give-up sweep both skip. A leg hangs off no ratchet chain, so the target rather than a generation
  carries A3.12's exempting provenance (#404).
- `daemonseed_core::dm::outbox::ReseedSchedule::deferred(now_ms)`,
  `OutboxEntry::defer_first_dispatch(now_ms)`, `RECONNECT_FIRST_DISPATCH` and
  `RECONNECT_JITTER_FRAC` — a first emission due at a delay drawn from A5.5's reconnect-cadence band
  rather than at the enqueue instant, with the rung unspent. Refused past the first dispatch
  (`OutboxError::FirstDispatchPassed`) (#404).
- `daemonseed_veilid_net::dm` — the DM driver's load-time re-establishment pass. On the first tick
  after a load, an established correspondence runs the dead-chain sweep against its resume record's
  re-root generation, and — where the outbox holds pending mail — seals a `RE-EST` under the
  committed re-establishment root, commits it to the resume record, and queues it on its own
  direction record under `OutboxTarget::ReEstablishmentLeg` with a first dispatch drawn from A5.5's
  reconnect-cadence band. A persisted attempt is re-emitted as the stored bytes at the sequence the
  own slot records, never resealed (#404).
- `daemonseed_veilid_net::dm` — the re-establishment exchange. A queued leg is published to this
  side's direction record at `msg_addr(dir, seq)`, derived from the address root and the outbox's
  stored direction rather than from a key schedule. A swept slot the ratchet cannot open, or that
  arrives at a correspondence holding no key schedule, is trial-decrypted as the leg kinds the
  resume record says this side expects: `RE-ACK` while an initiation stands, `RE-CONFIRM` while an
  unconfirmed acceptance stands, `RE-EST` at one past the committed generation, and `RE-EST` under
  the retained root at the generation an open exchange is at. An opened `RE-EST` is deduped, put to
  the contest coin, admitted through `ReEstGate` under a per-session response-emission cap, answered
  with a `RE-ACK` sealed under the root it opened under, committed, and then queued. An opened
  `RE-ACK` at or above the current attempt completes: the record advances, the settling `RE-CONFIRM`
  is sealed and queued, and the resumed ratchet opens one position past it. An opened `RE-CONFIRM`
  settles the exchange this side answered, advancing the generation and retiring the superseded
  root. A completion runs the dead-chain sweep and ends the legs the exchange finished with. A
  correspondence with no key schedule sweeps its receiving pages, and an acceptor's knock position
  is re-settled at load. Every tick runs one idempotent upkeep pass per established correspondence:
  the retention ceiling, the initiating side's confirming observation, a re-queue of any stored leg
  whose entry is absent, the retirement of a leg no slot names, and the give-up of a leg unanswered
  for seven days. A fold that opened a leg and could not finish leaves the position unsettled and
  writes nothing. **Ordinary mail after a re-establishment is NOT sealed** — a channel frame
  binds this side's own `PK_pc`, which no record holds after a restart (#404).
- `daemonseed_core::dm::paging` — `DmPageAddress::sending_on` and `DmPageAddress::receiving_on`,
  taking an explicit `Direction` in place of a `Ratchet` (#404).
- `daemonseed_core::dm::ratchet::Direction::opposite()` (#404).
- `daemonseed_core::dm::resume` — `ResumeRecord::accept_peer_initiation(Rerooted, AcceptanceSlot,
  bool, i64) -> Zeroizing<[u8; ROOT_KEY_LEN]>`, `ResumeRecord::confirm_acceptance(u32) -> bool`,
  `ResumeRecord::take_own_slot() -> Option<OwnSlot>`, `ResumeRecord::set_window_anchor(u32)` and
  `OwnSlot::into_eph_dk()` (#404).
- `daemonseed_core::dm::outbox` — `Outbox::retire_leg(u64) -> bool` ends a leg the handshake
  finished with (`ConfirmedCollected`); `Outbox::abandon_leg(u64) -> bool` ends one that will never
  be opened — a conceded initiation or a leg past its give-up — as `Undelivered`. Both leave
  `Surfacing::Clear` and refuse any entry that is not a pending leg (#404).
- `daemonseed_core::dm::resume` — `ConfirmSlot`, the sealed `RE-CONFIRM` a completed exchange
  persists, with `ResumeRecord::confirm_slot()` and `ResumeRecord::retire_confirm()`;
  `AcceptanceSlot::accept` takes the outbox sequence its answer was addressed to and
  `AcceptanceSlot::seq()` reads it; `ResumeRecord::commit_reestablished` takes the `ConfirmSlot`.
  The at-rest v2 body gains the acceptance slot's `seq`, the confirm slot's generation and sequence,
  and the sealed `RE-CONFIRM`, extended in place because no released build has written the layout
  (#404).
- `daemonseed_core::dm::resume::T_RETIRE_MS` — A3.5's retention ceiling at fourteen days, the
  design's suggested value (#404).
- `daemonseed_core::dm::persist::DmPersist::commit_resume` guards the confirm slot: a stored
  settling leg is not dropped, re-sealed at one generation, or rolled back to an earlier one, except
  by its confirming observation — which retires the retained root in the same write — or by a later
  exchange. `ResumeError::ConfirmSlotDropped`, `ConfirmResealed` and `ConfirmSlotWouldRollBack`
  (#404).
- `daemonseed_core::trust_events::TrustEventKey` — `DmPeerStateRegressed`,
  `DmReestablishmentFailed`, `DmReestablishmentUnconfirmed` and `DmReestablishmentBackoffEngaged`,
  A3.8's loud re-establishment states, all `PersistentNonBlocking` (#404).
- `daemonseed_veilid_net::dm::DmEvent::ReestablishmentAnomaly { with, event }` — one variant for
  that family, named by its classed key; routed to the audit log by both front ends (#404).
- `daemonseed_veilid_net::dm::DmEvent::ChannelHealth` — `leg_folds_deferred` and
  `leg_unaddressable` (#404).
- `daemonseed_tui::net` / `daemonseed_gui::net` — the front-end DM contract. `NetCommand::Connect`
  carries `dm_session_keys: Option<DmSessionKeys>` (the full identity KEM keypair, the doorbell slot
  secret and the profile at-rest key); the net actor moves it into `DmDriverParts` and spawns a
  `DmDriver` beside itself, one per connect, sending `DmCommand::Shutdown` to any prior driver and to
  the current one when the command channel closes. `NetCommand::Dm(DmCommand)` is forwarded to that
  driver through `DmDriverHandle::try_send`, and `NetHandle::dm(cmd)` is the UI-side wrapper; a
  command arriving with no driver running, or with a full one, is dropped rather than awaited.
  `NetEvent::Dm(Arc<DmEvent>)` carries the driver's events back. The driver runs
  `AdmissionPolicy::Open` with `PowDifficulty::PRODUCTION`, a 30-second idle tick, no spent-token
  store, and a `DmPersist` opened at `<profile root>/dm` under the profile's at-rest key. It is
  started with `DmDriver::try_spawn` and shut down on the next `Connect` — reached whether or not
  the transport came up — on `NetCommand::GracefulClose`, and when the command channel closes.
  Partial (#339): the refusal reaches the front end's state, not yet the user. (#232, #339)
- `daemonseed_tui::app::DmState` and `daemonseed_gui::state::DmState` — the DM state a session
  accumulates from `DmEvent`: held contact requests, per-correspondence delivery states and
  undelivered sequence numbers, the last refusal, and the last doorbell and channel health reports.
  Folded by `App::on_net_event` and `GuiState::on_dm_event`; nothing is rendered from it. The
  held-request list is capped at `PENDING_REQUEST_CAP`, oldest dropped, because no event retires a
  request. `Debug` prints body lengths and redacted identity keys, as `DmEvent`'s own does. Partial
  (#339). (#339)
- `daemonseed_tui::app::App::dm_session_keys` / `dm_state`, `daemonseed_gui::state::GuiState::dm_session_keys`
  / `dm_state` / `on_dm_event`, and `daemonseed_gui::profile::Profile::dm_session_keys`. (#339)
- `daemonseed_core::storage::seeds::SealingKey::to_bytes` — the raw at-rest key as a
  `Zeroizing<[u8; AEAD_KEY_LEN]>`, for a record store that takes it by reference rather than through
  the type. (#339)
- `daemonseed_veilid_net::dm::DmDriver::try_spawn` and `DmSpawnError` — the startup conditions
  `DmDriver::spawn` panics on, reported instead. The three fallible steps — both owner-seed
  derivations and the block-list provision — run on the caller's thread, so a read-only or full
  profile directory would otherwise kill a caller that has other work. `spawn` remains the panicking
  wrapper. (#339)
- `daemonseed_veilid_net::dm::DmDriverHandle::try_send` and `DmTrySendError` — queue one command
  without waiting. `send` applies backpressure to its caller, which is wrong for a shared actor loop
  where a full DM queue would stall every other command. (#339)
- `daemonseed_veilid_net::dm::PENDING_REQUEST_CAP` — the driver's held-request bound, made public so
  a front end's own list is bounded by the same number rather than a second one. (#339)

- `daemonseed_core::dm::frame::seal_accept(outbound, chan_id, signing_pc, signing_lt, recipient_hash, sent_unix_ms, ack)` — the acceptor's ACCEPT: an ordinary channel frame at the acceptor's sequence zero with an empty body, carrying `pk_pc` and `bind_lt` in the sealed body. (#234, #236)
- `daemonseed_core::dm::frame::ParsedFrame::open_accept(key, chan_id, dir, found_at, recipient_hash, peer_pk_lt) -> VerifiedAccept` — opens that frame with no prior pseudonym, verifying `bind_lt` under the peer's long-term key. `VerifiedAccept { frame, peer_pk_pc }`. (#234, #236)
- `daemonseed_core::dm::frame::DmFrameError` — `Binding`, `MissingBinding`, `PseudonymMismatch` and `NotAccept { seq }`. (#234, #236)
- `daemonseed_core::dm::persist::PendingHandshake::ratchet()` / `commit()` — derive the initiator's ratchet without erasing the provisional record, and erase it. `establish()` remains the pair. (#234, #236)
- `DmChannelBody.pk_pc` (tag 6) and `DmChannelBody.bind_lt` (tag 7) — the acceptor's pseudonym key and its long-term binding, empty on every other frame. Wire-visible, MINOR. (#234, #236)
- `daemonseed_veilid_net::dm::RefusalReason` / `AcceptFailure` — why a first contact stopped, and why
  an accepted request was not established. `DmEvent::Refused` carries the first; the new
  `DmEvent::AcceptFailed { request, from, reason }` carries the second and leaves the request held.
  (#236)
- `daemonseed_veilid_net::dm::DmEvent` — `ChannelLost` carries the `surfaced` sequence numbers the
  user is owed; `DoorbellHealth` carries admission's running `AdmissionCounters`; new variants
  `ChannelDirectionUnknown`, `ContactLookupFailed`, `BlockListProvisioned` and
  `SpentTokensNotPersisted`. `DoorbellHealth` also carries `pending_full`, the slots this sweep
  skipped because the held-request list was full. `RefusalReason::TaskPanicked` is a panicked
  transport task, distinct from `MintPanicked`. (#236)
- `daemonseed_core::dm::outbox::Outbox::room_for(seq, target, frame_len)` — whether a sealed entry of
  that size would be accepted, priced by the same gate `enqueue_sealed` passes. (#236, #339)
- `daemonseed_core::dm::collect::Collection::resuming_from_page(page)` — a collection whose probe
  frontier starts at a persisted cursor's page; the settled set is not restored. (#236)
- `daemonseed_core::dm::ratchet::Ratchet::next_send_seq` — the sequence number the next `send_next`
  will place on a message. (#236, #339)
- `daemonseed_veilid_net::dm::DmEvent::ChannelHealth { with, partial_sweeps, already_consumed,
  unopenable, peer_pseudonym_unknown, peer_acks_deferred }` — one correspondence's channel-plane
  accounting, cumulative per session, emitted only when a counter moves. (#236)
- `daemonseed_veilid_net::dm::RefusalReason` — `OutboxFull { needed }`, `NotEstablishedThisSession`,
  `BodyTooLarge` and `SealFailed`. (#236, #339)
- `daemonseed_veilid_net::dm::DmEvent::ChannelHealth` counts `peer_pseudonym_unknown`: an initiator
  learns no pseudonym for its correspondent, so it verifies nothing and does not sweep. (#236)
- `daemonseed_core::dm::admission::SeenSet::forget` — un-record one entry hash, for a caller that
  abandoned an entry's verification rather than finishing it. (#236)
- `daemonseed_core::dm::persist::DmPersistError::AlreadyEstablished` — `accept_first_contact` refuses a
  second correspondence for one identity key rather than minting a second label. (#236)
- `daemonseed_core::dm::spent_store::read_from` / `write_to` — read the sealed spent-token set at a
  path (`Ok(None)` when absent, an error when present and unopenable) and replace it atomically.
  `SpentStoreError` gains `Io` and `Replace`. (#236)
- `daemonseed_veilid_net::dm` — the DM driver's doorbell half. On its cadence the driver sweeps its
  own doorbell and runs each populated slot through `daemonseed_core::dm::admission::Admitter`;
  an admitted knock from a stranger is held and surfaced as `DmEvent::ContactRequest`, one from a
  blocked identity surfaces nothing, and one from a known correspondent reaches
  `DmPersist::correspondent_state_lost` and surfaces `DmEvent::ChannelLost`. `DmCommand::Accept`
  establishes the correspondence through `DmPersist::accept_first_contact`; `Decline` drops the held
  request and writes nothing; `Block` / `Unblock` update the block list, with a refused 513th entry
  surfacing as the new `DmEvent::BlockListFull { count }`. `DmCommand::FirstContact` fetches the
  recipient's key record, mints the entry on a blocking thread, then writes the provisional record
  and publishes the knock; an absent key record publishes nothing and surfaces `DmEvent::Refused`.
  `DmDriverConfig` gains `policy` and `pow_difficulty`; `DmDriverParts` gains `spent_tokens`, a
  `SpentTokenStore`. `DmDriver::spawn` derives the identity's own owner seeds, provisions the block
  list and opens the spent-token set before the task starts, and panics if any of them fails; an
  invite-only policy with no `spent_tokens` panics likewise. A doorbell sweep retires the seen set
  and prunes the spent set, drops held requests whose admitting epoch has left the accept window,
  forgets slots the doorbell no longer holds, and ends before recording anything when the block list
  will not read. A slot arriving at a full held-request list is skipped before admission rather than
  discarded after it, and a slot whose contact lookup failed is left unrecorded — both are read
  normally on a later sweep. A panicked spawned job is attributed to what it was doing: a mint or a
  transport task releases its introduction, a spent-token write poisons the store. `FirstContact` is refused
  when a correspondence with that identity already exists or an introduction to it is in flight, and
  reuses one provisional label per recipient. A spent-token set that will not open poisons the store
  for the life of the driver rather than being written over. (#236)
- `daemonseed_veilid_net::dm::SpentTokenStore` — where a profile's consumed invite-token nonces are
  sealed, by profile root, passphrase, profile id and Argon2id parameters. (#236)
- `daemonseed_core::dm::persist::DmPersist::accept_first_contact` — mints a correspondence label,
  opens the recipient ratchet and writes the contact record from a verified knock, in one call.
  (#236)
- `daemonseed_core::dm::persist::DmPersist::provision_block_list` — writes an empty block list when
  the profile has none, and reports whether it wrote. (#236)
- `daemonseed_core::dm::provisional::Teardown::into_cause` — the teardown's cause, by value. (#236)
- `daemonseed_core::dm::admission::AdmissionOutcome::Admitted` carries `entry_hash`, the value step 2
  computed over the admitted entry. (#236)
- `daemonseed_veilid_net::dm` — the DM driver's seam and harness. `DmDht`, a trait over the seven DM
  DHT operations returning `DmDhtFuture<T>`, implemented for `VeilidNetHandle`. `DmDriver::spawn`
  takes `DmDriverParts` (`dht`, `clock`, `identity`, `persist`, `cfg`) and returns a
  `DmDriverHandle` plus an `mpsc::Receiver<DmEvent>`; the driver wakes on `cfg.idle_tick`, performs
  no DHT operation, and ends on `DmCommand::Shutdown` or on the last handle dropping, aborting
  whatever is in flight. A zero `idle_tick` panics at construction. Adds `DmCommand`, `DmEvent`,
  `RequestId`, `PkLt`, `DmIdentity`, `DmDriverConfig`, and `WallClock` (unix milliseconds injected
  as a closure). `DmCommand` and `DmEvent` redact message bodies and identity keys in `Debug`.
  `dm.rs` becomes `dm/mod.rs` with `seam`, `types`, `machine` and `driver` siblings. (#235, #236)
- `daemonseed_core::identity::keys::IDENTITY_PK_LEN` — the width of a long-term identity public key
  in bytes.
- `daemonseed_core::dm::persist` — `DmPersist::correspondent_state_lost`, which answers an opened
  first-contact entry against what is stored and stops that correspondence's outbox where the entry
  means the correspondent lost their at-rest state. `StateLoss::NoCorrespondence` for an identity no
  correspondence holds, `StateLoss::SameChannel` for an entry addressing the recorded channel (an
  introduction re-seeded, which changes nothing), `StateLoss::Confirmed` for an entry under a channel
  the store does not hold — which ends every pending entry as `Undelivered` and surfaces it at once,
  without waiting out the `GIVE_UP_MS` window, carrying a `Teardown` for the reason.
  `DmPersistError::AmbiguousCorrespondent` is propagated and nothing is marked. An idle queue is
  not written. **Breaking (crate API):** `DmPersistError` gains a `FirstContact` variant. (#261)
- `daemonseed_core::dm::persist` — `DmPersist::peek_channel_restart`, which returns the same
  `StoredChannelRestart` arms as `restart_channel` and writes nothing: it deletes no lingering
  provisional record and takes no lock. `DmMachine::provisional_label`'s scan across stored
  correspondences uses it.
- `daemonseed_core::dm::persist` — `DmPersist::sweep_lingering_provisionals() -> Result<usize, DmPersistError>`
  deletes every provisional record left beside a readable resume record and reports how many. A
  store that will not enumerate is an error; a single correspondence that will not read is skipped.
  The DM driver runs it once when it rebuilds its correspondences from the store.
- `daemonseed_core::dm::contact_cache` — `ContactRecord::addresses_same_channel`, which reports
  whether an address root is the one this record stores. The comparison is not
  constant-time. It holds only under one at-rest store per `pk_lt`, which nothing enforces. (#261)
- `daemonseed_core::dm::contact_cache` — `ContactRecord::new` and `decode` refuse an all-zero
  address root as `ContactCacheError::PlaceholderAddressRoot`. **Breaking (crate API):**
  `ContactCacheError` gains a `PlaceholderAddressRoot` variant. (#261)
- `daemonseed_core::dm::provisional` — `TeardownCause::CorrespondentStateLost`, the fourth cause and
  the only one under which `Outbox::channel_torn_down` ends an `AwaitingCollection` entry. Its
  `TeardownOutcome::retained` is always empty. (#261)
- `daemonseed_core::trust_events` — `TrustEventKey::DmCorrespondentStateLost`, class
  `PersistentNonBlocking`, stable string `dm-correspondent-state-lost`. (#261)
- `daemonseed_core::dm::persist` — `DmPersist::correspondence_for_pk_lt`, which names the
  correspondence whose contact record holds a given long-term identity key. It is a scan of
  the store's correspondences and their contact records, not a stored index, and is
  lock-free. `Ok(None)` is no match; two or more matches is
  `DmPersistError::AmbiguousCorrespondent`, carrying the count and no label. A
  correspondence with no contact record is skipped; a contact record that exists and will
  not decode fails the whole lookup. **Breaking (crate API):** `DmPersistError` gains an
  `AmbiguousCorrespondent` variant. (#261)
- `daemonseed_core::storage::dm_store` — `DmStore::correspondences`, the sorted list of every
  correspondence established under the store root, taken without the lock and creating
  nothing. A root entry counts when its name is a label's lower-case hex directory form and
  resolves to a directory, so the profile lock and the profile-scoped records are excluded by
  name. A listed correspondence may hold no record. An unreadable root, or a per-entry IO
  error that is not `NotFound`, is a `DmStoreError`. (#261)
- `daemonseed_core::dm::block_list` — `BlockList::encode` and `BlockList::decode`, the
  block list's at-rest form: every blocked long-term identity key concatenated in ascending
  byte order, with no header, count or occupancy map. `BLOCK_LIST_MAX_ENTRIES` (512) is the
  ceiling and `BLOCK_LIST_CAPACITY` a full list's payload size. `encode` refuses a list over
  the ceiling with `BlockListError::Full` before any write; `decode` gives `Full` at the same
  ceiling, `NotWholeKeys` for a payload that is not a whole number of ML-DSA-87 public keys,
  and `NotAscending` for keys out of order or repeated. (#390)
- `daemonseed_core::dm::persist` — `DmPersist::read_block_list` and
  `DmPersist::update_block_list`, the block list's path to and from the DM at-rest store.
  `read_block_list` is lock-free; an absent record is `DmPersistError::BlockListMissing`,
  never an empty list. `update_block_list` is read-modify-write inside one profile critical
  section and writes on every call, spending one seal whether or not the list changed;
  nothing is written if the caller's closure fails or the resulting list is over the ceiling.
  **Breaking (crate API):** `DmPersistError` gains `BlockList` and `BlockListMissing`
  variants. (#390)
- `daemonseed_core::storage::dm_store` — profile-scoped records, held at the store root
  rather than in a correspondence directory. `RecordScope` and `RecordKind::scope` name a
  kind's scope; `RecordKind::BlockList` is the block list's, sealed under
  `DM_STORE_PROFILE_AAD`, which binds the record kind and no correspondence label.
  `DmStore::read_profile_unlocked` reads one without the lock, and
  `DmStore::profile_critical_section` yields a `LockedProfile` guard carrying `read`,
  `present` and `replace`, with no `delete`. Both guards refuse a kind of the other scope.
  **Breaking (crate API):** `DmStoreError` gains a `WrongScope` variant and `RecordKind` a
  `BlockList` variant. (#390)
- `daemonseed_core::storage::atomic_file` — `FileLock::try_acquire` takes the lock if it is
  free and returns `Ok(None)` if another holder has it, never blocking. (#390)
- `daemonseed_core::dm::persist` — `DmPersist::read_contact` and
  `DmPersist::update_contact`, the contact record's path to and from the DM at-rest
  store. `read_contact` is lock-free and creates nothing; a stored record that will
  not decode is `DmPersistError::Contact`, never `Ok(None)`. `update_contact` is
  read-modify-write inside one critical section, takes a seed closure built only when
  the correspondence has no record, and writes a stored record back only on
  `Mutation::Changed`; a seeded record is written whatever the closure reports.
  **Breaking (crate API):** `DmPersistError` gains a `Contact` variant. (#236)
- `identity::OwnerSeed`, `identity::OwnerPublic` and `identity::RendezvousOwner` in
  `daemonseed-veilid-net`: how a party holds a rendezvous record's owner, either `Held`
  (the owner seed) or `PublicOnly` (the owner public key). An `OwnerPublic` is
  constructible only by the one-way derivation from an `OwnerSeed` or from a key baked
  into the source — there is no `From<[u8; 32]>` and no public field.
- `identity::owner_public_key` and `identity::PROJECT_ANNOUNCE_OWNER_PUBKEY`: the VLD0
  public key naming a rendezvous owner, and the baked owner public key of the
  project-announce/MOTD record. Together they name that record's DHT address with no
  owner secret derived or held; they confer no write capability. (ISC-15)
- Two-node integration test for the direct-message acknowledgement record: one node publishes
  a state with gaps, the other derives the same record, fetches it, verifies it and merges it
  under its own ceiling. (#235)
- Direct-message acknowledgement piggyback: `DmChannelBody` carries `ack_high_water` and
  `ack_beyond`, bound in `msg_sig` and surfaced as `VerifiedFrame::peer_ack`. A channel
  frame reserves `WORST_CASE_ACK_FIELDS_LEN` when choosing its padding rung, so the rung
  does not vary with whether an acknowledgement rode along. **BREAKING (MAJOR wire):** the
  channel frame's signature preimage now binds these two fields, so a frame sealed by a
  build without them does not verify against one with them, in either direction.
  **Breaking (crate API):** `frame::seal` and `frame::frame_sig_input` take the
  acknowledgement as a new argument, and `DmFrameError` gains a `PiggybackedAck` variant.
- `cargo check --workspace --release` runs as a `pre-push` gate and a `release-gate` step,
  covering code that compiles under `debug_assertions` and not in the release profile. (#381)
- `cargo xtask check-ui-strings` refuses placeholder text in any string a user can read,
  and runs as a `release-gate` step.
- Direct-message doorbell transport: a first-contact entry publishes into a slot of the
  recipient's world-derivable doorbell record, and a recipient sweeps all 32 slots of its own.
  A user's first send is classified `Chat`; a scheduler re-dispatch is `Keepalive`. (#233)
- First-contact admission: a knock carries a SHA-384 hashcash proof of work bound to the entry,
  the recipient and the epoch, plus an invite token bound to its grantee and redeemable once.
  A verifier disposes of a doorbell slot cheapest-check-first, admitting an entry to the
  duplicate-suppression set only once its proof of work has been paid. (#233)
- `daemonseed_core::dm::spent_store` — the spent-invite-token set's home at the profile root,
  sealed under its own key. (#233)
- `TrustEventLog::unreadable_entries` reports how many persisted entries this build could not
  read. (#337)
- `ArgonParams::is_openable` bounds the Argon2 cost an opener will honour from a file
  header. (#337)
- `cargo xtask check-manifests` parses every LAMA manifest with duplicate-key detection at
  the YAML event level and fails on a repeat, which an ordinary loader discards silently.
  Covers `docs/llm-api-manifest/*.yaml` and the root `lama.yaml`, and runs as part of
  `release-gate`. (#326)

- `daemonseed_core::dm::resume` — the A9.2 re-establishment resume record.
  `ResumeRecord` carries `S_pc`/`PK_pc`, the committed re-establishment root,
  the `attempt` counter, the sealed RE-EST frame bytes, the send-side floor, the
  window anchor and the toward-`C` count in one blob. `SendFloor` is
  `(generation, seq)` and orders lexicographically, so a generation bump is not
  a rollback. `SealedReEst` binds the sealed frame to the `Attempt` it was
  sealed under; `SealedReEst::seal` consumes a `FreshAttempt`, minted solely by
  `Attempt::advance` and `FreshAttempt::first`, so it cannot be called with an
  attempt already in hand (A9.1). `ResumeRecord::decode` rebuilds the pairing
  from at-rest bytes without a token, so the store remains the enforcement
  point. `DmPersist::commit_resume` writes the record and returns the
  sealed bytes to emit; `read_resume` reads it back. `RESUME_CAPACITY` is now
  checked against a computed worst case rather than estimated.

- Re-keyed the write funnel's FIFO and coalescing scope onto the owner's public
  key at every enqueue site, through one `funnel_record_key` helper; four sites
  still passed the raw owner seed while the DM page site used the public key. The
  mapping is injective and all four moved together, so no coalescing group
  changes. (#256)

- `daemonseed_core::dm::paging` — a page address is checked against the ratchet's
  conversation. `Ratchet` carries `ar_fingerprint()`, derived at construction from
  the `ss0` it already takes, and `DmPageAddress::sending` / `::receiving` refuse a
  root that does not match it with `DmPageError::ConversationMismatch`. Previously a
  caller holding two channels could resolve one conversation's root against the
  other's ratchet and receive a valid, wrongly-directed address; frames are
  individually authenticated, so the conversation stopped progressing in silence
  rather than anything being forged. `firstcontact::ar_fingerprint` and
  `conversation_binding` are the derivation. (#270)

- `daemonseed_core::dm::persist` — the wiring between the DM types and the
  store, so DM state is finally written. `DmPersist` derives both the store key
  and the provisional record's key from one at-rest key. `restart_channel`
  returns `StoredChannelRestart::HandshakeResumes(PendingHandshake)` or a loud
  `Teardown`; `PendingHandshake` owns the record and its one consuming method,
  `establish`, builds the ratchet **and** deletes the record — so `ss0` is
  actually erased on establishment rather than documented as erased.
  `ProvisionalRecord::into_ratchet` is now `pub(crate)`, so outside the crate
  `establish` is the only path from a record to a ratchet. `update_outbox` and
  `advance_cursor` are read-modify-write inside one critical section; there is
  no load-then-save pair to lose an update. `read_outbox` / `read_cursor` are
  lock-free and create nothing. The provisional record is sealed by its own
  path and again by the store: the two bind different facts — `RecordContext`
  refuses a record lifted from another channel, the store's AAD refuses a blob
  moved between slots — and neither layer can check the other's. Erasure is
  `unlink`, not an overwrite (#293). (#281, #243)

- `daemonseed_core::storage::dm_store` — the DM at-rest store. `DmStore::open`
  derives one seal key from the profile at-rest key (HKDF-SHA384 under the new
  `DM_STORE_SALT` / `DM_STORE_SEAL` / `DM_STORE_AAD` labels) and sweeps orphaned
  temp siblings (#286). `critical_section` holds an `flock` for the whole
  closure and hands out a `Locked` guard carrying `read` / `replace` / `delete` /
  `present`, so a read-modify-write cannot be spelled without the lock; entering
  one establishes the correspondence. `read_unlocked` / `present_unlocked` ask
  after a correspondence without taking the lock and without creating anything.
  A nested `critical_section` on one label from one thread is
  `DmStoreError::Reentrant` rather than a deadlock. Each `RecordKind` has a
  fixed on-disk size and a payload capacity; `replace` pads to the bucket with
  CSPRNG filler behind a length prefix inside the seal and refuses an oversized
  payload rather than truncating. `ReceiveCursor` is unsealed and must be
  exactly its 8 bytes. Errors preserve `atomic_file`'s landed/not-landed
  distinction. One key per profile with random nonces and no rotation (#289).
  (Amendment A9 build obligation, #281)

- `daemonseed_core::storage::atomic_file` — durable atomic file replacement.
  `replace_atomically` writes a CSPRNG-suffixed temp sibling (`O_CREAT|O_EXCL`,
  mode 0600), fsyncs it, renames over the destination, and fsyncs the parent
  directory; a newly created ancestor is fsynced into its own parent as it is
  created. Errors name the destination's state: `NotLanded`, `Indeterminate`,
  `LandedNotDurable`, `NoParent`, `Entropy`. `FileLock` is the `fs4` exclusive
  advisory lock for a read-modify-write critical section, with its own
  `LockError`; `replace_atomically` does not take it. On Windows the
  destination is removed before the rename and the directory barrier is a
  no-op (#285). Orphaned temp siblings after a `SIGKILL` are not swept (#286).
  (Amendment A9 build obligation, #281)
- ISC-A-C43: no daemonseed-authored protocol message or sealed envelope falls
  below CNSA 2.0, independently of the transport carrying it. Riding a
  pre-CNSA-2.0 transport is permitted; emitting a pre-CNSA-2.0 envelope over it
  is not.

- The DM store scrubs a record before unlinking it: an erasure sentinel and
  then the body, each forced to the medium, for every `RecordKind`.
  `DmStoreError::ErasureInterrupted` names a record whose erase was cut short,
  so a crash mid-delete is never reported as tampering. Best-effort by
  construction — an SSD's FTL or a copy-on-write filesystem leaves the original
  blocks untouched. ISC-A-C45. (#293)

- The startup sweep scrubs an orphaned temp sibling before unlinking it, and
  skips one it cannot scrub rather than failing `DmStore::open`. (#293)

- **Behaviour change:** a crash inside the erase destroys the provisional
  record, where one before it left a resumable handshake.
  `PendingHandshake::establish` is no longer a safe retry. An interrupted erase
  reports as `TeardownCause::NoProvisionalRecord`, not `StoreUnreadable`. (#293)

- `CorrespondenceLabel::mint` — a correspondence's on-disk directory name is
  minted from the CSPRNG and recorded in the contact cache, never derived from
  `chan_id`, the recipient's key-record address, or a salted derivation over
  either. ISC-A-C44. (#288)

- `daemonseed_veilid_net::dm` — the DM driver's acknowledgement half. A receiver holds one
  `StandaloneAckCadence` per correspondence and one client-global `StandaloneAckBudget`; on each tick
  every correspondence that wants a write is ordered by `ack_cadence::pick_next`, oldest pending
  first, and the budget grants at most one. A granted write builds the record with
  `ack_record::build_encoded` over the collection's own state and publishes it at
  `DmAckAddress::for_direction` over the receiving direction; the cadence advances on the write's
  outcome, never on the decision. A refusal's `retry_after_ms` becomes a wake time. The taper is
  keyed on each collected frame's own `sent_unix_ms`, and a correspondence stops wanting a write once
  every message it collected has passed the sender's give-up. A sender holds one retained `AckState`
  per correspondence: piggybacked acknowledgements are folded where the frame is opened, and on each
  tick a correspondence with unsettled entries and a known pseudonym fetches the peer's record,
  verifies it with `ack_record::decode_and_verify` and folds that. Each collected frame's asserted
  send time is clamped to the moment it was collected before it enters the taper's set: a
  peer-asserted time in the future never ages out of the give-up window, so stored verbatim it
  terminates no conversation, writes for ever, and takes the client-global allowance from every
  honest correspondence at once. The set is sorted, deduplicated and capped, dropping the
  second-newest entry on overflow so the oldest and the newest both survive. Either fold merges under the
  highest sequence this side has sent, then settles the outbox and emits
  `DmEvent::Delivery { state: ConfirmedCollected }` for each settled sequence, once per run. Cadence
  and budget state are not persisted: after a restart the taper restarts from the floor. (#235)

- An acceptor's collection settles the knock's own sequence zero, which arrives by doorbell and no
  page will ever hold, so the contiguous prefix starts and the initiator's opening message can be
  confirmed. (#235)

- `crates/daemonseed-veilid-net/tests/two_node_dm_driver.rs` — opt-in `#[ignore]`d live oracle: two
  nodes, one `DmDriver` each over its own `VeilidNetHandle`, driven through the driver's command and
  event channels. `FirstContact` → `ContactRequest` at the correspondent → `Accept` → the acceptance
  collected at sequence zero → one channel message each way, each collected exactly once → both
  outboxes at `DeliveryState::ConfirmedCollected`. Proof of work minted and verified at
  `PowDifficulty::PRODUCTION`. (#235, #236)

- `daemonseed_core::dm::persist::PendingHandshake::establish_with_resume` and
  `commit_with_resume` take a `&ResumeRecord`, commit it, and then erase the provisional record
  best-effort. `StoredChannelRestart::Established(Box<ResumeRecord>)` is a third restart outcome:
  a stored resume record is the authority, and a provisional record beside it is ignored and
  deleted. (#401)
- `daemonseed_core::dm::persist::DmPersist::record_first_contact_sent(label, pk_lt, ar, now_ms)` —
  writes the initiator's contact record when a first-contact entry is sent, with no pseudonym. A
  record already there is re-addressed to the new root and keeps its `first_seen_ms`;
  `DmPersistError::AlreadyEstablished` for an established correspondence and
  `CorrespondenceHoldsAnotherIdentity` for one holding a different `pk_lt`. (#402)
- `daemonseed_core::dm::persist::DmPersist::record_correspondent_pseudonym(label, pk_pc, now_ms) -> bool`
  — fills the pseudonym on that record when the acceptance verifies, reporting whether it was newly
  recorded, and records the sighting. `DmPersistError::ContactRecordMissing` where no record exists.
  (#402)
- `daemonseed_core::dm::contact_cache::ContactRecord::record_pseudonym(pk_pc) -> bool` — fills an
  absent pseudonym; `ContactCacheError::PseudonymAlreadyRecorded` for a different key, an identical
  key reports `false`. (#402)
- `daemonseed_core::dm::contact_cache::ContactCacheError` — `UnknownPseudonymPresence { found }`,
  `PlaceholderPseudonym`, `PseudonymAlreadyRecorded`. (#402)
- `daemonseed_core::dm::persist::DmPersistError` — `CorrespondenceHoldsAnotherIdentity`,
  `ContactRecordMissing`. (#402)
- `daemonseed_core::dm::persist::DmPersistError::retrying_cannot_help()` — whether repeating the
  same call could answer differently. Every `Contact`, `ContactRecordMissing`,
  `CorrespondenceHoldsAnotherIdentity`, `AlreadyEstablished`, `AmbiguousCorrespondent`,
  `OutboxDirectionMismatch` and `CursorPayloadWrongLen` is settled, as is a `Store` error naming
  unreadable bytes. (#402)
- `daemonseed_core::dm::provisional::ProvisionalRecord::channel_roots()` and
  `daemonseed_core::dm::persist::PendingHandshake::channel_roots()` — both channel roots
  recomputed from the stored handshake, `AR` and `chan_id` together, in a `ChannelRoots` that
  erases itself. (#402)
- The graceful-close path traces every stage under `DAEMONSEED_VEILID_TRACE`: entry with the
  pre-flush budget, each share withdraw as posted or timed out with the withdraw budget left,
  each room's LEAVE tombstone as awaited or timed out, the flush budget handed over and whether
  `shutdown` returned or hit `flush_budget + TEARDOWN_CAP`, and on the actor side the
  `Command::Shutdown` dequeue with its budget, the scheduler flush return, and the teardown
  return or `TEARDOWN_CAP`. A leave or flush stage that is skipped for want of a session says
  so, so a silent trace means the close never ran rather than ran and did nothing. (#370)

### Fixed

- DM key-record and ack fetches release their read-pool permit on timeout instead of holding it across an unanswered read (#411)
- `daemonseed-tui`: a graceful close publishes a LEAVE tombstone for every joined circle as well as
  the lobby, each sealed under its own circle key and posted to that circle's presence record,
  awaited concurrently under the close budget. (#368)
- `cargo xtask install-hooks` writes the hook to the directory git runs hooks from
  (`git rev-parse --git-path hooks`): `core.hooksPath` when set, otherwise the common `.git/hooks`.
  Run from a worktree it wrote to `.git/worktrees/<name>/hooks/`, which git does not read.
- The `daemonseed_core::presence` interval-draw documentation links `apply_jitter` in
  `daemonseed_core::backoff`, the module that defines it. (#332)

- A direct-message leg fold works on its own copy of the page's resume record and writes it back
  only when it consumes its leg, so a fold that defers or refuses leaves nothing for a later fold on
  the same page to commit; a withheld attempt is not recorded in the seen-frame memory; the own
  slot is emptied only after decapsulation succeeds. (#404)
- A torn-down direct-message conversation opens no re-establishment at load, gets no upkeep, and
  its queued leg is skipped before the retry ladder advances. (#404)
- A direct-message first-contact entry sent and then restarted before it was accepted no longer
  strands: the acceptance is collected and the correspondent's messages are delivered, where before
  nothing mapped their identity key to the correspondence and every message they composed re-emitted
  to the outbox's seven-day give-up. (#402)
- Bounded each rendezvous sweep GET at `SWEEP_GET_TIMEOUT` (15s), with `SWEEP_READ_FANOUT` (4) in
  flight at once, so a sweep of an `o_cnt`-subkey record spends at most `o_cnt.div_ceil(4) × 15s`
  on its reads however many go unanswered; every slot is still read exactly once in index order.
  `SweepOutcome` gains `timed_out`, a subset of `failed`, and the rendezvous sweep traces its
  start as well as its counts on completion. (#397)
- The terminal client shows a direct-message channel torn down for want of a stored handshake
  record as "conversation ended — start a new one" in the status badge and Trust History,
  through `trust_persistent_text`, rather than printing the event key
  `dm-channel-torn-down-on-restart` verbatim. Every other key of that class still renders as
  its stable string. The event key is unchanged.
- `Display for TeardownCause::NoProvisionalRecord` no longer states that the application
  restarted, a claim that does not hold on every path reaching that cause; it states that the
  conversation cannot be resumed. The impl has no caller outside tests.
- Corrected the direct-message outbox record's growth, which retained every entry ever
  inserted and so grew with lifetime rather than owed messages, reaching a wall past which
  every persist for that correspondence failed for good. `DmPersist::update_outbox` calls
  `Outbox::prune` before running the caller's closure once the encoded record reaches half
  the outbox record's capacity, so an enqueue's capacity gate prices against the reclaimed
  bytes. Reclaiming an entry discards which terminal state its message reached:
  `Outbox::pruned_high_water` records only that the sequence is gone, and an acknowledgement
  reports a given-up sequence as settled. A prune that reclaims nothing spends no seal, and
  one that reclaims writes once for the backlog. (#323)
- Corrected the DHT open cache's treatment of DM channel page records, which opened a page
  once per session and never closed it, so open-record cardinality grew with message volume.
  The page subset of the cache is bounded by `DM_PAGE_CACHE_CAPACITY`, and an eviction closes
  the record it drops. The lobby record and share adverts derive the same owner key and keep
  the open-once behaviour. An open holds a lease that makes its record id non-evictable, and
  an eviction closes under the evicted record's own lock, so a record another operation is
  using is never closed. (#252)
- Corrected the rustdoc where the direct-message at-rest store is introduced, which left
  the word *store* to be read as the place messages are kept. `storage::dm_store`, the
  `dm_store` entry in `storage`, `dm::persist` and `dm::spent_store` name what it holds:
  per correspondence the resume, provisional, outbox, receive-cursor and contact records,
  plus the profile's block list. Message content is present only while an outbox entry is
  in flight, and a received message is never written. `dm::spent_store`'s argument for
  keeping the spent-token set outside the store rests on the fixed-size profile record's
  shape rather than on every record belonging to a correspondence. (#384)
- Corrected the keepalive and heartbeat interval coverage, which asserted band membership and
  variation but not band width, so a draw collapsed to a tenth of its span passed.
  `interval_in_band` is the single definition for both and takes its entropy source as a
  parameter. (#364)

- Corrected the graceful close in both front ends, which never ran the WB-3 I7 write-scheduler
  flush — `VeilidNetHandle::shutdown` had no caller anywhere in the tree — and never emitted a
  leave at all from the TUI. A departed member dropped off peers' rosters only at the ~600s
  `PRESENCE_TTL`, making a clean quit indistinguishable from a crash. Both front ends now
  withdraw owned shares, publish per-room LEAVE tombstones concurrently, then flush; the TUI
  closes after restoring the terminal. An unpublish posts its withdraw before de-registering
  from the serve registry, so a close-path timeout can no longer clear the share locally and
  tell the UI it stopped while every listener carries it to the prune TTL. (#161)

- Corrected three reference-doc descriptions that named things the Veilid cutover removed.
  `lama.yaml`'s integration-tests entry names the per-milestone and per-feature ISC-coverage
  files it holds; its xtask entry lists the seven subcommands that exist; and
  `ChannelBindingSource` is described as the seam a transport-terminating layer would
  implement, with no implementor outside the module's test fake. (#307, #306)

- Corrected whole-share placement into a chosen destination, which keyed the wrapper folder on
  the share's display name, so a share re-announced under a new name no longer resolved to the
  bytes an interrupted download had staged. `wrapper_folder` reuses the folder the download
  actually staged under, keeps the name of a download that has already staged bytes, and
  collision-suffixes a fresh one against the destination. (#355)
- `daemonseed_core::backoff::apply_jitter` is pinned by tests that can fail. Three probes assert
  the band's edges and its centre, that a unit outside `[-1, 1]` is clamped, and that a negative
  or NaN factor returns zero rather than panicking. Tests only; no production code changes.
  (#332)
- Corrected the at-rest circle read high-water map, which held a circle's `cot_key` IKM in the
  clear as a `BTreeMap` key while `PersistedCircle` protected the identical value. The key is
  `CircleSeenKey`, a newtype over `Zeroizing<String>`, so the phrase is wiped on an ordinary
  drop, on every early return of `from_plaintext` taken after a `circle-seen` line was read,
  and on every clone. (#358)

- Corrected the at-rest read path, which left decoded secrets in freed memory on its error
  paths: a circle's entropy in `Seeds::from_plaintext` and `Seeds::add_circle`, and the whole
  decrypted payload in `open_v2` and `open_v1`. Every one is now held in `Zeroizing` from the
  byte it exists. (#343)

- `secret_zeroize_on_drop`: the parse-error case is armed on the buffer the secret hex decode
  reports rather than on the first allocation of the secret's length, so another allocation of
  that length can neither take the watch nor disarm it. (#422)

- Corrected the TUI's whole-share download to a user-chosen destination, which placed
  files at their share-root-relative paths and so dropped the share's own folder name —
  a single-depth share landed as loose files in the chosen folder. It now wraps them
  under the share name via core `no_scatter`, matching the GUI. A nested share is
  unchanged. (#216)

- Corrected both shares panes, which drew every row from the first and clipped at the pane
  height, so a row past the fold was selectable but never drawn. Each pane draws the page of
  rows its selection falls in, moving a page at a time rather than a line. Rows truncate
  rather than wrap and are budgeted to the pane width: a row that cannot fit keeps its name
  down to a twelve-character floor and middle-ellipsizes the trailing field — the publish
  state in My-shares, the rating and sharer handle in Public-shares. The defined-shares
  header is 72 characters, fits an 80-column terminal, and stays drawn above every page
  along with the indexer status rather than paging with the rows. The public-share selection clamps
  against the visible count rather than the raw listing, so a selection that survives a hide
  no longer sits past the last drawn row with `f` a no-op. (#352)
- Corrected the move of the chat send target from a circle to the public lobby, which carried
  the compose buffer across, leaving text composed against a circle one keystroke from a public
  post. The draft is dropped on every move that widens the audience — `Home` and the `←/→`
  carousel step alike; a draft composed on the lobby is left alone. `Home` in the chat pane
  returns the send target to the lobby in one step from any carousel position, and does nothing
  when no public room is joined. The compose block's title carries `[Home] lobby` while a circle
  is active and a lobby exists. (#354)

### Removed

- `daemonseed-core`: `TrustEventKey::ConnectionRateLimited` and
  `TrustEventKey::ConnectionRateLimitedExhausted`, their `class_of` and stable-string entries, and
  the `daemonseed-tui` toast that rendered the first as "server busy — backing off". Neither key has
  had a producer since the reconnect backoff was removed. Neither stable string parses any more. Only
  `connection-rate-limited-exhausted` can appear in an audit log written before the removal, and such
  an entry now counts in `TrustEventLog::unreadable_entries`; `connection-rate-limited` was
  `Transient`, which `append` drops, so no log ever held it.
- `cargo xtask findings-resolved`. It asserted marker strings in a document kept outside this
  repository, so it could not run from a clean checkout.
- `daemonseed-core`: `PROJECT_RELEASE_SEED`, `dev_project_release_keypair`,
  `dev_project_announce_veilid_owner_seed` — the seed is no longer in the source tree.
- `daemonseed-gui`: `DAEMONSEED_OPERATOR` — possession of the project-announce seed is the operator
  capability; there is no second gate. Debug builds are no longer world-writable on the announce
  record.
- `daemonseed_core::backoff::Backoff` and `daemonseed_core::backoff::BackoffPolicy`, with the
  `DEFAULT_BASE`, `DEFAULT_CAP` and `DEFAULT_MAX_RETRIES` constants they carried. Nothing
  constructed a `Backoff`; the retry cadences that run carry their own delay ladders.
  `Backoff::refusal_event`, noted in issue #338, is removed with them. Jitter remains
  `daemonseed_core::backoff::apply_jitter` and `DEFAULT_JITTER_FRAC`, and the close-cause
  layering remains `daemonseed_core::backoff::CloseCause`. ISC-C26 is withdrawn as an `ISA.md`
  tombstone and deregistered from the ISC registry; `TOTAL` 245 after the registry change. (#332)
- `daemonseed_core::presence::next_heartbeat_interval` and
  `daemonseed_core::presence::HEARTBEAT_INTERVAL_MIN`. No production caller reached the draw,
  and the constant bounded nothing else. `HEARTBEAT_INTERVAL_MAX` and `HEARTBEAT_MISS_COUNT`
  are retained for the test and integration fixtures that build a `PresenceTracker` with a
  cadence; no production caller reads either. The crate-internal `interval_in_band` remains the
  single uniform-band draw. (#372)

- `daemonseed_veilid_net::dm::spawn_dm_ack_publish`. The DM driver owns when a standalone
  acknowledgement is written, and the helper decided nothing about it; no production caller
  existed. Building and addressing a record remains
  `daemonseed_core::dm::ack_record::build_encoded` plus `DmAckAddress::for_direction`, and the
  write remains `VeilidNetHandle::publish_dm_ack`. (#235)

- The default path for `cargo xtask findings-resolved`, which pointed outside the
  repository. The subcommand now requires `--draft <path>`.

- The two placeholder strings on the join-a-circle assurance card, which rendered
  literally to any user opening the overlay. The end-to-end-encryption line remains.

- The `oxicrypt-zeroize` workspace dependency, which no member crate consumed. daemonseed
  zeroizes through the RustCrypto `zeroize` crate's `Zeroizing` and `ZeroizeOnDrop`;
  oxicrypt's is an in-boundary FIPS SSP zeroizer exposing free functions over byte slices.

- `daemonseed_core::tls` and the TLS dependency stack it existed for:
  the `oxitls-rustls-provider` and `oxitls-webpki-mldsa` path-dependencies,
  and `rustls`, `rustls-pki-types`, `tokio-rustls`. Veilid supplies transport
  security; daemonseed terminates no TLS. `oxicrypt` is now the only sibling
  path-dependency, so a build needs only `../oxicrypt` checked out.

### Changed

- ISC-C80 is withdrawn and deregistered. It described a reconnect on a capped exponential backoff
  timer, and the `Backoff` type that was the timer is deleted. `ISA.md` keeps the ID as a reserved
  tombstone and `daemonseed_isc::TOTAL` falls from 245 to 244.
- `daemonseed-tui`: the Shares pane's key legend carries the hints and its input line carries the
  selected defined share and the serving count, which were previously appended to the legend after
  `[Esc] back`. The trust-history, deprecation and shares legends are shortened so each fits an
  80-column terminal with `[Esc] back` whole (#236).
- `daemonseed-core`: rustdoc that introduces the DM record store names what it holds — five fixed
  records per correspondence plus the profile's block list, never a message archive. (#384)
- A resumed channel's clear ratchet generation is agreed inside the settling legs rather than derived
  on each side: the `RE-ACK` carries the answering party's floor, the initiating party computes
  `reest::agreed_generation` from both floors, and the `RE-CONFIRM` carries the result. Each side
  refuses a value at or below the floor it brought to the agreement, or `u32::MAX`, before the
  exchange spends anything, and reports the refusal once per session as
  `TrustEventKey::DmReestablishmentFailed`. The answering side judges the settlement against the
  floor it advertised rather than against its live counter (#404).
- `daemonseed-veilid-net`: `DmCommand::Send` composes on a channel a completed re-establishment
  opened. The answering side is refused with `RefusalReason::AwaitingCorrespondentsFirstFrame` until
  the correspondent's first frame under the re-rooted root opens its sending chain; the refusal
  spends no sequence number (#404).
- `.github/workflows/ci.yml`: the `release-suite` job runs on pushes to `main` and on manual dispatch,
  not on pull requests; `preflight` and `dev-suite` run on both.
- Design documents, `README.md`, `AGENTS.md` and code comments state the design and the tests in
  plain terms: internal review-process narrative, pointers to material not in the repository, and
  private working vocabulary are removed; `README.md` says encrypt where it said seal.
- `project_release_*` is renamed `project_announce_*` throughout `daemonseed-core` and
  `daemonseed-veilid-net`: `project_announce_pubkey()`, `project_announce_pubkey.bin`,
  `ProjectAnnounceSeed` / `ProjectAnnounceSeedText` / `ProjectAnnounceSeedSource`,
  `PROJECT_ANNOUNCE_SEED_{ENV,FILENAME,LEN}`, the `project_announce_pubkeys` example. Operators supply
  the seed as `DAEMONSEED_PROJECT_ANNOUNCE_SEED` or `<profile-root>/project-announce.seed`; the former
  names are not read. No key-derivation label or wire value changes.
- The project-announce identity is rotated: `project_announce_pubkey()` and
  `PROJECT_ANNOUNCE_OWNER_PUBKEY` are the keys of a new seed. Every client re-anchors to the new
  announce record on upgrade. Builds carrying the previous keys are untrusted and must be upgraded:
  they accept content signed under a seed that is no longer private.
- `daemonseed-gui`: the operator credential is loaded once at Connect and held for the session; a
  seed that is malformed, readable by others, or not the project-announce seed is reported on the
  announcements pane on every snapshot and at every write, rather than silently demoting the
  instance to a reader. The composer, the keep-alive and every write read one predicate: whether
  a credential was loaded. The seed variable's value is taken out of the process environment at
  startup.
- `daemonseed-veilid-net`: the two-node operator-record oracle draws a fresh project seed per run and
  hands node B the derived owner public key as bytes; it no longer writes to the live announce record.
- The pre-push hook runs `cargo xtask gate --group preflight`.
- Gate steps carry a group and a child environment; the table runs `preflight`, then `dev-suite`,
  then `release-suite`.
- `daemonseed_core::public_space::{first_operator_keepalive_interval, next_operator_keepalive_interval}`
  and `daemonseed_core::dm::keyrec::next_reseed_interval` draw through one crate-internal
  interval-drawing helper; the private `public_space::jittered` helper is gone. Each band gains the
  band-ceiling, entropy-degrade, spread, density and cardinality assertions (#372).
- `daemonseed_core::dm::resume::ResumeRecord::new` returns `Result<Self, ResumeError>` and refuses
  an own slot whose attempt disagrees with the counter, an acceptance below the committed
  generation (`AcceptanceBelowGeneration`), a confirm slot ahead of it
  (`ConfirmSlotAheadOfGeneration`), and a retained root without its stamp. (#404)
- `daemonseed_core::dm::firstcontact::ChannelRoots` — fields private behind `ar()`, `chan_id()`
  and `rs0()`; construction crate-private; `Clone` removed. (#404)
- `daemonseed_core::dm::resume` — `ResumeRecord::commit_reestablished` carries the dedup memory into
  the new retention rather than emptying it: the root moving into retention is the one every
  recorded frame was sealed under, so A5.3's retirement gate has not fired for them (#404).

- `daemonseed_core::dm::persist::DmPersist::accept_first_contact` takes the acceptor's own
  per-correspondent keypair as a `SignKeypair` and writes the correspondence's resume record before
  its contact record (#404).
- `daemonseed_core::dm::resume::ResumeRecord` carries this party's own verifying key beside `s_pc`,
  read by `own_pk_pc()` and taken by `ResumeRecord::new`. At rest it sits between `s_pc` and the
  peer's `pk_pc`; the magic is unchanged. `ResumeError::OwnVerifyingKeyAbsent` refuses an all-zero
  one at construction and at decode.
- `daemonseed_core::dm::provisional::ProvisionalRecord` carries this party's own per-correspondent
  signing keypair, read by `s_pc()` and `pk_pc()` and taken by `ProvisionalRecord::new` and
  `FirstContactState::into_provisional`. `SigningKeyPc` is the secret half's zeroizing newtype,
  `ProvisionalError::MismatchedSigningPair` refuses halves that do not sign and verify, and
  `PROVISIONAL_RECORD_LEN` is 12301 bytes.
- `daemonseed_core::dm::resume` at-rest v2 carries the own slot's `seq` between its attempt and the
  ephemeral-key presence flag. The magic is unchanged: no released build has written v2.
  `ResumeError::EmptySlotHasSequence` refuses a non-zero sequence beside an empty slot (#404).
- `daemonseed_core::dm::outbox` at-rest v5 assigns target tag `2` to
  `OutboxTarget::ReEstablishmentLeg`. The magic is unchanged: no released build has written v5.
  `OutboxError::FirstDispatchPassed` is new (#404).
- `daemonseed_core::dm::outbox` at-rest format v5 (`daemonseed/dm/outbox/v5\0`): the header carries
  `next_send_seq` and `last_clear_gen`, each entry carries `sealed_under_gen`. v4, v3 and v2 are
  read with the new fields zero; v1 is still refused. `Outbox::publish` and `Outbox::enqueue_sealed`
  take the sealing generation (#404).
- `daemonseed_core::dm::resume` at-rest format v2 (`daemonseed/dm/resume/v2\0`): the own slot carries
  its ephemeral decapsulation key behind a presence flag, and the record carries
  `reroot_ratchet_gen`. `RESUME_MAGIC_V1` is refused with `ResumeError::ObsoleteV1Layout` (#404).
- `daemonseed_core::dm::resume::ResumeRecord::commit_reestablished` re-qualifies the send floor by
  the re-rooted ratchet generation, carrying its sequence across unchanged (#404).
- `daemonseed_core::dm::outbox::Outbox::sweep_dead_chain` leaves `OutboxTarget::Doorbell` entries
  alone; `Outbox::enqueue_awaiting_key` raises `next_send_seq` (#404).
- `daemonseed_core::dm::resume::CommittedRoot::from_bytes` and
  `daemonseed_core::dm::ratchet::RootKey::from_bytes` borrow their bytes (#404).
- `daemonseed_core::dm::contact_cache::ContactRecord` holds `pk_pc` as `Option`: `new` takes
  `Option<Box<[u8; ml_dsa::PK_LEN]>>` and `pk_pc()` returns `Option<&[u8; ml_dsa::PK_LEN]>`. The
  at-rest form gains a presence byte before the key, which keeps its width when absent;
  `CONTACT_RECORD_LEN` is 5234. `decode` refuses a presence byte outside `{0, 1}` and a key claimed
  present and all-zero. (#402)
- `daemonseed_core::dm::persist::DmPersist::correspondence_for_pk_lt` names a correspondence whose
  contact record carries no pseudonym; `correspondent_state_lost` reports `NoCorrespondence` for
  one. `accept_first_contact` refuses only an established correspondence and removes a
  pseudonym-less record for the same identity before minting. (#402)
- The direct-message driver writes the contact record when it sends a first-contact entry, fills the
  pseudonym when the acceptance verifies, and seeds a restarted correspondence with the pseudonym
  the record holds. Its established-correspondence checks read the record rather than the label.
  On the first tick after a restart it recomputes the ratchet and channel roots of a correspondence
  whose entry is unanswered, from the stored handshake at either live first-contact epoch, and
  collects the acceptance. A page sweep requires the ratchet and channel roots, no longer this
  side's own pseudonym keypair. It reuses a recorded correspondence's label when re-sending an
  entry, and erases the stored handshake only once the collected pseudonym has reached the contact
  record, retrying that write on the tick and releasing the handshake record when the refusal is
  settled. A refused contact-record write erases the handshake record it wrote a moment earlier, and
  a re-arm gives up after eight consecutive store faults, as does the pseudonym write. (#402)

- Amended the direct-message design of record: the acknowledgement handshake terminates on an
  elapsed-time taper rather than mutual observation, acknowledgement reads are priced against the
  read pool at one fetch per tick per unsettled correspondence, and the receive cursor is sealed
  at rest so the store has no unsealed record kind. ISC-C46 re-cut to "a blocked correspondent's
  records are not read" and closed; block-stops-reads-not-writes recorded under ISC-A-C23. (#389)

- The DM driver hands a channel page's DHT record back when it will not address the page again: a
  receiving page below both the watched window and the first unsettled position, a sending page
  whose every position the correspondent has settled, and every page of a torn-down conversation.
  `daemonseed_veilid_net::dm::seam::DmDht::close_dm_page` and `VeilidNetHandle::close_dm_page`
  take the new direction-erased `daemonseed_veilid_net::actor::DmPageRecord` and answer whether a
  record was released; `Command::CloseDmPage` carries it to the actor, where
  `rendezvous::close_page_now` drops the open-cache entry and closes the record under its own
  `record_lock`, refusing a page an operation still holds.
  `daemonseed_core::dm::collect::Collection::retired_below`,
  `daemonseed_core::dm::collect::WATCHED_PAGES` and
  `daemonseed_core::dm::ack::AckState::settled_pages_below` are the settlement bounds those
  signals read; a sending position given up at the seven-day window settles for that bound, and a
  torn-down conversation plans and writes nothing further on the channel plane — sweeps, page
  writes, acknowledgement fetches and acknowledgement writes are all gated on it, the last at its
  candidate scan so a dead correspondence cannot spend the client-global acknowledgement permit
  or starve a live one — and a page an operation was holding at teardown is handed back when that
  operation's outcome lands. The receiving side has no give-up signal — no record carries the
  sender's abandonment, so a permanently lost inbound position pins its pages and
  `Collection::abandoned` still has no production caller — and `rendezvous::RecordLocks` entries
  are still never removed, an entry being unsafe to drop while any task holds a clone of its
  `Arc`. Covers the open-cache and page-ring half of issue #252. (#252)

- `daemonseed_core::dm::persist::DmPersist::advance_cursor` returns `CursorAdvance` (`moved()` /
  `repaired()`) and replaces a `cursor.bin` it cannot read — wrong width, not authentic,
  interrupted erase, or a payload that is not `RECEIVE_CURSOR_LEN` bytes — with the caller's own
  page, reporting `repaired()`; an environment error and `DmPersistError::CursorNotCorroborated`
  still propagate. A payload of another length is the new
  `DmPersistError::CursorPayloadWrongLen`. `DmPersistError::is_unreadable_record` is public and
  says which errors license that replacement. The DM driver flags a `cursor.bin` its seed cannot
  read and replaces it on the next idle tick — the fold's repair only fires when the contiguous
  prefix moved, which a correspondence with no live channel never does.
  `daemonseed_veilid_net::dm::DmEvent::ChannelHealth` carries `cursor_records_repaired`, folded
  by `daemonseed_tui::app::DmChannelHealth` and `daemonseed_gui::state::DmChannelHealth`. (#389)

- `daemonseed_core::storage::dm_store::RecordKind::ReceiveCursor` is sealed at rest under AAD tag
  4 and padded to a fixed bucket, like every other kind: `capacity` is `RECEIVE_CURSOR_LEN` = 8
  and `on_disk_len` is `NONCE_LEN + LEN_PREFIX + 8 + TAG_LEN`. `RecordKind::is_sealed` and
  `DmStoreError::UnsealedPayloadNotExact` are removed; a cursor payload shorter than 8 bytes is
  padded and recovered exactly rather than refused, and a `cursor.bin` of the former 8-byte width
  reads as `DmStoreError::WrongFileLen`. (#389)

- `daemonseed_veilid_net::dm::DmEvent::ChannelLost` carries `event:
  daemonseed_core::trust_events::TrustEventKey`, the key
  `daemonseed_core::dm::provisional::Teardown::event` classes the teardown's cause under (the
  2026-07-30 loud-teardown note in `docs/design/direct-messaging.md`).
  `daemonseed_tui::app::App::on_net_event` folds it into the trust-event audit log and raises its
  ISC-C28 persistent-non-blocking affordance; `daemonseed_gui::state::GuiState` gains a
  `TrustEventLog` and `GuiState::on_dm_event` appends to it only, the GUI having no affordance
  surface. The entry carries the key, the wall clock and no correspondent.

- `daemonseed_veilid_net::dm::DmEvent::Refused` carries `event:
  Option<daemonseed_core::trust_events::TrustEventKey>` — `Some` where the refusal is a
  provisional channel torn down as an introduction is minted, carrying
  `daemonseed_core::dm::provisional::Teardown::event`'s key for that cause, and `None` on every
  other refusal. `daemonseed_tui::app::App::on_net_event` folds a carried key into the
  trust-event audit log and raises its ISC-C28 affordance;
  `daemonseed_gui::state::GuiState::on_dm_event` appends it to the audit log.

- The DM driver verifies a fetched key record through a per-correspondent
  `daemonseed_core::dm::keyrec::KeyRecordCache` keyed by the correspondent's long-term identity
  key, so a record naming a `version` below the highest already verified for that identity is
  refused with the new `RefusalReason::KeyRecordRollback` instead of being sealed to (design M1);
  an equal version is accepted as a re-fetch and a higher one advances the bound, which is held
  for the life of the driver and not persisted.
  `daemonseed_core::dm::keyrec::KeyRecordCache::accept_encoded` decodes and admits raw fetched
  bytes in one step.
- `daemonseed_core::dm::contact_cache::ContactRecord` stores the channel's address root `AR` in
  place of `ss0`. `new` takes `Zeroizing<[u8; ROOT_LEN]>`, `address_root` returns
  `[u8; ROOT_LEN]`, `addresses_same_channel` returns `bool`, and an all-zero root is
  `ContactCacheError::PlaceholderAddressRoot`. `CONTACT_RECORD_LEN` and the
  `RecordKind::ContactCache` bucket are unchanged. **Breaking (crate API):**
  `ContactRecord::new`'s third parameter, `address_root`'s and
  `addresses_same_channel`'s return types, and `ContactCacheError`'s
  `PlaceholderSecret` variant, now `PlaceholderAddressRoot`.
- `daemonseed_core::dm::resume::ResumeRecord::new` takes `sealed: Option<SealedReEst>`, and
  `attempt`, `sealed` and `sealed_re_est` return `Option`. `None` is the empty handshake slot,
  encoded at rest as attempt `0` with a zero-length frame and ordering below every `Attempt`;
  attempt `0` beside a non-empty frame is `ResumeError::EmptySlotHasFrame { len }`.
  `DmPersist::commit_resume` returns `Result<Option<Vec<u8>>, DmPersistError>`, `None` where the
  slot is empty, and refuses `ResumeError::PseudonymPairChanged` when a write would change the
  stored `s_pc` or `pk_pc`, `ResumeError::EmptySlotWouldReplaceAttempt { stored }` when an empty
  slot is offered against a persisted attempt, and — at decode —
  `ResumeError::OccupiedSlotHasNoFrame { attempt }` beside `EmptySlotHasFrame { len }`. (#401)

- `daemonseed_tui::net::NetCommand` derives `Debug` only and `daemonseed_tui::net::NetEvent`
  derives `Debug` and `Clone` only: `DmCommand` is not `Clone` and `DmEvent` has no equality.
  (#339)

- `daemonseed_veilid_net::dm::DmEvent::ChannelHealth` carries `peer_acks_clipped` and
  `peer_acks_unverified`: a peer acknowledgement claiming a sequence above what this side has sent,
  and a fetched record that did not decode or did not verify. `peer_acks_deferred` now counts
  acknowledgements that would not merge into the retained state, where before it counted every
  piggybacked one the driver did not fold. (#235)

- `daemonseed_veilid_net::dm::DmCommand::Accept` also composes the acceptance and queues it at channel sequence zero, emitting `DmEvent::Delivery { seq: 0, state: Composed }`, and erases any provisional record this side held for the same identity. A refused acceptance emits `DmEvent::Delivery { seq: 0, state: Undelivered }` with a `DmEvent::Refused` naming the reason, and is retried on the idle cadence while the acceptor's sequence zero is unspent, reported once per distinct reason. A record the erase could not reach is retried on later ticks rather than dropped. (#234, #236)
- A first-contact mint is refused with `RefusalReason::AlreadyEstablished` when a correspondence with that identity already carries the correspondent's pseudonym. (#234, #236)
- `DmEvent::ChannelHealth`'s `peer_pseudonym_unknown` counts unsettled positions an initiator left alone, once per sweep that saw them, rather than sweeps skipped. (#234, #236)
- `daemonseed_core::dm::frame::ParsedFrame::open` verifies a carried `pk_pc` against the author key it was given, before the authorship signature: a different key is `PseudonymMismatch`, and a carried binding that does not verify under the author's long-term key is `Binding`. A body carrying neither field takes the path it took before. (#234, #236)
- The DM driver's initiator sweeps before it knows its correspondent's pseudonym, opens the acceptance at the acceptor's sequence zero, installs `pk_pc`, and erases the provisional record in the same act. Frames at later sequences are left unsettled and counted `peer_pseudonym_unknown` until then. (#234, #236)
- The DM driver's initiator keeps its provisional record from the mint until a verified acceptance, rather than consuming it at the mint. (#234, #236)
- The DM driver keeps at most one sweep of a record in flight: one of its own doorbell, one per receiving page of a conversation. A tick that finds a sweep still open asks for no second one; the record is released when the sweep returns, fails on the transport, or its task panics. An unread doorbell entry waits at most one sweep plus one idle tick. `DhtOutcome` carries the operation's `DhtOpKind`; `PanickedJob` gains `DoorbellSweep` and `PageSweep`. `MockDht` takes a per-method latency override set after construction.
- `daemonseed_veilid_net::dm::DmCommand::Send` sends on an established channel: the outbox is priced
  before the ratchet steps, the frame is sealed with the collection's acknowledgement piggybacked,
  and `DmEvent::Delivery { state: Composed }` reports the queued sequence. A full outbox is
  `DmEvent::Refused { reason: OutboxFull { needed } }` with nothing spent. (#236, #339)
- `daemonseed_veilid_net::dm::DmCommand::Surfaced` clears the surfacing owed on the named sequence
  numbers. (#236, #279)
- The driver's idle cadence emits due outbox entries, publishes them at
  `DmPageAddress::sending(..)`, confirms a landed write, sweeps given-up entries as
  `DmEvent::Delivery { state: Undelivered }`, and sweeps the receiving pages
  `Collection::probe_plan` names. A page sweep that did not read the whole record folds nothing.
  (#236, #279)
- A give-up is offered to the front end without clearing the outbox's surfacing flag; only
  `DmCommand::Surfaced` clears it, and a session that has already offered one does not repeat it.
  (#236, #279)
- The outbox is driven for a correspondence recovered from disk: the direction comes from the stored
  record, so a queued `OutboxTarget::Doorbell` entry is re-seeded and given up on without a key
  schedule. A `ChannelPage` entry is left un-emitted, having no address without a ratchet. (#236)
- A page sweep counts as complete only when nothing failed AND the transport attempted either no
  subkey (an absent record) or every subkey the record holds. (#236)
- A first contact queues its entry in the outbox as sequence zero against
  `OutboxTarget::Doorbell { slot }`, so a re-seed re-emits the identical bytes and a failed publish
  is an unconfirmed entry. The initiator's ratchet opens at that point, consuming the provisional
  record. (#236)
- `daemonseed_veilid_net::dm::DmEvent::Refused` covers a channel send as well as a first contact.
  (#236)
- The DM driver stops sweeping a blocked correspondent's channel and fetching its acknowledgement record from the next idle tick, and folds neither a page outcome nor an acknowledgement that arrives for a correspondent blocked since it was asked for, settling nothing it drops; after an unblock the next tick asks again and re-collects from the outcome it returns. An unreadable block list sweeps, fetches and folds nothing and emits `DmEvent::BlockListUnreadable` once for the tick. A block the store refuses leaves the held request from that identity on screen. Sends to a blocked identity are unchanged, and the correspondence, its channel and its outbox are left standing; an entry queued for a blocked correspondent therefore re-seeds to the seven-day give-up and is then surfaced `Undelivered` even where that correspondent collected it, the acknowledgement saying so being one of the reads the block stops. (#390)

- `VeilidNetHandle::subscribe_room`, `resweep_rendezvous`, `repair_rendezvous` and
  `rendezvous_record_key` take a `RendezvousOwner` in place of a raw `[u8; 32]` owner
  seed, and `subscribe_circle` takes an `OwnerSeed`. **Breaking (crate API)** for callers
  of those five methods. (#244)
- `VeilidNetHandle::subscribe_room` returns `Result<bool>`: `true` when a record was opened
  and watched, `false` when a `PublicOnly` owner found none. A caller that remembers a
  record as subscribed must remember it only on `true`. **Breaking (crate API)**. (ISC-15)
- `resweep::next_resweep_seed` is now `resweep::next_resweep_record`. It rotates over a
  per-record identity the caller chooses, which must be the same choice for every record in
  one caller's set. **Breaking (crate API)**. (#244)
- A `PublicOnly` rendezvous owner reaches its record read-only: the engine opens it with no
  writer and never creates it. An absent record is a clean result on subscribe and re-sweep,
  and an error on repair. The open cache, the record locks and the repair in-flight set key
  on the owner's public key. (#244)
- The project-announce/MOTD reader addresses its record from the baked owner public key and
  holds no owner seed. The single instance that writes that record derives its owner key at
  each write and keeps nothing between them. (ISC-15)
- The two-node doorbell oracle's closing control waits for a definitive answer and never
  reads a transient error as an absent record. (#233)
- Tests, manifests and design documents that need a public Veilid attach describe what the
  test does and how to opt into it, naming no machine, host or network topology.
- `ISA.md` carries the design contract only — problem, boundaries, language, principles,
  constraints, the criteria under their permanent IDs, the durable design decisions, and
  how they are verified. Build narrative and per-session verification records are no
  longer part of it; change history is `CHANGELOG.md` and the signed tags, and the live
  criterion count comes from `cargo xtask isc-coverage`.
- Scoped trust-event dismissal to the kind of record it concerns, so acknowledging a blocked
  erasure of one kind leaves the others standing. (#337)
- Skipped and counted a trust-log entry whose event key this build does not know, where the
  whole log previously failed to open. (#337)
- Refused a stated Argon2 cost outside `ArgonParams::is_openable` before any key is derived
  from it, at all four readers: the trust log, the spent-token set, the `.dseed` recovery file
  and `daemonseed.toml`. The bound covers `memory_kib × iterations`, which is what determines
  the work; the per-field ceilings alone admit a corner costing minutes. (#337)
- `ProfileConfig::from_toml` returns `ArgonParamsOutOfRange` for work factors outside that
  bound. (#337)
- A trust-log body claiming an impossible entry count no longer pre-allocates for the
  claim. (#337)
- `open_log` and `spent_store::open` zeroize the decrypted buffer on their malformed-body
  paths, not only on success. (#337)
- A terminal-client trust badge carries the suite the event named, so dismissing a
  suite-scoped event matches it. (#337)

- A decoded-but-unmerged peer acknowledgement is a `PeerAck`, which answers no question about
  settlement; `merge_peer_ack` consumes it, so a peer's claim reaches our state only through the
  ceiling that bounds it. (#257)

- A trust event names the kind of record it concerns, so a blocked erasure is distinguishable
  from another blocked erasure without the audit log naming a correspondent. (#337)

- The trust-log file carries a version tag; a file written by the previous version still opens. (#337)

- An unrecognised record kind in a trust log costs that field alone; every other entry and field
  still reads. (#337)

- A coalesced write's survivor carries the strongest class of the writes it replaced, so a
  chat-class write already answered `Ok` is flushed at shutdown rather than shed. (#233)

- Every funnel-write publish method documents that `Ok` means the write left the layer, not that
  it reached the DHT, and names coalescing and tombstone dominance where they apply. (#233)

- `VeilidNetHandle::shutdown` takes a `flush_budget` and caps the transport teardown, and
  `GRACEFUL_CLOSE_BUDGET` (12s), `CLOSE_PREFLUSH_BUDGET` (6s), `CLOSE_FLUSH_FLOOR` (2s),
  `CLOSE_LEAVE_RESERVE` (2s) and `TEARDOWN_CAP` (3s) are public. A front end's close is carved
  out of the existing budget rather than added to it, so every step is bounded, including the
  node shutdown, which was an unbounded await on a path a UI thread blocks on. `flush_budget`
  counts only from the moment the actor dequeues the command and `actor_loop` is serial, so a
  caller bounds its own await at `flush_budget + TEARDOWN_CAP`; the withdraws are bounded by a
  deadline that leaves `CLOSE_LEAVE_RESERVE` for the tombstone. (#161)

- Advert-route release has two named entry points, `release_own_advert_route` and
  `release_any_advert_route`, in place of the remove-and-release idiom open-coded at three
  route-lifecycle sites. `StopServe` no longer holds the actor-wide mutex across the Veilid
  release call; the other two sites already dropped it first. (#175)

- Aligned the crypto stack on published oxicrypt: every `oxicrypt-*` dependency is pinned to
  `0.24.0` from crates.io instead of path-depending on a sibling checkout, and the packaging
  scripts fetch the integrity signer at that same pin through `packaging/lib/sign.sh`. A
  daemonseed clone now builds on its own. A commented `[patch.crates-io]` block redirects to a
  local `../oxicrypt` for cross-repo work.

- Corrected the DM channel-page address so a publish cannot name a slot its address does not
  hold: `DmPageAddress<Sending>` carries the `PagePosition` it writes, and `publish_dm_page`
  takes no separate position. **Breaking (crate API):** `publish_dm_page` loses an argument,
  `DmPageAddress::sending` takes a `PagePosition` rather than a page, and
  `VeilidNetError::DmPageWrongPage` is removed. Nothing on the wire moves. (#269)

- Added the conversation to a page sweep's result. `DmPageSweep` is a struct carrying the `AR`
  fingerprint alongside the slots and the outcome, so a caller sweeping several correspondents
  attributes frames by a value it was handed. **Breaking (crate API):** the sweep result is no
  longer a tuple. (#270)

- Aligned module initialization on oxicrypt 0.24.0, which requires the pre-operational
  integrity group. `daemonseed_core::kats::initialize_module` is the one production entry
  point and passes `oxicrypt_integrity::KATS` with `CNSA_2_0_KATS` under
  `AlgorithmProfile::Cnsa2`; `initialize_module_unsigned_test_binary`, behind the `testing`
  feature, is the test-target entry point. **The shipped artifact must be signed:
  `build-appimage.sh` runs `oxicrypt-integrity-sign --sign` on the AppDir binary and
  verifies the slot, last, after every step that rewrites the file.** An unsigned binary
  does not reach `Operational`.

- The serve loop's panic arm is reachable by a test. `serve_response_or_not_found` is
  factored out of `serve_loop`, which sits behind a live `VeilidAPI` and could not be
  driven, so the NOT_FOUND answer to a panicking blocking serve step is now pinned by a
  real `JoinError`. No behaviour change. (#248)

- The managed-download folder policy has one home. `resolve_share_folder` and
  `safe_folder_name` were implemented three times each — both front ends and
  `daemonseed_core::storage::fetched` — so a change to the collision-suffix format or the
  name derivation applied to some copies would make a front end's staging target disagree
  with its `downloads.idx` entry. Both are now `pub` in core and the copies are gone. The
  bodies were byte-identical, so behaviour is unchanged. (#211)

- `derive_resume_state` opens each candidate file once instead of once per chunk. The old
  helper did `File::open` plus `metadata` on every call and was called per chunk per
  location, so resuming a multi-GB folder issued thousands of redundant syscalls on top of
  the re-hashing. Measured on a two-chunk fixture: two staged read-opens before, one after.
  (#212)

- Corrected the DM store's nonce-budget documentation, which said the 2^32 birthday bound was
  "unreachable at any realistic volume". The dominant cost is the unconditional write in
  `update_outbox`: one seal per correspondence per sweep tick, reaching 61% of the bound in
  ten years at 500 correspondences and a 60-second tick with no messages sent. The sweep
  cadence is therefore a cryptographic parameter and is not yet set. A test recomputes the
  re-seed count from `RESEED_LADDER` and `GIVE_UP` so the figures cannot go stale unnoticed.
  The key construction is unchanged. (#289)

- `concat_kats` asserts it filled every slot, so an under-filled CNSA 2.0 KATS slice is a
  build error rather than a slice of placeholders the power-up self-test counts as passing.
  Coverage is now checked by requiring every upstream KAT name to appear, in place of the
  length comparison that could not fail against `concat_kats`. (#305)

- Extracted the runtime jitter draw into `daemonseed_core::jitter`. The byte-to-band
  mapping and the degrade-to-no-jitter on entropy failure were written inline and
  identically in `Backoff::next_jittered` and `ReseedSchedule::schedule_next_jittered`;
  both now call one seam that takes the entropy read as a parameter, so the degrade is
  reachable from a test. No behaviour change. (#280)

- Corrected `ReseedSchedule`'s documentation, which described a `testing`-gated
  re-export of the unit-taking method that does not exist, and the API manifest, which
  described a `schedule_next(now_ms, unit)` entry point removed in `1b232e3`.

- `VeilidNodeSeed` is reached through `with_bytes` and is no longer `Clone`. A new
  `inline_scoped` arm on `redacted_secret_newtype!` emits the scoped accessor in
  place of `as_bytes`; the other secret newtypes are unchanged. (#271)

- The DM outbox records whether a terminal transition still owes the user a
  notification. `OutboxEntry` gains `Surfacing` (`Clear` / `Owed`), set by the
  single private edge into a terminal lifecycle, so `sweep_give_ups`,
  `settle_from_ack` and `channel_torn_down`'s surfacing arms cannot move an
  entry without owing the notification. `Outbox::owed_surfacings` reads the
  outstanding set and `record_surfaced` clears it, only once the consumption has
  itself been persisted — the returned lists remain the fast path, and the flag
  is what makes them survive a crash between the call returning and the store
  write. `channel_torn_down`'s `retained` set is deliberately not flagged: those
  entries are unchanged and are re-reported on their own merits. The at-rest
  form is `daemonseed/dm/outbox/v2\0` with a 2-byte suite id after the magic;
  v1 is refused rather than dual-read, because a v1 file cannot supply a
  surfacing value and both defaults are wrong — `Clear` drops exactly the
  notification this closes, `Owed` re-offers every message that ever finished.
  Sealing, padding and the fixed on-disk size are `storage::dm_store`'s and are
  deliberately not duplicated here. (#279)

- The DM page transport takes a checked address. `daemonseed_core::dm::paging`
  gains `DmPageAddress<D>`, binding the page owner seed, the page number and the
  stream, built by `DmPageAddress::sending` / `receiving` from the ratchet's own
  `send_direction` / `recv_direction`; `page()`, `direction()` and `owner_seed()`
  read it. The stream rides in the type parameter (`Sending` / `Receiving` under
  the sealed `PageDirection`), and a page above `MAX_PAGE` is refused as
  `DmPageError::PageBeyondSequenceSpace`.
  `VeilidNetHandle::publish_dm_page(DmPageAddress<Sending>, PagePosition, Vec<u8>)`
  rejects a position whose page disagrees with the address as
  `VeilidNetError::DmPageWrongPage`, before the write is enqueued; that error
  carries the whole refused position, so its message names the page, the slot and
  the sequence number.
  `sweep_dm_page(DmPageAddress<Receiving>)` returns `(PagePosition, Vec<u8>)`
  pairs built against the swept page, refuses a record whose `o_cnt` is not
  `PAGE_SLOTS` as `VeilidNetError::DmPageShapeMismatch` before reading any slot,
  and reports a slot the record cannot hold as
  `VeilidNetError::DmPageSlotOutsideRecord`. `DmPageSweep` is that pair list plus
  the sweep outcome; `DmPageSlots` is removed. Page addresses and the wire format
  are unchanged. (#254)

- The release profile panics on integer overflow (`[profile.release]
  overflow-checks = true`), workspace-wide. (#258)

### Changed

- The DM outbox's at-rest format is `v4`, adding a pruned high-water mark. `v3`
  and `v2` records are read, with the field defaulting to zero. `Outbox::prune`
  removes entries that are terminal **and** already surfaced, which nothing did
  before. The high-water takes over the sequence dedup the pruned entries
  provided, and `u64::MAX` is refused at enqueue so its successor is always
  representable. Nothing calls `prune` yet, so the growth the issue describes is
  still reachable in any build that wires this module. (#323)

- `dm::domain`'s labels and their registry come from one `dm_labels!` invocation,
  so `ALL` cannot omit a label it declares and a byte value cannot drift from its
  declaration. Three tests that read the module's own source as text are retired
  with the parser they fed. A known-answer test pins all 37 labels to their
  pre-migration values, and one narrow source check remains, because a label
  declared outside the macro is still possible. (#296)

### Changed

- **Breaking:** `storage::atomic_file` is now crate-internal. `AtomicReplaceError`,
  `FileLock` and `LockError` are re-exported from `storage` — `DmStoreError` embeds
  the first two, so a caller must still be able to name what it caught.

### Fixed

- Corrected two `NOT YET AVAILABLE` notes in the core API manifest that named
  capabilities the tree ships: persistence and restore, and a store that reads
  and writes an outbox. Both are `dm::persist` over `storage::dm_store`.

- `Locked::delete` repairs a record whose mode lost owner-write, then fails
  loudly instead of wedging. The delete stays fail-closed — erasing the record
  is the forward-secrecy premise — but `EACCES` is permanent, so every retry
  took the same branch and a correspondence could never establish. One
  `set_permissions` repair is attempted; on continued failure, or when the
  directory refuses the unlink, `DmStoreError::ErasureBlocked` carries the
  `DmRecordErasureBlocked` trust event rather than a generic I/O error.

### Added

- `ResumeRecord`'s secret halves are covered by the out-of-crate zeroize witness.
  `s_pc` and `committed_root` are asserted wiped before their memory is released,
  with the skipped public field as the control. `#[zeroize(skip)]` on `s_pc` is a
  silent leak of a per-correspondent ML-DSA-87 signing key and is now caught;
  on `committed_root` it is inert, because the newtype zeroizes itself. (#314)

### Changed

- Re-seed jitter is drawn from the CSPRNG on every emission. `OutboxEntry::emit`
  and `retry_key_fetch` no longer take a caller-supplied jitter unit; they call
  `ReseedSchedule::schedule_next_jittered`, which had no call site. The
  unit-taking door is private, re-exported only under the `testing` feature. A
  caller passing a constant reconstitutes the M7 cross-record phase-lock the
  jitter exists to prevent, so it is no longer reachable from production. (#280)

### Added

- `Outbox` refuses a message it cannot persist, at enqueue rather than at the
  write. A send that would push the correspondence's outbox past
  `OUTBOX_CAPACITY` returns `OutboxError::Full` carrying the sequence number and
  the overshoot, and nothing is stored. The bucket holds 106–213 owed messages
  against a seven-day give-up window, so this is expected to fire in ordinary
  use. What the sender is shown is not decided here. (#291)

- `Outbox::publish` installs a sealed frame on an entry awaiting its recipient's
  key, under the same capacity refusal. `OutboxEntry::publish` is now
  `pub(crate)`: installing a frame is the other edge that grows the record, and
  an entry enqueued without one is admitted cheaply, so gating enqueue alone
  allowed hundreds of frameless entries to be fattened past capacity afterwards.
  A refused publish leaves the entry awaiting its key. (#291)

### Fixed

- Sweeping a DM page no longer creates it. `sweep_dm_page` opens through a new
  `rendezvous::open_only`, which reports an absent record as `Ok(None)` instead of
  creating one, so an unwritten page returns an empty sweep with `attempted: 0` and
  is distinguishable from a present page whose slots are all empty. An absence is
  never cached, so a page written later becomes visible, and each probe of a
  still-unwritten page pays a fresh open rather than a one-off create. (#253)

- `rendezvous::open_or_create` creates only on `KeyNotFound`. Any other open error
  now skips the create and goes straight to the reopen, so a transport fault no
  longer manufactures a DHT record. (#253)

- Removed a duplicate `security:` key from `IndexKey`'s entry in
  `docs/llm-api-manifest/daemonseed-core-api.yaml`. YAML has no duplicate-key
  semantics, so the first block was discarded on every parse. (#264)

- Corrected the DM outbox's delivery state, which inferred *on the DHT* from the
  re-seed rung and so reported a message as published after writes that errored
  and after a key-fetch retry on an entry that had never been emitted. A
  persisted `Acceptance` carries the fact, `OutboxEntry::confirm_written` is the
  transport's report that sets it, and `emit` alone claims nothing. The at-rest
  format is `daemonseed/dm/outbox/v3\0`; v2 records are read, every entry
  defaulting to `Unconfirmed`. (#278)

- `DmStoreError::Io`'s `Display` no longer renders the full path, which
  embedded the correspondence's directory name and put a stable
  per-correspondence identifier into any log line, crash report or toast
  carrying the error. It names the record file only.

- The operator write-gate travels as a value instead of being read from ambient
  state, so three GUI tests no longer assert debug-only behaviour and the suite
  is green under `cargo test --workspace --release`. `operator_write_enabled()`
  is `cfg!(debug_assertions) || <env>`, so in release the gate closed and two
  "reports a clean error" tests never reached the error they assert — their
  subject is the error path, with the gate an unexamined precondition. The
  projection, the two write guards and the command dispatch now take the gate as
  a parameter; the actor loop and the inbound handler remain the single ambient
  boundaries where the environment is read. A new test asserts the projection in
  both gate states, which is the coverage release was silently missing.
  `cargo xtask release-gate` gained a release-profile test step — it ran the
  suite in dev only, which is why this went unseen — and now sweeps linked
  binaries from `target/{debug,release}` afterwards, including on a red run.
  (#274)

- `VerifiedFirstContact` and `PersistedCircle` derive `Zeroize` +
  `ZeroizeOnDrop` instead of naming fields in a hand-written `Drop`, with **no**
  `#[zeroize(skip)]` on either. A field added later is now covered by
  construction rather than by whoever remembers to extend the `Drop` — the old
  arrangement had the test enumerating the same single field the code did, so
  it looked like coverage while sharing the code's blind spot. The three boxed
  public keys needed no exclusion: `Box<[u8; N]>` has no `Zeroize` impl, but the
  derive's `field.zeroize()` auto-derefs to the array and clears the heap block
  in place. The compile-time bound test now names both structs. **The
  fail-closed property is honestly half:** a field with no reachable `Zeroize`
  (`PathBuf`, `Uuid`, this crate's `boxed`-arm newtypes) is an `E0599` build
  failure, while `String` / `Vec<u8>` / `[u8; N]` / `Box<[u8; N]>` silently
  become wiped — the wanted outcome, but not a compile error. Both doc comments
  say exactly that. (#267)

- `Seeds::to_plaintext` assembles the at-rest payload into a single reservation
  and returns `Zeroizing<String>`. It previously grew the buffer from the
  mnemonic onward across ~10 `push_str` sites, each `format!` allocating a
  secret-bearing transient, so every reallocation copied the bytes to a new
  allocation and freed the old one untouched — beyond the reach of any later
  `zeroize()`. Capacity is computed up front with line prefixes single-sourced
  between the sizer and the writer, `push_hex` replaces every `hex::encode` +
  `format!` pair, and `Mnemonic::write_phrase_into` means the phrase never
  exists as its own `String`. A `debug_assert` compares the buffer pointer
  across assembly. The comments state plainly that this removes *our own*
  reallocation copies and nothing more: the buffer still outlives the call, and
  allocator reuse, swap and FTL remap remain out of reach. (#263)

- DM test fixtures no longer sit on page 0, where a `PagePosition`'s slot
  **equals** its sequence number and no test can tell the two apart. The
  crate's only coverage of slot misfiling —
  `a_frame_written_to_the_wrong_slot_is_rejected` — was at `(page 0, slot 1)`,
  so a mutant reading `found_at.slot()` where `open` reads `found_at.seq()` had
  nothing standing in its way, and it survives on the unfixed tree. It is now
  at `(page 3, slot 9, seq 57)` with a fixture control asserting those values,
  so a drift back to page 0 fails loudly rather than silently proving less.
  `dm::collect`'s two fold tests moved likewise, and `dm::outbox`'s
  `position()` — a site the issue did not list — gained a non-zero sibling.
  Tests whose actual subject is sequence 0 keep it and gained non-zero
  siblings. (#272)

- `VerifiedFirstContact` now enforces the invariant its doc comment claims. All
  eight fields were `pub`, so the type advertised "only constructible via
  `open`, so holding one IS the proof" while any caller could forge one with no
  seal opened and no signature verified — the reasoning that lets a call site
  skip re-checking provenance, resting on nothing. Fields are private with
  accessors for the public halves, and `into_ss0` is the only exit for the
  secret: consuming, returning a `Zeroizing`, following `FirstContactState`,
  which refuses a borrowing `ss0` accessor for the same reason. `Clone` is
  removed — a clone of a witness is a second `ss0` and a second plaintext.
  (#265)

- `VerifiedFirstContact.body` is the decrypted first-contact message, and it was
  printed verbatim by `Debug` and never wiped. One `debug!(?verified)` put a DM's
  plaintext on a log surface, and the `Drop` added by #259 reasoned field by
  field without mentioning it — so the struct wiped the key material and left
  the message it protects in a freed buffer. `Debug` redacts it and `Drop` wipes
  it. Whether the type should own the plaintext at all is open and tracked with
  #262. (#266)

- `daemonseed-tui`'s `JoinedCircle.entropy` held the canonicalized circle phrase
  — the `cot_key` IKM — in a bare `pub String` for the whole session: no wipe on
  drop, no redacted `Debug`, freely copyable out. #259 fixed this shape in the
  core and the GUI and named only the GUI site. It now mirrors `PersistedCircle`
  exactly: private `Zeroizing<String>`, `new()`, a borrowing accessor, a
  redacted `Debug`, and no derived equality. (#268)

- `dm::domain`'s label guards no longer parse their own source line by line, so
  a `rustfmt`-wrapped declaration cannot escape them. The parser joins each
  declaration to its terminating `;`, panics on a `pub const DM_` whose shape it
  cannot read rather than skipping it, and asserts its own parse is non-empty —
  a probe whose input goes empty previously reported success. The registry and
  prefix-freeness checks were genuinely blind to a wrapped declaration, and the
  `declared.len() == ALL.len()` cross-check did not catch it because the label
  went missing from both sides; `no_label_is_a_prefix_of_another` now also runs
  over the declared set, which is the one that can silently shrink. Six fixture
  tests drive the parser over wrapped-declaration strings so each check is
  proved able to fail. (#283)

- `derive_root`'s doc-comment named `the_three_roots_from_ss0_are_independent`
  as holding the roots' non-derivability. That test asserts distinctness, which
  passes for any three distinct labels and would pass unchanged if the roots
  were refactored into a chain — the shape the sibling structure exists to
  prevent, and the one the comment cited it for. The comment now separates the
  assumption (HKDF-Expand does not yield its PRK) from the tested property
  (still siblings of one extraction), and a known-answer test pins all three
  roots under one `ss0` so any change to the derivation structure fails.
  Verified: chaining `chan_id` off `ar` fails the new test and passes the old
  one. (#282)

- Two claims in `dm::provisional`'s docs outran what any store here does, and
  one of them was load-bearing. The record was described as "overwritten in
  place on establishment", and `ProvisionalRecord::open`'s rollback argument
  rested on that phrase. The store commits a replacement with `rename(2)` and a
  deletion with `unlink(2)`, so neither overwrites the bytes it supersedes. The
  rollback argument survives on a different fact — there is only ever one
  record, replaced in a single slot and deleted on establishment, so no earlier
  record is *referenced* to roll back to — and the limit is now stated as what
  it is: the superseded bytes are unreferenced, not scrubbed (#293).

- `daemonseed_core::storage::seeds::PersistedCircle` holds `entropy` privately as a
  `Zeroizing<String>`, read through `entropy()` and built through `new()`. `Debug`
  redacts it; `PartialEq` / `Eq` are gone. (#259)

- `daemonseed_gui::profile::PersistedCircle` carries the circle phrase as a
  `Zeroizing<String>`. (#259)

- `daemonseed_core::storage::seeds::seal_with_key` holds the serialized plaintext
  buffer in `Zeroizing`, wiping it on every path out including an unwind. (#259)

- `daemonseed_core::storage::recovery_file::seal_under` holds the derived AEAD key
  and the mnemonic phrase in `Zeroizing`, wiping each on every path out. (#259)

- `daemonseed_core::dm::firstcontact::VerifiedFirstContact` zeroizes `ss0` on
  drop. (#259)

- DM page transport carries the page owner seed as
  `daemonseed_core::dm::paging::DmPageOwnerSeed` — the boxed, redacted,
  zeroize-on-drop newtype — through `VeilidNetHandle::publish_dm_page` and
  `sweep_dm_page`, the two commands behind them, and the scheduler's dispatch
  token. It was a `Copy` `[u8; 32]`, duplicated into the command channel, the
  actor stack, the pending queue and the dispatch frame, none of which zeroize.
  A page's owner seed is the conversation secret; every other owner seed in the
  crate is world-derivable. This bounds daemonseed's own copies, not the secret:
  veilid retains the signing keypair in an opened record for as long as that
  record stays open, and records are opened once per session. (#244, #252, #254)

- A DM page write's funnel `record` — its FIFO and coalescing scope — is the
  owner's PUBLIC key rather than the owner seed. `identity::rendezvous_owner_public_bytes`
  is the total 32-byte derivation it uses. (#244, #254)

- The rendezvous open-cache and per-record locks key on the owner's PUBLIC key
  rather than the owner seed. Every record that existed when those caches were
  written had a world-derivable seed, so holding one cost nothing; a DM channel
  page is the first whose seed is the conversation secret, and under Veilid a
  derivable owner seed *is* write access to the conversation. The public key
  identifies a record at least as precisely — it is what the DHT address derives
  from — and is public by construction. (#244)

- `FirstContactState` zeroizes `ss0` on drop and carries its opening ratchet
  decapsulation key as `ratchet::EphemeralDecapKey`, which zeroizes on drop; it
  was a bare `Box<[u8; DK_LEN]>` with no wrapper. (#234, #135)

- `dm::firstcontact::derive_channel_roots` zeroizes its transient buffers on
  every path and `ChannelRoots` is zeroize-on-drop: `[u8; N]` is `Copy` with no
  `Drop`, so the originals were staying live in the stack frame after the struct
  took its copies. (#234, #135)

- The DFLT subkey write guard is schema-derived (`RecordShape`): the cap is
  `min(MAX_SUBKEY_SIZE, MAX_RECORD_DATA_SIZE / o_cnt)`, the bound `veilid-core`
  enforces. The rendezvous engine derives a record's key from its shape and
  returns the two bound as a `RendezvousHandle`, so a write or sweep reads the
  shape off the handle rather than re-supplying it. The open-cache is keyed on
  `(owner_seed, o_cnt)`. An out-of-range `o_cnt` panics rather than clamping.
  (#232, ISC-C100)

### Added

- `daemonseed_core::dm::outbox` holds the persisted DM outbox (#235).
  `Outbox::new(Direction)` keys `OutboxEntry` by sequence number over one
  direction of one correspondence, covering the doorbell knock at sequence 0 and
  every channel message after it; `direction()` reads it and there is no
  `Default`. An entry carries an `OutboxTarget` (`Doorbell { slot }` /
  `ChannelPage`), the compose timestamp, a `ReseedSchedule` and a `Lifecycle`.
  `Lifecycle` is `AwaitingKey`, `AwaitingCollection(SealedFrame)`,
  `ConfirmedCollected` or `Undelivered`; `OutboxEntry::delivery_state` maps it to
  `DeliveryState` (`Composed` / `OnDht` / `ConfirmedCollected` / `Undelivered`),
  with a sealed-but-never-emitted entry reading `Composed`. `SealedFrame` has no
  mutating API, and `OutboxEntry::publish(now_ms, frame)` is the only edge that
  installs one. `emit(now_ms, unit)` returns the stored bytes borrowed and
  advances the schedule; `retry_key_fetch(now_ms, unit)` advances it for an
  unsealed entry. All three take the clock and refuse an entry past its give-up
  window with `OutboxError::GaveUp`, which is distinct from
  `OutboxError::NothingToEmit`: the first is a live message owed a surfacing, the
  second a terminal or inapplicable state needing nothing. `is_due` is false past
  the window too. `RESEED_LADDER` is 1/2/4/8/16/32/64 minutes, hourly, then daily
  repeating, jittered per emission by `RESEED_JITTER_FRAC` through
  `backoff::apply_jitter`. `Outbox::due` lists entries due at a clock value,
  `sweep_give_ups` moves entries past `GIVE_UP` (7 days from compose) to
  `Undelivered`, and `settle_from_ack(ack, now_ms)` confirms only entries that
  are `AwaitingCollection` and inside that window; both return the sequences they
  moved and both are `#[must_use]`.
  `channel_torn_down(&TeardownCause, now_ms)` returns a `TeardownOutcome`
  (`#[must_use]` on the type): entries past the give-up window surfaced as
  `Undelivered` whatever the cause, published entries retained with their bytes,
  unsealed entries surfaced, and nothing else changed on
  `TeardownCause::StoreUnreadable`.
  `enqueue_sealed` / `enqueue_awaiting_key` take the caller's clock as the
  compose time, so an entry composed outside the give-up window has no spelling.
  `encode` / `decode(bytes, now_ms)` are the at-rest form under `OUTBOX_MAGIC`;
  `decode` refuses an entry whose stored compose time is ahead of `now_ms` with
  `OutboxError::ComposedInFuture` and rewrites no stored value. No caller writes
  or reads one.
- `daemonseed_core::backoff::apply_jitter(delay, frac, unit)` applies `±frac`
  jitter to a delay. `BackoffPolicy::jitter` calls it.
- `daemonseed_core::dm::collect` holds the pure DM collection state machine.
  `Collection` carries the probe frontier — the highest page observed holding any
  populated slot — and an `AckState` for the contiguous cursor. `observe_page`
  folds a swept page into `PageObservation` (unsettled positions ascending and
  deduplicated, plus whether the frontier moved) and records nothing on either
  `CollectError::SlotOutsideRecord` or `CollectError::PageBeyondSequenceSpace`,
  the second naming a page above `paging::MAX_PAGE`. `collected(PagePosition)`
  and `abandoned(seq)` settle a position and lift the frontier to the cursor's
  page when the cursor has run past it; a `TooManyRuns` refusal from either is
  dropped rather than queued. `watched()` gives the current and next page;
  `probe_plan(now_ms)` gives that pair plus up to `MAX_BACKFILL_PAGES` (2) pages
  holding a hole — those `outstanding()` witnesses, then those between the cursor
  and the frontier — or `None` inside `PROBE_INTERVAL_MS` (30 s).
  `contiguous_through()`, `frontier_page()`, `outstanding()` and `view()` read
  the state; `ack()` reads the acknowledgement. `AckState::beyond_runs` returns
  the settled runs beyond the prefix as ascending inclusive ranges.
  `paging::MAX_PAGE` is the highest page a sequence number lives on, which
  `PagePosition::new` enforces. (#236)

- `redacted_secret_newtype!`'s zeroize-on-drop and redacted `Debug` are under
  test. `crates/daemonseed-core/src/secret_seed.rs` asserts the `ZeroizeOnDrop`
  bound on all seventeen generated secret types and pins both arms' `Debug`
  rendering; `crates/daemonseed-core/tests/secret_zeroize_on_drop.rs` installs a
  witness global allocator that reads each secret's block inside
  `GlobalAlloc::dealloc` and requires it to be zero, over three boxed-arm
  rendezvous-owner seeds plus the ratchet's ephemeral decapsulation key, and the
  three inline-arm identity-rooted secrets.
  (#242)

- DM restart handling — `daemonseed_core::dm::provisional` (`ProvisionalRecord`,
  `ProvisionalError`, `ChannelRestart`, `Teardown`, `TeardownCause`,
  `ReceiveCursor`, `RecordContext`, `derive_seal_key`,
  `PROVISIONAL_RECORD_VERSION`, `PROVISIONAL_PLAINTEXT_LEN`,
  `PROVISIONAL_RECORD_LEN`, `BINDING_TAG_LEN`). The steady-state ratchet is not
  persisted. `ProvisionalRecord` holds `{ss0, eph_ek, eph_dk}` for a
  pre-establishment channel and recomputes `AR`, `chan_id` and the ratchet root
  from `ss0`; `address_root()`, `eph_ek()` and the consuming `into_ratchet()`
  read it. `seal(&Aes256Key, &RecordContext)` / `open(&Aes256Key, &[u8],
  &RecordContext)` are the at-rest form — one fixed `PROVISIONAL_RECORD_LEN`,
  `nonce ‖ AES-256-GCM(version ‖ binding ‖ ss0 ‖ eph_ek ‖ eph_dk) ‖ tag` under
  AAD `daemonseed/dm/provisional/aad/v1 ‖ lp(recipient_keyrec_addr) ‖
  lp(fc_epoch)`, written to a fixed-size file overwritten in place on
  establishment. `RecordContext` is `{recipient_keyrec_addr, fc_epoch}`. The
  `BINDING_TAG_LEN`-byte binding tag is HKDF-SHA-384 over `ss0` under salt
  `daemonseed/dm/provisional/bind-salt/v1` and info
  `daemonseed/dm/provisional/bind/v1 ‖ lp(eph_ek)`. `open()` rejects a record
  that is not `PROVISIONAL_RECORD_LEN` bytes, one that does not authenticate
  under the given `RecordContext`, one naming another
  `PROVISIONAL_RECORD_VERSION`, one whose binding tag does not match its
  contents, and one whose ephemeral halves are not a keypair.
  `derive_seal_key(&[u8; AEAD_KEY_LEN])` is HKDF-SHA-384 under salt
  `daemonseed/dm/provisional/salt/v1` and info
  `daemonseed/dm/provisional/seal/v1`. `restart(Result<Option<&[u8]>, E>,
  &Aes256Key, &RecordContext)` returns `ChannelRestart::HandshakeResumes` or
  `ChannelRestart::TornDown`; a `Teardown` carries its `TeardownCause` and the
  `TrustEventKey` it surfaces as. `ReceiveCursor` is a page number bounded by
  `paging::MAX_PAGE`; `advance_to(page, read_through)` and
  `from_be_bytes(bytes, read_through)` refuse a page past what the caller has
  read. (#243)

- `daemonseed_core::trust_events::TrustEventKey` gains
  `DmChannelTornDownOnRestart` (`dm-channel-torn-down-on-restart`),
  `DmProvisionalHandshakeLost` (`dm-provisional-handshake-lost`) and
  `DmProvisionalRecordUnreadable` (`dm-provisional-record-unreadable`), all
  `PersistentNonBlocking`. (#243)

- `daemonseed_core::dm::firstcontact::FirstContactState` carries `eph_ek` and
  holds `ss0` as `Zeroizing<[u8; SS0_LEN]>` with no `Drop` impl, so its fields
  move out; the fields are private, read through `roots()` and `eph_ek()`, and
  `into_provisional()` consumes it into a `ProvisionalRecord`. (#255)

- DM delivery-acknowledgement core — `daemonseed_core::dm::ack`
  (`derive_seal_key`, `ack_sig_input`, `AckState`, `PeerAckOutcome`,
  `DmAckSealKey`, `AckError`, `MAX_ACK_RUNS`). `derive_seal_key(AR, dir)` is
  HKDF-SHA-384 under salt `daemonseed/dm/ack/salt/v1` and info
  `daemonseed/dm/ack/seal/v3 ‖ lp(dir)`. `AckState` holds a contiguous prefix
  (`high_water() -> Option<u64>`) plus a set of settled positions beyond it,
  encoded as canonical RLE runs. `collect(seq)` and `abandon(seq)` both settle;
  `abandon` advances the prefix past the position. `is_settled(seq)` answers from
  the prefix or a run and is false otherwise. `merge_own_ack(other)` is a
  monotonic union. `merge_peer_ack(other, highest_sent)` is that union with the
  peer's claim first clipped to `highest_sent`, returning `PeerAckOutcome`.
  Beyond `MAX_ACK_RUNS` (64) an insert or merge returns `TooManyRuns` and leaves
  the state unchanged. `encode_beyond()` emits a `u16` run count then a
  big-endian `(gap, extent)` pair per run. `decode_unvalidated(high_water, bytes)`
  rejects a count over the cap before allocating, a body length that is not
  exactly `count × 16`, arithmetic leaving the sequence space, and any run at or
  below the prefix. `ack_sig_input(chan_id, dir, state)` binds
  `daemonseed/dm/ack/sig/v3 ‖ lp(chan_id) ‖ lp(dir) ‖ lp(high_water) ‖
  lp(encoded runs)`, with an absent prefix as a zero-length component. `AckState`
  carries no `chan_id`. Not included: the ack record, its seal, its jittered
  standalone cadence, the piggyback path, the persisted outbox. (#235)

- DM channel-page transport — `VeilidNetHandle::publish_dm_page` and
  `sweep_dm_page`, over a third record shape, `RecordShape::DM_PAGE` (`dflt(16)`).
  A publish writes one sealed frame into one slot as a non-coalescible chat-class
  funnel write; the record open is warmed off the chat lane before the write is
  enqueued. A sweep returns `(slot, bytes)` per populated slot plus the sweep
  outcome, bounded by the shape on the record handle. Both move opaque bytes: this
  layer never parses or verifies a frame. Write-once and partial-sweep recovery
  are caller obligations, not properties this layer enforces. Rationale in
  `docs/design/direct-messaging.md` and `ISA.md`. (#234)

- `publish_at_subkey` rejects a subkey outside the record's schema locally,
  naming the slot and the bound, instead of letting veilid reject it after the
  record has already been opened or created. Every pre-DM caller reduces its slot
  mod the shape and cannot trip it; the DM page is the first to take a slot from
  caller-supplied arithmetic.

- DM ratchet key schedule — `daemonseed_core::dm::ratchet` (`derive_root`,
  `advance_root`, `chain_key`, `chain_step`, `skip`, `SkippedKeys`, `KeySlot`,
  `Direction`, `Role`, and the `RootKey` / `ChainKey` / `MessageKey` newtypes).
  `RK0` is a third sibling of the `ss0` extraction that yields `AR` and `chan_id`;
  a generation step extracts under the previous root as salt with the freshly
  encapsulated secret as IKM. Each direction derives its own chain key; `MK` and
  the successor `CK` are siblings of one extraction. `advance_root` and
  `chain_step` take their key by value, so a stepped key cannot be retained.
  `skip` returns each derived key tagged with its `KeySlot` and refuses a request
  past `MAX_SKIP` (64) rather than truncating. `SkippedKeys` holds
  `SKIPPED_KEY_CAPACITY` (2 × `MAX_SKIP`, so one generation change cannot evict
  the previous chain's tail), is insertion-ordered, replaces rather than
  duplicates an occupied slot, and counts evictions. `Role` maps an end of the
  conversation onto its send and receive directions. `Direction::label` is the
  sole definition of the `a2b` / `b2a` wire literals. Every derivation zeroizes
  its transient buffer on both paths. The generation state machine, page
  addressing and the wire frame are not wired yet. (#234, ISC-C38)

- DM ratchet state machine — `daemonseed_core::dm::ratchet::Ratchet`
  (`initiator`, `recipient`, `send_next`, `receive`, `role`, `generation`,
  `skipped_stats`), with `FrameHeader`, `Outbound`, `EphemeralDecapKey`,
  `EPHEMERAL_WINDOW`, `FIRST_INITIATOR_CHANNEL_SEQ`,
  `FIRST_RECIPIENT_CHANNEL_SEQ`. `send_next` takes a generation step when the
  peer has published an ephemeral newer than the one last stepped against, mints
  a fresh ephemeral, and repeats the generation's ciphertext on every message of
  it. `receive` takes the caller's open-and-verify as a closure, computes against
  clones, and applies its state changes only if that closure succeeds; it runs
  the previous chain out to the arriving chain's base so messages in flight
  across a ratchet step stay readable, and serves an already-skipped position
  from the cache without touching anything else. A frame at generation `G`
  decapsulates with the ephemeral published at `G-1`, so no selector rides the
  wire. The initiator's channel sequence starts at 1 (sequence 0 is the
  first-contact entry, carried by doorbell); the recipient's starts at 0.
  `MAX_SKIP` bounds how many keys are kept and `MAX_CATCH_UP` (16 x `MAX_SKIP`)
  how far a chain is walked, so a receiver returning from a long absence loses
  the messages it missed rather than the direction; a previous chain too far
  behind to walk is retired outright at a ratchet step. `Ratchet::losses`
  reports pending, evicted and abandoned counts separately. `initiator` rejects
  an opening ephemeral whose halves are not a keypair. `RatchetError`
  distinguishes `AlreadyConsumed`, `GenerationTooOld`, `SeqBeforeChainBase`,
  `BacklogTooWide`, `MissingCiphertext`, `UnknownEphemeral`, `MismatchedEphemeral`,
  `GenerationExhausted`, `SequenceExhausted` and `NotYetEstablished`. A chain
  refuses to step past the last sequence number rather than wrapping its cursor
  to zero. The wire frame and page addressing are not wired yet.
  (#234, #243, ISC-C38)

- DM channel page addressing — `daemonseed_core::dm::paging` (`derive_owner_seed`,
  `position_of`, `PagePosition`, `PAGE_SLOTS`, `DmPageOwnerSeed`). A
  `PagePosition` is built only through the checked `PagePosition::new`, which
  rejects a slot at or past `PAGE_SLOTS` and a page whose first sequence number
  would overflow, so `position_of` and `PagePosition::seq` are inverses in both
  directions. A page's Veilid owner seed is
  `HKDF(salt = daemonseed/dm/page/salt/v1, ikm = AR, info = daemonseed/dm/page/addr/v4 || lp(dir) || lp(page_be))`,
  so only the two parties can derive the address and therefore only they can
  write it; the ongoing channel needs no admission control against strangers.
  `AR` is symmetric, so the address separates the two streams and not the two
  authors — authorship within the pair rests on `msg_sig`, never on the address. `PAGE_SLOTS` (16)
  is the record's `o_cnt` and part of its address; a writer must build its
  `RecordShape` from it. `position_of` maps a per-direction sequence number to
  one page and slot, total and injective, so a message is written once and never
  wrapped or overwritten. The page record and its transport are not wired yet.
  (#234, ISC-C42, ISC-A-C24)

- DM ongoing-channel wire frame — `daemonseed_core::dm::frame` (`seal`, `parse`,
  `ParsedFrame`, `VerifiedFrame`, `frame_sig_input`, `FRAME_KIND_CHANNEL`,
  `PAD_BUCKETS`, `MAX_FRAME_LEN`, `DmFrameError`) and the `DmChannelFrame` /
  `DmChannelBody` wire messages. The frame carries the ratchet header
  (`ratchet_gen`, `chain_base`, `seq`), the sender's current ephemeral and the
  generation ciphertext in the clear — everything a receiver needs before it can
  derive a key — and seals the rest under the ratchet message key. No identity,
  pseudonym key or signature appears in the clear. Every clear field is bound in
  the AAD and again in `msg_sig`, which extends the shared `/v6` preimage under
  the `msg` frame kind with the generation, the chain base and the generation
  ciphertext, an absent ciphertext binding as a zero-length component.
  `ParsedFrame::open` takes a message key rather than a ratchet, so it composes
  as the closure of `Ratchet::receive` and no ratchet state moves for a frame
  that fails to authenticate; it verifies `msg_sig` unconditionally, since page
  owner-write authority is symmetric and nothing else establishes authorship. The
  plaintext is padded to one of two buckets before sealing. (#234, ISC-C42,
  ISC-A-C20, ISC-A-C21, ISC-A-C22)

- Domain labels `DM_PAGE_SALT`, `DM_PAGE_ADDR`, `DM_RATCHET_ROOT`, `DM_RATCHET_STEP`, `DM_CHAIN_SALT`,
  `DM_CHAIN_A2B`, `DM_CHAIN_B2A`, `DM_CHAIN_STEP_SALT`, `DM_MK`, `DM_CK`. (#234)

- DM first-contact entry — `daemonseed_core::dm::firstcontact` (`build`, `open`,
  `derive_channel_roots`, `bind_lt_input`, `msg_sig_input`, `FirstContactState`).
  ML-KEM-1024 to the recipient's published static key; AES-256-GCM under a key
  derived from the encapsulated secret, AAD binding the recipient's key-record
  address and the first-contact epoch, current or previous accepted. The seal
  carries a per-contact pseudonym, a `bind_lt` signature under the long-term key,
  and a mandatory `msg_sig` under the pseudonym. `open` exact-length gates every
  field, requires `seq == 0` and `key_selector == STATIC`, and verifies both
  signatures. Padded to one of two buckets. `build` generates the opening ratchet
  ephemeral and returns its secret half. Admission checks and transport are not
  wired yet, nor is the established-channel replay rule (v6 minor invariant (b)).
  (#233, ISC-C41)

- Wire: `FirstContactEntry` and `FirstContactBody` (additive MINOR). (#233)

- DM doorbell address and slot derivation — `daemonseed_core::dm::doorbell`
  (`derive_owner_seed`, `slot_for`, `DOORBELL_SLOTS`). The record, entry and
  admission checks are not wired yet. (#233, ISC-C41)

- `DmDoorbellSlotSecret` — a sixth identity-PRK expansion under the
  identity-scoped label `dm-doorbell-slot/v1`, carried on `IdentityKeys`. (#233)

- DM key records are published and re-seeded by both clients (ISC-C40). Each
  publishes its static ML-KEM-1024 encapsulation key once the session is live and
  re-seeds it against eviction on a jittered ~50-minute cadence (Veilid has no
  TTL, so a record survives only while its owner re-writes it). An ephemeral /
  no-profile session publishes nothing — with no persistent key it is genuinely
  not DM-reachable. (#232, ISC-C40)

- DM key-record transport: `VeilidNetHandle::publish_dm_key_record` enqueues the
  signed record on the WB-3 funnel as a coalescible `Keepalive` write to subkey 0
  of its `dflt(1)` record; `fetch_dm_key_record` reads it back off the actor loop,
  returning `Ok(None)` for an empty slot distinctly from a transport error. Bytes
  stay opaque to the transport — verification needs the identity key only the
  caller holds. (#232, ISC-C40)

- `daemonseed_core::dm` — direct-messaging core. The key record publishes an
  identity's static ML-KEM-1024 encapsulation key at a `dflt(1)` Veilid record
  whose owner is derived from the identity's ML-DSA-87 public key, so any holder
  of that key computes the address. Sign/verify, a highest-verified-version-wins
  rollback guard, the clock-derived first-contact epoch, and the
  `daemonseed/dm/…` domain-label namespace. Wire: `DmKeyRecord` and the reserved
  `KeySelector` enum (additive MINOR). (#232, ISC-C40)
- The GUI announcements pane orders posts newest first by `sent_unix_ms`, ties
  broken by content-address slot key (#237). Posts previously rendered in
  content-address order, placing a newer announcement below an older one.
- `daemonseed_core::dm::contact_cache::ContactRecord` and `RecordKind::ContactCache`,
  the DM store's fifth record kind: the correspondent's long-term and pseudonym
  public keys, `ss0`, and first/last-seen timestamps, in a fixed
  `CONTACT_RECORD_LEN` layout sealed by the store. (#236)
- `daemonseed_core::dm::block_list::BlockList` — a set of long-term identity
  public keys with `block`, `unblock`, `is_blocked`, and the two suppression
  predicates `suppresses_knock` (over an opened first-contact entry) and
  `suppresses_channel`. In memory only; not persisted. (#236)
- `daemonseed_core::dm::ack_budget` — the client-global allowance for standalone
  acknowledgements. `StandaloneAckBudget::request(now_ms)` returns `AckPermit::Granted` or
  `AckPermit::Refused { retry_after_ms }` against `STANDALONE_ACK_MIN_INTERVAL_MS` (60 s),
  shared across every conversation rather than held per channel. The clock is an argument, and
  one that goes backwards refuses. (#235)
- `daemonseed_core::dm::ack_cadence` — when a receiver writes a standalone acknowledgement.
  `oldest_live_pending_ms` drops every pending message past its own give-up and returns the
  oldest that remains; `standalone_interval_ms` interpolates linearly from `MAX_INTERVAL_MS`
  (24 h) to `MIN_INTERVAL_MS` (60 s) across that message's remaining window, and is `None`
  when nothing is left. `StandaloneAckCadence::on_collected` makes the next acknowledgement
  due wherever the curve has reached; `on_acked` clears it. `pick_next` takes the candidate
  whose oldest pending message was sent first, with the sort key clamped to one give-up
  window and the previous winner skipped unless it is the only candidate. The clock and the
  window are arguments, and a clock that goes backwards is not due. (#391)
- `daemonseed_core::dm::ack_record` — the DHT record an `AckState` is published in.
  `derive_owner_seed(AR, dir)` is `HKDF-SHA-384(salt=daemonseed/dm/ack/addr/salt/v1, ikm=AR,
  info=daemonseed/dm/ack/addr/v1 || lp(dir))`, and `DmAckAddress::for_direction` pairs that
  seed with its direction. `build` / `build_encoded` sign an `AckState` under the pseudonym
  key, pad the body to `ACK_PAD_BUCKETS` and seal it under `K_ack(dir)` binding
  `daemonseed/dm/ack/aad/v3 || lp(chan_id) || lp(dir)`; `decode_and_verify` / `verify` open
  and authenticate one, returning `PeerAck`. `ACK_RECORD_SLOTS` is 1. (#235)
- `DmAck` and `DmAckBody` wire messages — a sealed acknowledgement envelope and its
  contents: an optional `high_water`, the canonical run encoding, and the ML-DSA-87
  signature over both. (#235)
- `daemonseed/dm/ack/addr/salt/v1`, `daemonseed/dm/ack/addr/v1` and
  `daemonseed/dm/ack/aad/v3` domain labels. (#235)
- `VeilidNetHandle::publish_dm_ack` and `fetch_dm_ack` write and read subkey 0 of a
  conversation's `dflt(1)` acknowledgement record; the publish is a coalescible `Keepalive`
  current-state write, and an empty slot fetches as `Ok(None)`. `RecordShape::DM_ACK` is that
  record's shape. (#235)
- `daemonseed_veilid_net::dm::spawn_dm_ack_publish` builds, addresses and publishes one
  direction's acknowledgement off the caller's loop. (#235)

### Changed

- The closure that `DmPersist::update_outbox` takes returns `Mutation<T>` —
  `Changed(T)` or `Unchanged(T)`, `must_use` — and the record is written only on
  `Changed`. An `Unchanged` report for a correspondence with no record writes no
  record and spends no seal, so `DmPersistError::OutboxDirectionMismatch` arises
  once an entry has been queued. Debug builds panic when an `Unchanged` report
  follows a change. A record is re-encoded to the current format and write suite
  only on a `Changed` write. `DmStore` counts its seals in test builds. (#347)
- `daemonseed_core::dm::resume::ResumeRecord` carries the re-establishment state that must agree
  with itself, written by one `replace_atomically`. `new` takes two grouped structs in place of
  eight positional fields: `ReEstState { reconnect_gen, attempt, own, acceptance,
  attempt_at_window_start }` holds the two handshake slots, the committed generation, the monotone
  attempt counter and the window anchor (A3.14, A3.4, A5.2, A7.3), and `Retention { retained, dedup,
  stopped }` holds everything scoped to the retained `RS_n`. New: the peer-acceptance slot
  (`AcceptanceSlot`, carrying the sealed `RE-ACK` that is re-served byte-identically and the
  confirmation lock; A3.4, A5.1(ii)), the retained `RS_n` with its write-once `superseded_at_ms`
  (`RetainedRoot`), the dedup memory keyed `(gen, attempt, leg, dir, seq)` (`DedupMemory`,
  `DedupKey`, `Leg`, `Novelty`, bounded at `DEDUP_CAPACITY` and holding the one plane a party
  receives on; A5.3), `reconnect_gen`, the `attempt` counter as a field of its own, and the
  retained-but-stopped flag (A5.4). `retire_retained` drops the retained root, its stamp, its dedup
  memory and the flag together; `observe_accepted` raises the `RE-EST` window base and, in the same
  call, drops the dedup entries whose frames the scan can no longer open. `last_seen_re_est` and
  `last_seen_re_ack` are the two window bases, one per direction (A6.1); the `RE-EST` base is a
  stored, monotone field of `ReEstState` rather than a reading of the acceptance slot, which is
  zeroed on completion. `commit_resume` licenses dropping a dedup position below the offered base and refuses
  dropping one at or above it, so the record's eviction is committable and the memory does not grow
  without bound across the window rollovers a retention contains.
  Removed: `window_anchor_ms` and the stored `toward_c`, replaced by `attempt_at_window_start` — an
  attempt number from which the toward-`C` count is a subtraction (A7.3). `previously_established`,
  the peer's `PK_lt` and cached EK, and the clear ratchet-generation counter are **not** in the
  record: their homes are the record's own presence, `dm::contact_cache`, and the outbox (A4.8)
  respectively, and the module docs record each. The at-rest form changes; no released build has
  written this record. (#404)
- `daemonseed_core::dm::persist::DmPersist::commit_resume` narrows
  `ResumeError::EmptySlotWouldReplaceAttempt` to an empty own slot at an unchanged `reconnect_gen`,
  so the slot may be zeroed on completion (A3.14), and adds guards for the acceptance slot
  (no attempt rollback within a generation, no reseal of an accepted attempt, no clearing a confirmed
  slot without a generation advance), the write-once `superseded_at_ms`, monotone `reconnect_gen`,
  and dedup positions dropped while their `RS_n` is retained (a subset test, so a swap is refused as
  well as a shrink). The own slot may be emptied by an abandonment (A3.7) — recognised by an acceptance
  newly occupying the contested generation — or by the completion that advances `reconnect_gen`, and
  by nothing else. `ResumeRecord::decode` additionally refuses an empty frame, a slot whose attempt
  disagrees with the counter, a generation on an empty slot, retained bytes under a clear presence
  flag, and a duplicate dedup position. (#404)
- `daemonseed_core::dm::reest::ReEstGate` is built by `from_record` and carries the persisted
  confirmation lock (A5.1(ii)); `admit` answers the new `ReEstAdmission::Locked` for any differing
  attempt at a confirmed generation, ahead of the budget closure (A9.4(ii)). The type
  no longer derives `Default`. `AttemptBudget` is anchor-based: it carries
  `attempt_at_window_start` beside the monotone attempt counter, derives the toward-`C` count as
  their difference, and resets the anchor only through `observe_peer_opened`, which takes the attempt
  an opened `RE-ACK` names — the `last_seen`-derived rollover (A8.2). Together these bound
  `attempt − last_seen` by `C`, so `MAX_GAP = C` is sufficient and the multi-window lockout is
  unreachable (A7.3). The gate additionally carries the record's committed `reconnect_gen` as a
  floor, so a gate reloaded after a completion — which zeroes the acceptance slot — still drops the
  generations that handshake closed. (#404)

## [0.36.3] — 2026-07-28

### Added

- Direct-messaging design-of-record **FROZEN** (`docs/design/direct-messaging.md`,
  DRAFT v6): hardened over 8 adversarial review rounds (crypto/metadata/erasure)
  to a post-quantum double-ratchet DM over per-page scattered DHT records, a
  sender-blind first-contact doorbell, and fail-safe delivery (never claims
  "delivered"). Its ISC family (ISC-C38–C46 / ISC-A-C20–A-C25) is re-cut in
  `ISA.md` to v6; build slices are tracked as GitHub issues (forces #177).
  Design + criteria only; the build carries the strictly-additive wire delta.

### Fixed

- Operator announcement keep-alive re-seeds from the operator instance only, one
  slot per emission, on a jittered 45–75 minute band after a jittered 2–5 minute
  first emission (#238). Previously every subscribed client re-published every
  announcement every 120 seconds, so write load on the single announce record
  scaled with both the fleet size and the number of standing announcements.
- The GUI and TUI serve a published share from disk, reading one `CHUNK_SIZE`
  range per request, instead of holding every published byte in memory for the
  session (#246). Publishing a multi-gigabyte folder no longer costs comparable
  resident memory. Share ids, chunk addresses, and the wire form are unchanged.
  A published file that is moved, deleted, truncated, or grown after publish now
  stops serving instead of serving a publish-time copy; a same-length in-place
  edit is served and rejected by the fetcher's per-chunk hash check. Re-publish
  to serve changed content.

## [0.36.2] — 2026-07-27

### Fixed

- The Announcements unread dot no longer re-fires on content already read. Operator
  content folds in one item at a time, so the pane is routinely observed partially
  converged; the seen-marker hashed the whole view, which every arrival invalidated.
  It is now a set of per-item hashes, unioned on write and derived from what the pane
  displays, so an item once read stays read whatever folds in beside it and however
  slowly the DHT converges (#217, #158).

- TUI lobby presence now carries the client's own display name instead of the
  `guest` fallback. The self-handle is learned at connect rather than only from
  the first chat send, so a publish-only or lurking client (e.g. a seed node
  that never chats) is named in the roster.
- Share listings (both TUI and GUI) show the sharer's name without the
  `#<12hex>` fingerprint, matching the Lobby roster — the verified fingerprint
  stays on hover. A TUI client publishes its full `name#hash` as the sharer
  handle (a GUI client publishes the bare name), so the GUI browse row now
  strips it too rather than assuming a name-only handle. The transform lives in
  `daemonseed-core::handle::strip_handle_hash`, shared by all surfaces so they
  cannot drift.

## [0.36.1] — 2026-07-22

### Added

- Right-click **Copy** on chat message bubbles (#67).

### Changed

- `rendezvous::sweep_gated`'s callback receives the subkey index alongside the
  bytes (`FnMut(u32, Vec<u8>) -> bool`). The index is the sweep loop's own
  variable, so passing it costs nothing, and a record's slot can be load-bearing:
  for a DM channel page it IS the message's sequence number, and the frame's own
  declared `seq` has to be checked against it. The rendezvous backlog ignores it,
  as it should — a rendezvous message lands wherever the ring put it. (#234)


- Project-release signer and announce write-gate derive from a rotated in-source
  seed; artifacts signed by the former shared dev seed no longer verify.

## [0.36.0] — 2026-07-21

### Added

- `daemonseed-veilid-net`: a per-route concurrency budget (`route_budget::RouteBudget`) capping in-flight fragment `app_call`s per serving route, with a global cap and an error-primary window controller; the fresh-route ceiling is a constructor knob (`RouteBudget::with_default_ceiling`), pinned in production to `DEFAULT_ROUTE_CEIL` (the floor) on veilid 0.5.7 (`docs/design/download-subsystem.md` Part 1).
- `daemonseed-veilid-net`: budget-admitted fetch variants (`share::fetch_manifest_budgeted` / `fetch_chunk_budgeted`) that admit every fragment through the per-route budget (`docs/design/download-subsystem.md` step 3).
- `daemonseed-core`: `storage::fetched::place_at_dest` — placement of a fetch's selected files under a user-chosen destination as a total function of the selection roots (`SelectionRoot`) (`docs/design/download-subsystem.md` Part 2).
- `daemonseed-core`: `storage::fetched::StagingArea` — stages a download's verified chunks at their offsets in a reserved `.dspart/<share_id>/` namespace and promotes each file (no-clobber) on completion (`docs/design/download-subsystem.md` Part 3).
- `daemonseed-core`: `storage::fetched::sweep_staging` — reclaims unresumable staging debris, gated on a `LiveFetchRegistry` (`docs/design/download-subsystem.md` Part 3).
- `daemonseed-core`: `storage::fetched::FetchedStore::record_share` serializes its `downloads.idx` read-modify-write with an OS advisory file lock (`fs4`) (#208).
- `daemonseed-veilid-net`: a shared download engine (`download::run_download` over `PlannedFile` → `DownloadOutcome`) fetching placed files' chunks in parallel under one `RouteLease`, staging each verified chunk at its offset, promoting on completion, and disposing staging by failure class; plus handle methods `VeilidNetHandle::fetch_manifest_budgeted` / `fetch_chunk_budgeted` (`docs/design/download-subsystem.md` step 5).
- `daemonseed-core`: `storage::fetched::FetchedStore::register_share` — records a `downloads.idx` entry for an already-promoted managed download without re-writing bytes, under the `record_share` idx lock (`docs/design/download-subsystem.md` step 5).
- `daemonseed-core`: verified-resume core — `StagingArea::{persist_manifest, read_stored_manifest}`, `manifest_digest`, `verify_stored_manifest`, and `derive_resume_state` (`docs/design/download-subsystem.md` Part 3; DL-ISC-12/20).
- `daemonseed-core`: `storage::manifest_digest::ManifestDigestStore` — a profile-local redb store mapping `share_id` to the confirmed manifest's SHA-384 digest (`docs/design/download-subsystem.md` Part 3; DL-ISC-20).
- `daemonseed-gui` + `daemonseed-veilid-net`: verified resume for interrupted downloads — a fresh confirm persists the confirmed manifest and its profile-anchored SHA-384 digest; a re-initiated fetch verifies it fail-closed and re-fetches only the missing chunks (`docs/design/download-subsystem.md` Part 3; DL-ISC-12/20).
- `daemonseed-tui`: verified-resume parity on the TUI download path (`docs/design/download-subsystem.md` Part 3; DL-ISC-12/20).

### Changed

- `daemonseed-veilid-net`: the share-fetch boundary types failures via `FetchErrorClass` (transient / integrity / not-served / local); content-address and malformed-frame failures classify as `Integrity`, distinct from transient transport (#205, `docs/design/download-subsystem.md`).
- `daemonseed-gui`: the download path (`veilid_net::run_confirm_download`) drives the shared engine — selection roots on `ConfirmFetch` (`RootKind`), stage-then-promote, integrity poison without an Unresolved mark or parked retry, and a terminal outcome on a worker panic (`docs/design/download-subsystem.md` step 5; folds #207).
- `daemonseed-tui`: the download path (`veilid_net::run_confirm_download`) drives the same shared engine — selection roots on `ConfirmFetch` (`RootKind`, cardinality-derived), stage-then-promote, parallel fetch under one per-route budget lease, integrity poison without an Unresolved mark or parked retry, and a terminal outcome on either spawn seam's worker panic (`docs/design/download-subsystem.md` step 6; folds #207).

### Removed

- `daemonseed-veilid-net`: the legacy window-parameter chunk-fetch path (`VeilidNetHandle::fetch_chunk` / `share::fetch_chunk`) is removed — both frontends now fetch through the budget-admitted seam (`docs/design/download-subsystem.md` step 7).
- `daemonseed-core`: the dead `storage::fetched::rebase_to_selection_root` is removed; `place_at_dest` is the placement function.

### Fixed

- `daemonseed-veilid-net`: an integrity failure dominates a concurrent transient across any file and chunk set size — a poisoned unit beyond the in-flight window still poisons the share (DL-ISC-13).
- `daemonseed-gui` + `daemonseed-tui`: a hostile or malformed share manifest classifies as `Integrity` and poisons the share; only transport failures mark it Unresolved and park a retry (DL-ISC-13).
- `daemonseed-veilid-net`: a route death records the sharer's learned ceiling once, at half the killing width (DL-ISC-2).
- `daemonseed-gui`: a selected folder keeps its own name at a user-chosen destination — the placement root carries the toggled folder's path (DL-ISC-8).
- `daemonseed-core`: promoting onto a byte-identical pre-existing file keeps it in place rather than writing a `name-2` duplicate (DL-ISC-21).
- `daemonseed-gui`: a downloads-index read error while resolving a managed download's folder fails the download closed.
- `daemonseed-gui` + `daemonseed-tui`: a download reclaims unresumable `.dspart` staging debris under its destination root before starting, so a crash before the confirmed manifest persisted no longer strands an orphaned staging tree indefinitely (DL-ISC-22).
- `daemonseed-core`: `storage::manifest_digest::ManifestDigestStore` serializes concurrent opens with an advisory file lock, so parallel downloads — in one process, or a co-resident GUI and TUI — no longer collide on redb's exclusive lock and spuriously fail.

## [0.35.1] — 2026-07-20

### Fixed

- Downloading a share no longer starves the downloader's own chat: `ConfirmFetch` runs off the net-actor loop, so chat sends/receives while a download is in flight (#197).
- A failed download no longer strands a full-looking copy under `.dspart`: a preallocated-but-empty staging area (the confirmed manifest persisted, but the fetch died before any chunk landed) is reclaimed by the start-of-download sweep instead of being retained as a phantom "resumable" partial; a partial with real staged progress is still kept for resume (#214).
- A whole-share download to a chosen destination no longer scatters loose files: a share's own top-level folder name is not part of its file paths, so a single-depth share (files directly under the share root) now lands in a folder named after the share (`<dest>/<ShareName>/…`) instead of loose in the destination; a nested share is unchanged. A completed or reclaimed download also removes the now-empty `.dspart/` staging root.

## [0.35.0] — 2026-07-19

### Changed

- `daemonseed-veilid-net`: veilid-core 0.5.6 → 0.5.7.

### Fixed

- `daemonseed-veilid-net`: fetch fragment concurrency lowered 8 → 2 so a multi-file folder download no longer kills the serving private route mid-fetch (#204).
- `daemonseed-gui`: the folder-download chunk-fetch window slow-starts and adapts to route health (`AimdWindow::slow_start`, #128 D-2) rather than opening at the fixed 8-wide chunk fanout, keeping multi-file folder downloads from killing the serving private route mid-fetch on Windows (#204).

## [0.34.0] — 2026-07-19

### Added

- `docs/design/consumer-route-self-heal.md` — frozen design-of-record for the consumer-side share route self-heal: sweep error accounting, cadence-timed session repair, fetch-path prune retirement, off-loop fetch, route-release hygiene, sweep-first Refresh; spawns CRSH-ISC-1..20 (#180).
- `daemonseed-core`: a consumer-side per-record session-health tracker (`session_health`) that flags a record repair-due after K consecutive all-failed steady-resweep passes in calm weather, from network-state evidence only — the detection half of the share-route self-heal (#180, CRSH-ISC-2/9/11).
- `daemonseed-veilid-net`: a `RepairDue` record is re-established under its `record_lock` (invalidate open-cache → re-open → re-watch → full sweep), dispatched on cadence past warmup, with per-record decaying backoff for a permanently-dead record; a same-record write serializes behind the repair and reads the fresh session (#180, CRSH-ISC-3/17/18).
- `daemonseed-gui`: the manual Refresh button is now sweep-first over every share-bearing subscribed record (traffic-shaped like the steady resweep, off the actor loop) with evidence-gated re-establishment — a record whose Refresh sweep just failed in calm weather re-establishes its session in one action, while a healthy record emits only sweep GETs (#180, CRSH-ISC-13/16/20).
- `daemonseed-gui`: the manual Refresh re-indexes each own published root (`ShareContent::index_dir`) and re-announces it under the same deterministic `share_id`, so a file added to a shared folder mid-session becomes fetchable without a relaunch; the own-share list upserts by `share_id` and the re-index is gated on Connected and rides only the user-initiated Refresh, never the 3 s liveness poll (#195, CRSH-ISC-28).

### Changed

- `veilid-core`: 0.5.4 → 0.5.6 (transitive x25519-dalek 2 → 3).
- `daemonseed-veilid-net`: the §I5″.1 margin (≤ 2 concurrent un-gated `open_dht_record`/`watch_dht_values`) is enforced by a semaphore every open/watch site acquires, rather than held by a census argument — so spawned open/watch sites cannot breach it (#180, CRSH-ISC-14).
- `daemonseed-{gui,tui}`: a browse-fetch failure marks the share `Unresolved` (it stays listed); when the sharer's route later rotates, the route-rotation fold marks the share fetchable-again (clears `Unresolved`) — a local no-network op keyed on the route rotating, so recovery is not bounded by any window — and the user re-initiates the fetch (no auto-re-download); a content-only re-advert keeps the share re-resolving; both fetch-preview prune sites are retired, so a share is removed only on verified withdraw or catalog TTL (#180, CRSH-ISC-4/5/6/15/19).
- `daemonseed-veilid-net`, `daemonseed-{gui,tui}`: consumer-imported share routes release on the later of advert-replacement or in-flight-fetch completion (in-use guard); all route releases route through a helper tolerating an already-evicted route; dead advertised routes drop from the republish set; the download-failure path marks the share `Unresolved` instead of pruning it, so `prune_unreachable_share` is retired entirely (#180, CRSH-ISC-10; CRSH-ISC-5 now spans both fetch surfaces).

### Fixed

- `daemonseed-gui`: Windows reclaims a stale single-instance lock via a per-root `Global` named mutex, and surfaces a native recovery dialog on the no-console build instead of failing to start silently (#196).
- `daemonseed-veilid-net`: the steady resweep surfaces per-record GET accounting (attempted/failed/found) instead of swallowing GET errors into the empty-slot path — the enabling observability for consumer-side session-health (#180, CRSH-ISC-1).
- `daemonseed-{gui,tui}`: a share fetch runs off the net-actor loop — spawned, with its outcome folded back on-loop as a generation-tagged event — so a slow or failing fetch can no longer starve chat delivery (#180, CRSH-ISC-7/8).
- `daemonseed-veilid-net`: a `RepairRendezvous` is dispatched off the transport actor loop (spawned, not awaited inline) so a slow repair's close/open/watch/sweep no longer stalls chat and joins; a per-record in-flight guard skips a re-dispatch for a record already repairing (#180, CRSH-ISC-22).
- `daemonseed-core`: an identical advert re-read (same owner, timestamp, and metadata) now folds as `CatalogChange::Unchanged`, so the consumer's steady resweep no longer spuriously bumps the discovered-entry generation; a same-metadata newer-timestamp re-announce still folds `Updated` (#180, CRSH-ISC-21).
- `daemonseed-{gui,tui}`: a fetch outcome that goes stale because a fresh advert advanced the discovered-entry generation now re-parks a browse retry at the outcome's generation (it was dropped, stranding the share permanently `Unresolved`); a stale outcome for a withdrawn share still drops (#180, CRSH-ISC-23).
- `daemonseed-{gui,tui}`: a queued repair is re-checked when the queue drains — a record whose session recovered while queued is dropped rather than spuriously re-established — and an immediately-dispatched record is removed from the queue so it is never double-repaired (#180, CRSH-ISC-24).
- `daemonseed-{gui,tui}`: a successful download now clears the share's `Unresolved` mark and its parked browse retry (it was left stranded "re-resolving", and the stale retry fired a redundant browse fetch) (#180, CRSH-ISC-25).
- `daemonseed-{core,gui,tui}`: a verified withdraw releases the share's imported route (deferred past any in-flight download) and drops its route-guard entry, so no imported route leaks past withdraw and `route_guard` does not grow unbounded (#180, CRSH-ISC-26).
- `daemonseed-core`: an identical advert re-read now refreshes `received_at` (while still folding `Unchanged`) so a continuously-reheard live share is not aged out by the catalog TTL prune (#180).
- `daemonseed-veilid-net`: the spawned repair clears its in-flight marker via RAII (Drop) so a panic in the spawned repair cannot permanently disable a record's self-heal (#180).
- `daemonseed-gui`: a manual Refresh queued during a busy/warmup window now heals the dead record when the repair queue drains — the Refresh arm survives the enqueue instead of being dropped as "recovered" (#180, CRSH-ISC-13).
- `daemonseed-{gui,tui}`: a consumer re-imports a share's rotated route when the re-advert folds catalog-`Unchanged` — a sharer restart / route-death re-advertises the same sealed advert with only the `route_blob` rotated (same `sent_unix_ms`), which folded `Unchanged` and skipped the route-import gated behind that verdict, leaving the consumer wedged on the dead route (share listed, `Unresolved`) until restart; the blob change is now detected independently of the catalog verdict, re-imports the route, and arms the parked retry (#180, CRSH-ISC-27).
- `daemonseed-{gui,tui}`: a late stale fetch outcome no longer reverts a share that a newer overlapping fetch already resolved — a stale outcome re-parks only a still-unresolved share (#180, CRSH-ISC-23).

## [0.33.1] — 2026-07-15

### Fixed

- `daemonseed-gui`: the windowed (`desktop`) build no longer opens a stray console window on Windows — the crate sets the `windows` subsystem under the `desktop` feature; the offscreen build keeps stdout for headless verification.
- `daemonseed-gui`: the HERE NOW roster follows a rail switch — each room's roster is cached and repainted on switch, not only on the next content-changing beacon (#138).
- `daemonseed-gui`: the presence roster shows the member name inline with the `#<12hex>` fingerprint revealed on hover only, uniform for lobby and circle rows (#173).
- `daemonseed-gui`: the in-app version label matches the release tag.
- `packaging`: the AppImage and Windows build scripts build `--features desktop` (the removed `veilid` feature flag is dropped).
- `daemonseed-gui`: an inbound message or `CircleJoined` re-render no longer clears the in-progress composer draft (#189).
- `daemonseed-gui`: the single-line composer scrolls horizontally to follow the caret, so long input is no longer typed blind (#190).
- `daemonseed-gui`: with `DAEMONSEED_VEILID_PORT` unset the node binds an OS-assigned free listen port instead of veilid's fixed default, and keys its veilid namespace on the profile identity, so two co-resident no-env instances no longer abort startup on a port or protected-store clash; a listen-bind failure names the cause and the storage-dir create error propagates instead of being swallowed (#188).

### Changed

- `daemonseed-gui`: the connection-status line reads `connected · veilid` — transport-level, not the joined room name (#182).

### Security

- `daemonseed-gui`: the operator MOTD/announce composer is read-only in release builds except an operator instance (`DAEMONSEED_OPERATOR=1`); debug builds stay world-writable.

## [0.33.0] — 2026-07-14

### Added

- `daemonseed-{veilid-net,core,gui,tui}`: the WB-5.1 read-lane cure (`docs/design/veilid-write-budget.md` §WB-5.1) — the four-pool partitioned `dht_gate::DhtGate` (chat 2 / I8-floor 1 / write `W_max` / read remainder, no cross-pool fallback, `acquire_wait` demoted to trace-only telemetry); per-GET read permits in `rendezvous::sweep` so read occupancy is bounded by the read partition regardless of live sweep count; the acquire-wait window controller retired for a static `min(distinct pending non-chat records, W_max)` window; a dedicated capacity-1 floor lane with a direct starved-age eligibility predicate that survives I3 coalescing (`starved_since` inheritance) and I6b riding it deadline-first; a median-of-5 DHT-weather estimator replacing the EMA; the transport-free `presence::ReapGate` (8s/4s hysteresis band + 220s reap-resume grace) wired into both frontend reapers with a "presence may be stale" indicator; `#168` dispatch-future-construction panic supervision plus `record_locks`/`OpenCache` poison-recovery. Registers WB-ISC-16/17/18/20/21–28; WB-ISC-15/19 stay live-probe-deferred (#159, #168, #157).
- `docs/design/share-id-binding.md` — design-of-record (frozen) for #156: the receiver-verifiable `share_id`↔publisher binding. v2 derivation carries a `root_commitment` (nonce HKDF'd from one pinned identity IKM) so a receiver recomputes `share_id == derive_v2(sender_pubkey, root_commitment)` without the folder path; the derive-check gates the catalog fold, the withdraw branch, route import, and the circle path, and first-writer-wins is demoted to a continuity rule (#156, #152).
- `docs/design/veilid-write-budget.md` §WB-5.1 — amendment (frozen) superseding §I5′'s permit architecture: per-GET read gating on a four-pool partitioned DHT accountant (chat 2 / I8-floor 1 / write `W_max` / read remainder; margin reserved for un-gated ops under a single-permit rule); the acquire-wait window controller is retired for a static record-scaled window; chat is capped no-spill with I4 re-scoped to 2 concurrent cross-record writes; I8 gains a direct starved-age floor-eligibility predicate (surviving I3 coalescing) on a dedicated permit with I6b riding it deadline-first under a `slack ≥ 660s` bound; the regime estimator becomes a median-of-5 with an 8s/4s hysteresis band plus a 220s reap-resume grace; the presence-staleness signal gets production wiring in both frontends; #168 sync-panic and mutex-poison residuals are closed; WB-ISC-21..28 specified with a nine-step night-buildable contract (#159, #168, #157).
- `docs/design/veilid-write-budget.md` §WB-5 — amendment (frozen) reopening WB-3's I5 window: a record-scaled non-chat write window with a permit-acquire-wait congestion guard replacing AIMD-on-latency, denominated in veilid's shared 16-permit read/write DHT gate (content fetch is off that gate), with `W_max` starting at 2 and stepping up only on a single-client control measurement; adds a WB-4.L2 discovery floor to the #172 resweep backoff and a presence-staleness signal under reap-in-calm (#159, #157, #172).
- `daemonseed-core` + `daemonseed-{gui,tui}`: the WB-1 write-budget presence model (Slice B) — constant-cadence fixed-length keepalive + read-side inference. `presence::{next_keepalive_interval, PRESENCE_TTL, REAP_CONGESTION_THRESHOLD, PresenceTracker::for_room, PresenceTracker::apply_member_write}` and a congestion-aware `PresenceTracker::reap(now, congested)`; `heartbeat` seals every beacon to one constant `HEARTBEAT_SEALED_LEN` (padded) and carries a provenance-bound `MemberHeartbeat.is_leave` leave marker; `HeartbeatFields::is_leave`. `daemonseed-veilid-net`: `PresenceBoundary` (Join/Keepalive/Leave), `VeilidNetHandle::publish_presence` takes a `PresenceBoundary`, and `VeilidNetHandle::last_write_latency_ms` exposes the scheduler's enqueue-to-ack congestion signal. The gui/tui net actors emit a join beacon on subscribe, a [180,220]s keepalive, a leave tombstone on graceful close (gui), advance freshness from same-room chat writes, and reap only in calm. Registers WB-ISC-1–8 (#159, #77, #153).
- `daemonseed-{core,veilid-net,gui,tui}`: the WB-1 presence model — replaces the [50,55]s open-loop beacon + 60s reaper with a constant-cadence [180,220]s jittered keepalive (activity-independent) dispatched through the WB-3 funnel; all presence writes (join, keepalive, leave tombstone) seal to one constant byte length (`HEARTBEAT_SEALED_LEN`; the digest moved off the beacon so ciphertext length carries no share-count/handle metadata, and an oversized payload is rejected rather than sealed longer); read-side freshness `max(last beacon, last verified same-room member write)` dominated by a provenance-bound leave tombstone (no same-room write with `sent_unix_ms <= leave_ms` re-freshens), same-room-bound, and emission-free (no freshness/reap transition emits); reap at TTL 600s suspended while the scheduler's enqueue-to-ack latency is elevated. Presence slot-collision resolution stays a #77 requirement. WB-ISC-1-8 (#159, #77).
- `daemonseed-veilid-net`: `schedule` — the WB-3 write scheduler: one prioritized, rate-limited funnel that every `set_dht_value` in the actor passes through (priority chat > session-boundary > advert-refresh > keepalive > republish; per-record FIFO with seq/slot assigned inside `record_lock` at dispatch, #131 untouched; last-writer-wins current-state coalescing keyed on the logical id, with non-coalescible dominant tombstones/withdraws — the #121/#118 resurrection guard; chat holds a reserved slot, is never coalesced, and dispatches ≤2s to an idle record at any queue depth; non-chat in-flight bounded by the `AimdWindow`; MOTD deadline override; graceful-close chat+tombstone flush with class-3/4/5 shed; no read-triggered writes). A `WriteSink` seam drives the paused-time oracles WB-ISC-9–13. The three write commands + the advert-refresh path now enqueue and return, retiring the #154 actor inline-park (#159, #154, #158).
- `docs/design/veilid-write-budget.md` — design-of-record for the #159 Tier-2 structural fix: frozen presence model (constant-cadence fixed-length sealed keepalive + read-side freshness inference), priority write-scheduler invariants (single funnel, 4 non-chat writes/min ceiling), and the two-leg rendezvous discovery rule (swept-whole placement + steady-state re-surfacing) under which #157 is a temporal defect (#159, #157, #141, #77).
- `daemonseed-gui`: the startup "assembling network" mask now shows the Veilid attach **peer count counting up** during the cold-start warmup, and holds a short settle window past the first content before opening the Lobby (so it opens with more backlog already in) instead of snapping shut on the first message (#144).
- `daemonseed-core`: `transcript::is_stale_backlog(sent_unix_ms, now_ms)` — true when a message is older than `TRANSCRIPT_MAX_BACKLOG_AGE` (24h), for pruning stale count-bounded-ring backlog at ingest (#151).
- `daemonseed-core`: `room_message` module — the one signed room-message seal/open path (`seal_signed_room_message` / `open_signed_room_message`, parameterized by key + AEAD AAD + provenance domain + expected room_id) shared by public rooms and circles; plus `circle::key::circle_room_id`, the member-derivable circle wire identifier `SHA-384(cot_key)[:12]`, and `net::canonical_wire_handle` (gui) (#145, #146).
- `daemonseed-gui`: a startup "assembling your peer network" mask — a full-cover splash shown from Connect through the cold-start DHT warmup, framing the unavoidable convergence wait (see #140) as the serverless feature. Event-driven: dismissed on the first real content (a Lobby/circle message or a non-empty roster) or by the user ("Enter anyway"), never on a fixed timer (the warmup is long + variable). Shows the live connection-status; the attach peer-count + an animation are follow-ups (#144).
- `daemonseed-gui`: circle member-presence over Veilid (Phase 4 #77) — extends the lobby presence (#74) to circles: each joined circle gets a `PresenceTracker` and subscribes its presence sibling record; the heartbeat timer emits a per-circle sealed beacon and reaps each circle's roster, and inbound circle beacons fold into the owning circle's roster (`NetEvent::Roster{circle_id: Some(id)}`, routed to the active circle by `main.rs`). GUI only.
- `daemonseed-gui`: the unread-gated announcements landing over Veilid (Phase 4 A-d, #93) — after the operator record's post-connect backlog settles, the net actor fires one connect-time `PublicSpaceSnapshot` so the announcements pane auto-opens iff the content changed since last seen; fires once per connect. Landing timing on the async DHT is best-effort (#137).
- `daemonseed-gui`: the announcements/MOTD composer over Veilid (Phase 4 A-c, #92) — the GUI net actor wires `SetMotd` / `UploadAnnouncement` / `RefreshPublicSpace` (were "not yet on Veilid") onto the operator announce record: the composer signs content with the F17 project-release key (`dev_project_release_keypair`), publishes a 1-byte-KIND-tagged `SignedArtifact` (MOTD) / `Post` (announcement) via `publish_current_state`, and folds verified inbound items into a `PublicSpaceSnapshot` view (`build_announcements_view` reused). Clients verify against the always-authorized F17 key, so an empty `Whitelist` suffices — no signer-whitelist distribution. Dev-possession gate (`can_compose = true`); the production whitelist-membership gate and the rollback-freshness version (#136) are deferred. GUI only (TUI parity does not gate the cutover).
- `daemonseed-core`: `dev_project_release_keypair` — the dev-only F17 project-release SIGNING keypair (from the in-source `PROJECT_RELEASE_SEED`), the dev analog of `project_release_pubkey`; the key the dev announce composer signs with. Retired when the seed becomes a baked pubkey with an offline secret.
- `daemonseed-veilid-net`: `VeilidNetHandle::publish_current_state` (Phase 4 A-b) — the operator announcements/MOTD record write primitive: publish opaque bytes to a NAMED current-state slot (`"motd"`, or an announcement's content address) on the owner-gated project-announce record. The write is owner-signed, so only a holder of the project-announce owner seed (the non-derivable write-gate, A1) can place a value; clients `subscribe_room` and read/verify but cannot write. Content stays a public signed `SignedArtifact` (verified client-side by `verify_artifact`), not AEAD-sealed. Two-node operator-record oracle (`tests/two_node_operator_record.rs`, `#[ignore]`, live network). (The signer-gated composer, the app publish wiring, and the rollback-freshness version field are follow-ons — see the design's A1/A2 and #136.)
- `daemonseed-core`: project-announce channel core (Phase 4 A0/A1) — `derive_project_announce_veilid_owner_seed` / `ProjectAnnounceVeilidOwnerSeed` (+ `dev_project_announce_veilid_owner_seed`, `PROJECT_ANNOUNCE_OWNER_SALT` / `PROJECT_ANNOUNCE_VEILID_OWNER` HKDF constants): the maintainer-held Veilid DHT owner seed for the single project announcements/MOTD channel — the write-gate — HKDF-derived as a sibling of the F17 project-release seed, domain-disjoint from the content-signing key and every rendezvous owner. Plus `AnnounceFreshness` — the #78 monotonic rollback guard (holds `last_seen` as state so it is transposition-proof; `accepts`/`accept` reject a strictly-older record) so an untrusted transport can't replay a stale operator record to roll back a revocation/MOTD. The version must be a strictly-monotonic operator counter, never a wall clock.
- `daemonseed-core`: `derive_room_presence_veilid_owner_seed` / `RoomPresenceVeilidOwnerSeed` and `derive_circle_presence_veilid_owner_seed` / `CirclePresenceVeilidOwnerSeed`, plus the `public_room_presence_veilid_owner` / `circle_presence_veilid_owner` HKDF labels — a THIRD sibling of the room key / circle `cot_key`, disjoint from both the content key and the chat rendezvous owner, so member-presence beacons ride their OWN world-derivable DHT record (#74).
- `daemonseed-veilid-net`: `VeilidNetHandle::publish_presence` + `member_slot_id` — a current-state (last-writer-wins) transport write for sealed member-presence beacons on the presence rendezvous record, keyed to a per-member `current_state_subkey` slot (`member_slot_id` owns the pubkey→slot-id encoding so all callers agree); spawned off the actor loop and serialized per-record. Replaces the `presence()` stub. Slot count is bounded (`SUBKEY_COUNT`), so unbounded membership can slot-share — a bounded, self-healing degradation, not a crash (#74).
- `daemonseed-{gui,tui}`: Lobby member-presence over Veilid (#74) — the net actor subscribes the presence sibling record, emits a jittered ~15–20s sealed `MemberHeartbeat` (above the ~14.7s DHT watch floor, spawned OFF the actor loop so a slow DHT write never stalls chat) and reaps its `PresenceTracker` on the same timer, and folds verified, `#78`-fresh, non-own inbound beacons into the roster. The GUI emits `NetEvent::Roster`; the TUI maintains the tracker (its roster render is deferred). Two-node roster-converge oracle (`tests/two_node_presence.rs`, `#[ignore]`, live network).
- `docs/llm-api-manifest/daemonseed-veilid-net-api.yaml`: LAMA API manifest for the Veilid transport crate — modules, the `VeilidNet` / `VeilidNetHandle` surface (attach, routes, sealed send, circle/room publish/subscribe/resweep, share serve/fetch, share-advert publish/stop), the `discovery` (anti-swap route advert) and `share` primitives, `VeilidNetError`, and constants; plus a `lama.yaml` crate entry + manifest pointer. Closes the manifest gap open since the crate's Phase 1 (#127).
- `daemonseed-veilid-net` crate: Veilid transport layer (Phase 1) — identity-bound node, command-channel actor (`VeilidNet` / `VeilidNetHandle`), sealed 1:1 `app_message` over a private route, per-node `VeilidNetConfig::listen_address`. Workspace-excluded until the v0.33.0 cutover.
- `daemonseed-core`: `VeilidNodeSeed` + `DOMAIN_VEILID_NODE` — Veilid node identity derived from the identity mnemonic under a domain-separated HKDF label (D3).
- `daemonseed-veilid-net`: circles over Veilid (Phase 2, #99) — `VeilidNetHandle::publish_circle` / `subscribe_circle` over a shared-owner DFLT DHT rendezvous record; per-member append-ring fan-out; login-backlog sweep plus watch surfacing inbound circle messages as `VeilidNetEvent::Inbound`.
- `daemonseed-core`: `derive_circle_veilid_owner_seed` + `CircleVeilidOwnerSeed` + `circle_veilid_owner` HKDF label — a circle's deterministic Veilid rendezvous-owner seed, a sibling of `cot_key` from the same circle PRK, so every member computes the same DHT rendezvous address (#99).
- `daemonseed-tui`: Veilid net actor behind the `veilid` feature (#98) — `NetHandle::new` selects a `VeilidNetHandle`-backed actor (circles + attach; lobby/shares/presence/MOTD return "not yet on Veilid") over the same `NetCommand`/`NetEvent` contract; UI unchanged. Off by default.
- `daemonseed-veilid-net` + `daemonseed-{gui,tui}`: the steady-state resweep cursor selector is hoisted into a shared `resweep` module (`next_resweep_seed`) and imported by both net actors, replacing two byte-identical private copies; behavior and the per-crate tick/hand-off constants are unchanged (#157 follow-up).
- `daemonseed-{gui,tui}`: `DAEMONSEED_VEILID_DIR` / `DAEMONSEED_VEILID_PORT` env knobs select a per-instance Veilid store, listen port, and program namespace so several Veilid-mode clients run on one host (#98).
- `daemonseed-veilid-net` + `daemonseed-gui`: `DAEMONSEED_VEILID_TRACE` env gate (`vtrace!`) emits stderr probes at the attach (with peer counts), `open_or_create`, watch, sweep, and circle join/send/inbound boundaries for live Veilid manual test diagnosis (#98).
- `daemonseed-veilid-net`: extracted the shared-owner DFLT rendezvous engine to a generic `rendezvous` module (was `circle`); added `VeilidNetHandle::publish_room` / `subscribe_room` for the lobby / public rooms and public-share discovery — a `ShareAnnouncement` sealed under the `PublicRoomKey` is published on the lobby rendezvous record (Phase 3/4).
- `daemonseed-core`: `derive_room_veilid_owner_seed` + `RoomVeilidOwnerSeed` + `public_room_veilid_owner` HKDF label — a public room's deterministic Veilid rendezvous-owner seed, a sibling of the room key, so every participant computes the same lobby/public-room DHT rendezvous address (Phase 3/4).
- `daemonseed-veilid-net`: public-share content transfer over `app_call` (Phase 3) — `VeilidNetHandle::serve_share` serves an indexed share owner-on-demand over a private route; `fetch_manifest` / `fetch_chunk` reassemble the `PublicRoomKey`-sealed response from ≤32 KiB transport fragments and SHA-384-verify each 1 MiB chunk against its content address (ISC-S28).
- `daemonseed-veilid-net`: signed route advert for public-share discovery (Phase 3) — a `discovery` module (`DiscoveryEnvelope`, `route_provenance_input`, the `RouteAdvertSigner` capability, `verify_route_advert`) and `VeilidNetHandle::publish_share` bind a sharer's private-route blob to the announcer's ML-DSA-87 identity over a domain-separated `share_id ‖ route_blob` (anti-swap on the world-writable lobby record), signed via a least-authority capability that keeps the identity key out of the transport crate; re-published on `RouteChanged`.
- `daemonseed-gui`: public-share publish / discover / fetch wired onto the Veilid transport behind the `veilid` feature (Phase 3 Slice 2b) — the GUI net actor seals a `ShareAnnouncement` with the stable identity, serves content owner-on-demand, publishes a signed `DiscoveryEnvelope` on the lobby rendezvous, and on the fetch side anti-swap-verifies a discovered route before importing it. Node identity stays ephemeral; the stable key signs content only.
- `daemonseed-gui`: public-room (Lobby) chat over Veilid behind the `veilid` feature — `SendRoom` seals a `PublicRoomMessage` under the lobby `PublicRoomKey` and publishes it on the lobby rendezvous (`publish_room`) with an optimistic local echo; `subscribe_lobby` emits `RoomJoined` on connect; `handle_inbound` surfaces an inbound `open_room_message` as `NetEvent::Message` (own-suppressed by handle) ahead of share discovery.
- `daemonseed-tui`: public-room (Lobby) chat over Veilid behind the `veilid` feature (GUI parity) — `SendPublicRoom` seals a `PublicRoomMessage` and publishes it on the lobby rendezvous; `subscribe_lobby` emits `PublicRoomJoined` on connect; `handle_inbound` surfaces an inbound `open_room_message` as `PublicRoomMessage` (own-suppressed by handle) ahead of share discovery. No actor-side echo — the app echoes the composed line on Enter.
- `daemonseed-cli`: `route_signer::IdentityRouteAdvertSigner` (feature `veilid`) — least-authority adapter wrapping the stable `SignKeypair` as the `RouteAdvertSigner` capability, keeping the identity key out of the transport crate.
- `daemonseed-veilid-net`: `VeilidNetHandle::stop_serve` — the teeth of unpublish: de-registers a share from the serve registry and drops its advert, so the owner stops answering fetch `app_call`s for it (a withdraw announcement alone only removes it from listeners' catalogs).
- `daemonseed-veilid-net`: `VeilidNetError::NotServed` — an authoritative "the peer no longer serves this share" (withdrawn or never offered), distinct from a transport error, so a downloader distinguishes a deliberate unpublish from a silent disconnect instead of guessing through timeouts; surfaced in the GUI fetch path as a plain "the sharer withdrew this share" notice.
- `daemonseed-tui`: the same public-share publish / discover / fetch path on the Veilid transport behind the `veilid` feature (Phase 3 Slice 2b TUI mirror) — adapted to the TUI's `NetCommand`/`NetEvent` contract (`SharesSnapshot{local,remote,indexer_status}`, per-surface error events, `FetchedStore`-backed downloads), with the same invariants (ephemeral node id, stable-content identity, least-authority `RouteAdvertSigner`, `stop_serve` on unpublish, `NotServed`→withdrawn notice, anti-swap verify-before-import).
- `daemonseed-veilid-net`: transit-experiment harness (`tests/transit_experiment.rs`, `--ignored`) — a two-node live-network matrix measuring private-route `app_call` latency across the Stability × Sequencing 2×2 plus hop-count and burst cells, with a same-clock rtt split (`req_1way` / `reply_op` / `reply_path`) (#123).
- `daemonseed-veilid-net`: `DAEMONSEED_VEILID_TRACE` lines carry a `+seconds` relative timestamp (`trace_elapsed_secs`), and the serve / publish / advert-refresh paths report per-stage durations (queued / seal / reply; write ms), so a live log localizes where a deadline is spent.
- `daemonseed-veilid-net`: `AimdWindow` — an AIMD (additive-increase / multiplicative-decrease) fetch-concurrency window controller (climbs by one per healthy observation, halves on a breach, bounded `[1, FRAGMENT_FETCH_CONCURRENCY]`), wired as the public-share fetcher's adaptive fragment window (#128): `fetch_chunk` times each fragment `app_call` and returns the max per-fragment latency, and the GUI fetcher drives one controller per download, observing that latency against `FRAGMENT_LATENCY_THRESHOLD` (2 s, manual test-tunable) to size the next chunk's fragment concurrency. Starts fully open, so a healthy download is unchanged and only a congested link narrows the window, yielding concurrency back to interactive chat.
- `daemonseed-veilid-net`: `VeilidNetHandle::resweep_rendezvous` — re-runs the one-shot backlog sweep on an already-subscribed rendezvous record without registering another watch, the recovery primitive for a backlog item published during the post-(re)connect watch-warmup window (#132/#133).
- `daemonseed-gui`: chat messages carry a muted relative-age caption ("just now" / "2m ago" / "3h ago" / "sitting 3 days"), formatted by `format_relative_age(sent_unix_ms, now_ms)` on every model rebuild and refreshed on a ~30 s tick, so a swept old backlog message reads as stale, not live (#100).

### Changed

- docs/manifests: the residual relay-era references are swept for release — the gui/tui crate doc headers are rewritten for the Veilid-native client and every `cargo doc --workspace --no-deps` intra-doc-link warning is cleared; `docs/llm-api-manifest/daemonseed-cli-api.yaml` is rewritten to the current `route_signer` + `public_space` library surface; the stale `daemonseed_server` references are dropped from `daemonseed-core-api.yaml`, `lama.yaml`, and the root `Cargo.toml` dep comments; and the dead `xtask` `mvp-gate` / `wire-shape` subcommands (which built the deleted relay binary and ran deleted integration tests) are removed.
- `daemonseed-{gui,tui}`: the client net actors run Veilid-only. `net::NetHandle::new` spawns the Veilid actor unconditionally (the `#[cfg(feature = "veilid")]` selection is gone), and `net` is now the transport contract (`NetCommand` / `NetEvent` / `NetHandle` / `RosterEntry` / `ShareManifestEntry`) plus the transport-agnostic helpers the Veilid actor and the UI share (roster building, handle canonicalization, share-path hygiene). The `veilid` cargo feature is removed across `daemonseed-{gui,tui,cli}`; `daemonseed-veilid-net` is a non-optional dependency; `daemonseed-cli`'s `route_signer` module is unconditional.
- `daemonseed-{core,server}`: `kats` and the TLS `CryptoProvider` install move from `daemonseed-server` to `daemonseed-core`.
- `daemonseed-core`: the redacted-zeroizing secret-seed newtype boilerplate is consolidated behind one crate-internal `secret_seed::redacted_secret_newtype!` macro (`boxed` / `inline` shapes) and the six boxed rendezvous-owner-seed derivations share one `secret_seed::derive_boxed_seed` HKDF-expand/stack-zeroize/`Box` helper — the six `*VeilidOwnerSeed` types plus `ShareRootIkm` / `VeilidNodeSeed` now carry their zeroize-on-drop + redacted `Debug` + both-path stack-zeroize hygiene from one place; the per-context HKDF-extract, the distinct key-class newtypes, and every public signature and error variant are unchanged (byte-identity KATs guard the derivations). `ShareRootIkm` / `VeilidNodeSeed` `Debug` normalizes to the tuple form `Name(<redacted>)` used by the other secrets (both stay fully redacted) (#135).
- `daemonseed-core`: the AES-256-GCM `nonce ‖ ct ‖ tag` envelope invariant is extracted to one crate-internal `aead_envelope::{seal_envelope, open_envelope}` primitive shared by `room_message`, `heartbeat`, and `share_rollcall`, which previously inlined it three times; each call site keeps its own AAD, the heartbeat keeps its caller-side fixed-length padding, and each maps the internal `EnvelopeError` onto its existing error type so no public signature or wire byte changes (#149).
- `daemonseed-{proto,core,gui,tui}`: `ShareAnnouncement` carries `bytes root_commitment`, and `share_id` is the receiver-verifiable v2 derivation `trunc128(SHA-384("daemonseed/share-id/v2" ‖ sender_pubkey ‖ root_commitment))`, enforced at every ingest point — breaking `daemonseed-proto` v1 with no legacy arm; `mint_share_id` is removed from the publish path (all four sites derive) (#156).
- `daemonseed-veilid-net`: `VeilidNetEvent::Attachment` carries the current `reliable_peers` / `live_peers` attach counts (was only traced), surfaced to the startup mask as they climb (#144).
- `daemonseed-proto`: **BREAKING (MAJOR wire)** — `CircleMessage` and `PublicRoomMessage` merge into one signed `RoomMessage { room_id, sender_pubkey, sender_handle, body, sent_unix_ms, signature }`. Circle chat is now self-signed for per-sender authorship exactly as a public-room post; `room_id` is the room name (public) or the member-derivable circle fingerprint `SHA-384(cot_key)[:12]` (circle). No migration (ephemeral content; unsigned backlog fails verify and drops) (#145, #147).
- `daemonseed-core`: `circle::message::{seal_message, open_message}` and `public_room::{seal_room_message, open_room_message}` are thin wrappers over one signed `room_message` seal/open path; `seal_message` takes the poster's `SignKeypair`; the circle AAD + provenance domain are `daemonseed/circle/message/v2`; `open_room_message` gains a `room` argument (the signature is verified against the caller's expected room_id, never the carried field) (#145).
- `daemonseed-{gui,tui}`: circle send/open route through the signed `RoomMessage`; `mine`, own-loopback suppression, and dedup key on the stable `sender_pubkey`; the displayed author binds to `SHA-384(sender_pubkey)[:12]` via `Handle::display_bound`; the GUI send paths transmit the canonical `name#<12hex>` handle so receivers honor the display name (#146).
- `daemonseed-gui`: the announcements/MOTD pane never force-opens — the #93 connect-time auto-landing is replaced by an unread dot on the Announcements tab (`state::announcements_unread`, reusing `combined_content_hash`), shown when the verified content is non-empty and changed since last seen, cleared on open. It behaves identically on connect and mid-session, and an empty-view guard means an unconverged/blank pane no longer auto-opens (the old auto-land could land on a not-yet-converged blank view). Removes the `landing_decision`/`Landing` decision; `OPERATOR_CONNECT_LANDING_DELAY` + the connect-landing machinery are now vestigial (their removal is a follow-up, coupled to the #140 resweep references) (#142).
- `daemonseed-gui`: the post-connect warmup re-sweep is stepped and priority-ordered — the single delayed re-sweep at +25s is replaced by `WARMUP_RESWEEP_SCHEDULE` (force-refresh re-sweeps on `sleep_until` deadlines from connect), re-sweeping the content records in priority order (operator MOTD/announce → lobby chat → circle chats, via the unit-tested `warmup_priority_records`) so DHT-converged content surfaces sooner during cold-start than the passive watch alone. Presence records are excluded (they self-heal via the heartbeat cycle); re-swept already-seen items are deduped downstream. **Dialled down after manual test** (2026-07-08: the 4-round 12/25/45/75s schedule spun the host fans up for marginal benefit — operator content converged past the window) to a light 2-round schedule (+20/60s, circles only round 1); a light best-effort early-catch, tunable by hand, keep/revert pending manual test (#140).
- `docs/design`: the Phase 4 design-of-record (presence + announcements/MOTD) is consolidated onto Veilid as `phase4-veilid-presence-announcements.md`; the two relay-era docs (`presence-superstructure.md`, `announcements-motd-admin.md`) are archived under `docs/design/zarchive/` behind redirect tombstones — one active source of truth (#74/#75/#77, #88/#92/#93/#94). Announcements/MOTD MVP is scoped to a single project-owned channel (design decision A0); per-community channels are deferred (they reintroduce an owner/originator onto the deliberately-ownerless circle model, ISC-C8).
- `daemonseed-veilid-net`: the inbound serve lane is bounded — a full intake queue (`SERVE_QUEUE_CAP` = 256) sheds the incoming fetch request on the producer (a shed serve is one fetcher retry the fetch side already does) instead of growing without limit under a serve-latency spike, and concurrent `app_call_reply` tasks are capped by a semaphore (`MAX_CONCURRENT_SERVE_REPLIES` = 128) acquired before sealing, so a fetch burst can neither spawn unbounded reply tasks nor hold unbounded sealed responses in memory. The cap exceeds one fetcher's 64-fragment peak so a single legitimate large download never self-throttles, and the answer-window expiry is re-checked after the permit is acquired so a request that aged out while waiting is dropped instead of sealed-and-sent too late (#125).
- `daemonseed-gui`: the public-share list attributes a foreign share to its announcer — a discovered share's row shows the sharer's handle, with the sharer's **verified** `#12hex` identity fingerprint (`SHA-384(sender_pubkey)[:12]`, derived from the anti-swap-verified announcer pubkey, not the spoofable advisory handle) revealed on hover; own shares show "you", backed by the `ShareListing` `mine` marker distinguishing own published shares from foreign discovered shares. Adds `daemonseed_core::handle::pubkey_fingerprint` and a `ShareListing::sharer_fingerprint` field (#114).
- workspace: enable oxicrypt's `accel-aes` feature — AES-GCM (the cot seal/open) dispatches to AES-NI at runtime via CPUID when present, else the portable constant-time path; adds the `oxicrypt-aes-accel` path dep to the lock (#123).
- `daemonseed-veilid-net`: each rendezvous publish (`PublishRendezvous`) runs on a spawned task off the actor command loop instead of blocking it on the DHT write, so a slow publish no longer parks the commands behind it; delivery ordering stays receiver-side (`sent_unix_ms`), with shutdown-drain / backpressure hardening tracked in #129 (#128).
- `daemonseed-veilid-net`: opened rendezvous DHT records are cached per owner (`rendezvous::OpenCache`, owner seed → the post-`open_or_create` `RecordKey`), so repeated publishes/subscribes to a circle or the lobby reuse the open handle instead of paying a fresh `open_or_create` each time (#128).
- `daemonseed-gui`: the restore banner now leads the connect-time republish — a single "Restoring N shares from last session…" notice fires (via `NetEvent::RestoreStarted`) before any share is re-served, instead of a per-share completion notice that arrived coincident with the share going live and read as redundant (#122).
- `daemonseed-veilid-net`: the public-share fetcher pulls fragments in a bounded-concurrency pipeline (`buffered`, in request order) instead of one `app_call` at a time, with each fragment size-capped at `FRAGMENT_SIZE` to bound reassembly memory (#109).
- `daemonseed-gui`: public-share downloads fetch a file's chunks with bounded concurrency (`fetch_chunks_ordered`, `buffered` window `CHUNK_FETCH_CONCURRENCY`) instead of one chunk at a time, preserving manifest order for byte-for-byte reassembly and per-chunk progress; the higher level above #109's within-chunk fragment pipeline (#113).
- `ISA.md` / `daemonseed-isc`: the server `ISC-S*` design criteria are reconciled for the Veilid cutover. The relay/TLS/gRPC/federation criteria (positive S1/S2a/S3/S5/S6/S10–S14/S16–S19; negative A-S1/A-S4b/A-S6–A-S9/A-S11–A-S14) are withdrawn as ISA tombstones and deregistered from `daemonseed-isc` (`TOTAL` 213→189); the surviving public-space/CoT/room/share/provenance criteria are re-scoped from the relay to the Veilid DHT rendezvous, and `ISC-A-S4` re-scopes the signer whitelist to an operator-owned Veilid record. `ISC-S26` and `ISC-A-S5` relax "no persistent state / no store-and-forward" to bounded-TTL sealed DHT values (content-chunk fetch stays strictly live-only, ISC-A-S21).

### Removed

- `daemonseed-{gui,tui}`: the relay net actors (`net::net_actor` + the `Actor` relay implementation and its in-process relay round-trip tests) and the `veilid` feature gate; the relay-only `NetCommand` / `NetEvent` variants (the actor self-commands and the session/probe test seams) and the `NetCommand::Connect` relay fields (`server_id`, `address`, `index_params`) together with their `Profile::index_params` / `GuiState::persisted_index_params` / `Profile::index_key` plumbing.
- `daemonseed-gui`: `state::build_announcements_view` (the relay-path client re-verification of served announcements/MOTD); the Veilid actor verifies operator content at ingest and builds the view directly.
- `daemonseed-{gui,tui}`: the `daemonseed-server` dependency — crypto init (`kats` + TLS provider install) now rides `daemonseed-core`.
- `daemonseed-cli`: the relay client — the `connect` / `session` / `identity_proof` modules (TLS handshake, `AppSession` gRPC-over-h2, and the identity-proof exchange) and the `main` binary (its only subcommand was the relay `connect`). `daemonseed-cli` is now a library-only crate exposing the Veilid route-advert signer (`route_signer`) and the announcements/MOTD authoring + render helpers (`public_space`); the `daemonseed-server`, TLS-stack (`rustls`, `tokio-rustls`, `oxitls-rustls-provider`), tonic-client, `tokio`, and `clap` dependencies came off with it.
- The `daemonseed-server` relay crate and its server-only integration suite (the `announcements_motd` / `m6` / `m9` / `m10` / `public_rooms` / `alpha2_opaque_share_id` ISC-coverage tests, the `subprocess_gate` PTY harness, and the `tests/common/` relay-spawning harness). `daemonseed-veilid-net` joins the workspace as the transport; its standalone `Cargo.lock` folds into the workspace lock.

### Fixed

- `daemonseed-veilid-net`: the advert-publish rollback path no longer tears down a concurrent reshare's live route — `rollback_advert_route` (reached on signing- and DHT-write-failure) now compare-and-removes under the `advert_routes` lock, freeing only the route the failing call still owns, exactly like the one-shot withdraw path. A bare remove-by-key could otherwise wipe a same-`share_id` reshare's live entry (leaking its route and blinding RouteMaintenance to its death) and double-free an already-released route (#163).
- `daemonseed-gui`: leaving a circle no longer crashes the GUI — the circle-detail name/relay/fingerprint/leave sections are now always-present `visible:`-gated layouts instead of `if`-conditionals, so blanking those props on leave never tears down the subtree mid-render (`RefCell already borrowed` in Slint's software `free_graphics_resources`). Matches the existing phrase-reveal `visible:` convention (#176).
- `daemonseed-veilid-net` + `daemonseed-{gui,tui}`: a withdrawn share no longer re-lingers on the discovery record. `VeilidNetHandle::publish_share` takes a `persist` flag; a withdraw (`persist=false`) is a one-shot write that is never entered into the re-publish set and releases its own transient route once the single write completes (a guarded compare-and-release, so a concurrent reshare's live route is never freed). Previously the withdraw was re-inserted into the advert set and re-published on every RouteChanged/watchdog tick, wasting the WB write budget and churning routes for a share that was gone. Share conflict resolution stays last-writer-wins by `sent_unix_ms`, so a reshare of the same `share_id` still wins promptly (#163).
- `daemonseed-isc`: ISC-C99 (circle-chat per-sender authorship) is tracked in the coverage registry — present in `ISCS` (TOTAL 200→201) — with unit coverage (#150).
- `daemonseed-{core,gui,tui}`: a first-seed attacker can no longer occupy a victim's `share_id` under its own key — ingest folds an announcement only when `share_id == derive_share_id_v2(sender_pubkey, root_commitment)`, checked at the catalog fold, the withdraw branch, the standalone route-import gate, and the circle path; the nonce hiding the folder path is derived from a dedicated identity IKM, so `root_commitment` leaks no path (#156).
- `daemonseed-{gui,tui}`: chat and share adverts written after the cold-start warmup now re-surface at already-settled peers. The net actor runs a post-warmup steady-state resweep — one subscribed chat/discovery record per ~10s tick, round-robin over lobby chat, share-advert, operator, and each circle chat (key-based cursor, so a join/leave never skips a record); presence records are excluded (they self-heal via keepalive re-writes). Previously the warmup resweeps ended at +60s and the passive DHT watch missed ValueChanges, so a message that landed later echoed locally but never reached a peer that had already settled. Generalizes the WB-4 two-leg discovery fix past its frozen share-advert scope; registers WB-ISC-14 (#157).
- `daemonseed-{gui,tui}`: the read-side chat→presence fold now applies the same beacon-freshness bound as the beacon fold — a replayed, provenance-valid OLD same-room chat write no longer re-freshens a departed member's roster liveness (an untrusted relay could otherwise sustain a ghost "online" by replaying one captured message under the TTL). Message delivery and dedup are unaffected; only the presence refresh is bounded (#165).
- `daemonseed-gui`: the graceful-close LEAVE tombstone is now actually delivered — `WithdrawAllOwned` awaits each per-room leave publish (it was spawned fire-and-forget and aborted at process exit before its DHT set completed), so a member departs peers' rosters immediately on quit instead of aging out at the ~600s TTL; the close budget covers withdraws + leaves (raised 8s→12s). TUI graceful-close leave still relies on the TTL backstop (#161).
- `daemonseed-veilid-net`: the WB-3 write scheduler no longer busy-spins at 100% CPU under sustained write congestion — `next_wakeup` armed the timer at `now` for an already-passed starvation-escalation crossing (`.max(now)`), so the driver hot-looped while the aged non-chat write could not dispatch (AIMD window full). An escalation crossing is now armed only while it is still in the future; once passed the head already sorts at its escalated rank and dispatches on the next completion (#162).
- `daemonseed-veilid-net`: an in-flight tombstone now dominates a same-id current-state exactly like a queued one — the scheduler tracks the logical id of a tombstone currently being written, so a keepalive/refresh enqueued while a leave or share withdraw is mid-DHT-write is dropped instead of resurrecting the departed member / withdrawn share once the tombstone completes (closes the in-flight window WB-ISC-12 left open) (#164).
- `daemonseed-gui`: a nameless/floor identity no longer renders its own Veilid chat messages twice — the optimistic echo computes `who` through the same `Handle::display_bound(wire_handle, pubkey).format(Default)` path as the DHT re-surface, so a floor handle floors to `#<hex>` on both sides and `push_message` dedups the echo (the echo previously used `split('#').next()`, collapsing a `#<hex>` handle to `""` → dedup mismatch). (#155)
- `daemonseed-{gui,tui}`: the Veilid lobby presence-beacon cadence is widened [15,20]s → [50,55]s to relieve Veilid DHT `set_dht_value` saturation (#159) — the per-member beacon was the dominant DHT writer, backing writes up to minutes (`write ok in` 90s–314s) and starving chat delivery, share-advert refresh, and presence freshness (roster flicker-then-reap); the ~3× cadence cut restores single-digit-second writes (manual test 314s → ≤5.8s). Tier-1 mitigation; the structural fix (presence-as-reads + a priority write scheduler) is tracked by #159.
- `daemonseed-{core,gui,tui}`: public-share ownership is bound against forged withdraws and hijack re-announces (#152) — `ShareCatalog::apply` rejects a withdraw or an owner-changing refresh whose `sender_pubkey` differs from the stored owner (first-writer-wins on identity), and `apply_discovery` now gates the discovered-**route** map on the catalog decision, so a rejected forged withdraw no longer evicts the owner's route (share stays fetchable) and a rejected hijack refresh no longer replaces it (no fetch redirect). A foreign peer scraping a victim's public `share_id` off the world-writable lobby record can thus neither censor nor redirect a KNOWN share. The residual first-seed squatting of a not-yet-announced `share_id` (needs a receiver-verifiable `share_id`↔`sender_pubkey` binding) is tracked in #156.
- `daemonseed-{core,gui,tui}`: public-share discovery rides its OWN Veilid rendezvous record, split off the lobby chat record (#153) — a new `derive_room_share_veilid_owner_seed` / `RoomShareVeilidOwnerSeed` sibling (HKDF label `public_room_share_veilid_owner`, disjoint from the chat and presence owners) so share adverts (a current-state writer) and lobby chat (an append-ring writer) no longer overlap the same 64-slot subkey space and silently overwrite each other (the message-loss / undiscoverable-share collision the co-location caused). The GUI/TUI subscribe + re-sweep the share record and publish/withdraw adverts on it; the share write path fails closed on a derivation error (no all-zeros write record). The three room owner-seed derivations share one `expand_room_owner_seed` body so a future hardening change can't diverge them.
- `daemonseed-gui`: stale DHT-ring backlog (a message older than 24h, a count-bounded-ring ghost from a prior session) is pruned at ingest — no longer renders as a "ghost" nor collapses onto the `now-24h` ordering edge (which sorted old messages mixed) (#151). TUI prune deferred to #111.
- `daemonseed-{gui,tui}`: a mid-session identity rename no longer duplicates or mis-attributes own messages — authorship, `mine`, and own-loopback dedup key on the stable identity pubkey, not the mutable display handle (#143, #146).
- `daemonseed-gui`: operator announcements are kept alive in the DHT — the announce-owner-seed holder re-publishes the content-addressed announcement slots every `OPERATOR_KEEPALIVE_INTERVAL` (120s) off the actor loop so their DHT TTLs stay fresh; the mutable MOTD slot is excluded (#141).
- `daemonseed-gui`: own chat messages now render from the cold-start backlog — `handle_inbound` emits an own looped-back lobby/circle message `mine:true` (it was suppressed by handle match), and `push_message`'s exact-match dedup (`sent_unix_ms` + content) collapses the live echo↔re-surface pair, so a fresh start reconstructs BOTH halves of the conversation instead of only the other party's (#143).
- `daemonseed-{core,gui}`: the open lobby (and circles) order + read-high-water on a **clamped** sender timestamp, not the raw untrusted one — closing the forgeable-ordering vulnerability (#131/#126). `daemonseed_core::transcript::clamp_order_ms` bounds an advisory `sent_unix_ms` to `[now − 24h, now + 120s]`; each `Msg` stores its clamp-at-insert `order_ms`, and ordering + the read high-water use that stored key (real backlog is in-window so `order_ms == sent_unix_ms` — honest ordering is exact). A forged extreme is pulled to a window edge, so an open-room peer can no longer pin the transcript (`i64::MIN`/`i64::MAX`), bury a message far in the past, or suppress unreads with a far-future stamp — including via `switch_to`, which now advances the high-water from the clamped `order_ms` capped at `now`, never the raw timestamp. De-dup still keys on the original `sent_unix_ms` (stable across DHT re-sweeps). The TUI transcript keeps its #130 raw ordering for now (a post-cutover surface); TUI-#131 rides the TUI parity work (#111). Auto-closes #131 and #126 at the v0.33.0 cutover.
- `daemonseed-tui`: the chat transcript de-dups and chronologically orders messages — a new `App::push_message` routes both inbound sites (circle + lobby) and both local echoes through one path that skips an exact `(surface, sender, body, sent_unix_ms)` match (a DHT re-sweep can re-deliver an already-seen line) and inserts by `sent_unix_ms` (propagation can deliver out of send order), where the flat transcript stays globally sorted and `messages_on` keeps each pane chronological; a local echo now carries a real `now_unix_ms()` (was `0`) so it sorts as the newest line. TUI parity with the GUI's `push_message` (#130). (The GUI's per-room unread high-water half has no TUI counterpart — the TUI has no unread indicator.)
- `daemonseed-gui` tests: the two `presence_roster` fingerprint tests initialize oxicrypt before deriving a fingerprint, so SHA-384's power-up self-test passes and the fingerprint is non-empty; under nextest's per-test process isolation they degenerated to an empty `#` and failed `cargo test --workspace` (the release-gate). Test-only; no behaviour change.
- `daemonseed-veilid-net`: a share advertised over a route that died *silently* — one veilid never surfaced in a `RouteChange.dead_routes` — is recovered by a slow-cadence advert watchdog (`AdvertWatchdog`, `ADVERT_WATCHDOG_INTERVAL` = 150s) that re-publishes *idle* adverts on a timer, the only path independent of the observed-death trigger the relevance filter left as the sole refresh cause. It skips any share that answered a fetch within `SERVE_RECENCY_WINDOW`, so an active download's in-use route is never rotated out from under it; the interval is 30× the coalesce window and shares the same in-flight + interval gate as a `RouteChanged` refresh (`spawn_refresh_if_due`), so it cannot recreate the refresh storm (#124).
- `daemonseed-gui` Veilid mode: lobby chat carries the sender's wire `sent_unix_ms` through to the transcript, so a lobby message renders its real relative age (not "just now"), inserts in chronological order, and re-swept backlog is deduped — routed through the same `push_message` exact-match dedup + ordered-insert the circle path uses. `NetEvent::Message` now carries `sent_unix_ms` (#126).
- `daemonseed-gui` Veilid mode: the manual Refresh button on the public-shares tab re-sweeps the lobby rendezvous (`ResweepShares`) to recover a share announcement missed by the join-time sweep (#133) — a rendezvous subscribe sweeps once at join then relies on a watch whose latency is tens of seconds, so a plain re-render could never surface a missed announcement. The ~3 s shares-tab liveness auto-poll stays a cheap local re-render (`RefreshShares`) and never re-sweeps the DHT.
- `daemonseed-gui` Veilid mode: a one-shot delayed re-sweep runs ~25 s after connect over the lobby and every joined circle, recovering announcements and circle messages published during the post-connect watch-warmup window that the single join-time sweep missed (#132). Downstream dedup (`apply_discovery` self-filter, `push_message` exact-match) folds a re-swept already-seen item silently.
- `daemonseed-veilid-net`: concurrent writes to one rendezvous record are serialized by a per-`owner_seed` async lock. Spawning each `PublishRendezvous` off the actor loop (#128) let two append-ring writes for the same record race into the shared 2-slot ring, so an older seq landing after a newer one silently dropped the newer message — a loss the receiver's `sent_unix_ms` sort cannot recover. The lock is held across the whole open+seq-bump+write for a record, and every open path (`publish_rendezvous`, `publish_current_state`, `subscribe_rendezvous`) takes it, so it also single-flights the cold-cache record open (two concurrent first-publishes no longer both run `open_or_create`). Distinct records take distinct locks and stay fully concurrent, so the actor command loop still never blocks (#128).
- workspace: dev builds compile the oxicrypt crates at `opt-level = 3` — the portable constant-time crypto at opt-level 0 made a debug manual test client take ~5 s to AEAD-seal one 1 MiB share chunk, exceeding veilid's 5 s `app_call` answer window and failing every fragment fetch on a seal-cache miss (#123).
- `daemonseed-gui` Veilid mode: a graceful close now reliably withdraws owned shares before teardown — the close-time withdraw wait was raised from 2 s to 8 s so a Veilid DHT `set` under load completes (the actor acks only after the set returns) instead of being aborted mid-set, which had left the share on a peer's list for the full ~600 s TTL; the wait still returns the instant the withdraw acks, so a healthy close stays fast (#121).
- `daemonseed-gui`: leaving a circle no longer panics with "RefCell already borrowed" — the leave handler's `forget_circle` + rail rebuild is deferred to the next event-loop tick (`defer`) instead of mutating the rail model synchronously from inside the Slint clicked handler, where an inbound-circle-message rail rebuild on the drain timer could re-enter the partial renderer (#120).
- `daemonseed-gui` Veilid mode: a published share no longer appears twice (the second copy pointing at a dead route) on the sharer's reconnect — the `share_id` is now derived deterministically from `(identity pubkey, root)` (`daemonseed_core::share_announce::derive_share_id`) instead of freshly minted, so a republish re-asserts the same id and a fetcher folds it onto the existing catalog entry (#112).
- `daemonseed-gui` Veilid mode: a share whose fetch fails on a dead/un-importable route or an authoritative withdraw is pruned from the recipient's catalog + discovered-route map (ISC-S30 prune-on-fetch-fail), self-healing a stale copy instead of leaving it in the list; a still-live share re-announces and reappears (#112).
- `daemonseed-veilid-net`: the share-advert refresh no longer leaks private routes — each `RouteChanged` re-allocation releases the share's previous `RouteId` (`release_private_route`) instead of accumulating dead routes under churn.
- `daemonseed-veilid-net`: the `RouteChanged` advert refresh runs off the actor loop (spawned, coalesced by an in-flight guard, the interval stamped from completion) so re-allocating a route per advert no longer head-of-line-blocks inbound serve `app_call`s and outbound fetches; the append-ring cursor is shared behind a mutex so off-loop and on-loop writes don't collide.
- `daemonseed-veilid-net`: an inbound serve `app_call` is no longer silently dropped when the command channel is momentarily full — it falls back to a spawned awaited send so the fetcher doesn't time out on that fragment.
- `daemonseed-veilid-net`: the served-share seal cache is LRU-bounded (`SEAL_CACHE_CAPACITY`) so a large share's many chunks can't grow it without limit; an eviction beyond capacity is fail-closed (a re-seal makes the fetcher's mixed-seal reassembly fail its AEAD open, never accepting bytes).
- `daemonseed-gui` Veilid mode: persisted shares are re-published on connect — the Veilid path dropped `republish_roots`, so a restored share was neither re-served nor re-announced after a reconnect/restart; it now re-serves under a fresh route and re-announces on the lobby, relay-parity with the #102 circle rejoin (#108).
- `daemonseed-gui` Veilid mode: the sender's own circle message echoes immediately — the local echo is emitted before the DHT publish (which now runs off-task) instead of after the round-trip (#101).
- `daemonseed-gui` Veilid mode: persisted circles are re-subscribed on connect via `rejoin_circles`, so a restored circle pane is joined on the transport rather than failing the next send with "join the circle before sending" (#102).
- `daemonseed-gui`: the circle transcript is ordered by `sent_unix_ms` (ordered-insert in `push_message`), so a message delivered out of send-order by DHT propagation latency slots into its chronological place instead of appending out of order (#105).
- `daemonseed-veilid-net`: the public-share fetcher caps reassembly (fragment count + cumulative bytes, `MAX_FRAGMENTS` / `MAX_REASSEMBLED_LEN`) so a malicious sharer's oversized `total` cannot drive an unbounded `app_call` loop or memory growth before the post-reassembly SHA-384 chunk check (Phase 3).
- `daemonseed-gui`: a surface-level `NetEvent::Error` no longer flips the connection indicator to "offline" — a stubbed Phase-4 surface returning "not yet on Veilid" was being treated as a connection failure (`connected=false`), so a fully-attached Veilid node displayed as offline; connection state is now owned solely by `Connected`/`ConnectFailed`/`Disconnected`, and a real surface error shows as a transient notice.
- `daemonseed-gui`: the full fetch error is logged via `DAEMONSEED_VEILID_TRACE` (the GUI status line truncates it to an ellipsis), so a chunk-fetch failure's cause is diagnosable.
- `daemonseed-gui` Veilid mode: duplicate circle messages are coalesced — the login backlog sweep and the live watch could both deliver the same message; `push_message` now skips an exact `(sender, body, sent_unix_ms)` already present (alongside the #105 ordered-insert).
- `daemonseed-veilid-net`: public-share fetch retries a fragment `app_call` on a transient transport error (e.g. Timeout) up to 3× with a 250 ms backoff before failing the chunk — a single timed-out round-trip among a chunk's ~34 fragments no longer kills the whole fetch (WIP private-route stability; observed live as `chunk fetch failed: send failed: Timeout`). A not_found/withdraw is a successful reply, so retry never masks the authoritative `NotServed`.
- `daemonseed-veilid-net`: inbound serve `app_call`s are answered on a dedicated lane (`serve_loop`), never the actor command FIFO — a multi-second inline chat publish parked serve requests past veilid's ~5 s answer window, so every reply was rejected as "Unmatched operation id" and the fetcher timed out its whole fragment wave; entries already past the answer window are shed instead of sealed-and-rejected, and the shared serve registry recovers from a poisoned lock.
- `daemonseed-veilid-net`: the advert refresh fires only when a route the node currently advertises is in veilid's `dead_routes` — the actor's own per-republish route releases re-triggered `RouteMaintenance` in an endless refresh→release→RouteChange storm republishing the discovery envelope every coalesce window. A relevant death arriving while the refresh gate is busy is re-delivered after the window (the event is one-shot under the filter), `RouteChange` delivery falls back to a spawned send when the FIFO is full, and a failed advert publish rolls back its `advert_routes` entry and releases the never-published route.

## [0.32.0] — 2026-06-26

### Added

- server: `UploadMotd` RPC — in-band signer-set MOTD, single-slot replace, plaintext-enforced (#89)
- cli/public_space: client signer authoring (`sign_post`/`sign_motd`/`sign_post_delete`) + signer self-determination (`local_key_is_whitelisted`) (#90)
- gui: announcement + MOTD display panes — relay MOTD (verbatim) + announcements list, client-re-verified (#91)
- gui/tui: signer-gated MOTD/announcement composer — shown only when the local identity key is on the relay's published whitelist; signs + uploads via UploadMotd/UploadPost (#92)
- gui: unread-gated landing — auto-open the Announcements pane on connect when the relay's MOTD/announcements changed since last seen (per-relay client-derived hash), else the Lobby (#93)
- gui: per-circle connected-presence — sealed member heartbeats emitted into and tracked per joined circle (relay-blind), feeding the active room's roster (#77)
- gui: rename your identity from the Ctrl-K palette — validate, re-seal, and update the live handle without a reload; also recovers a nameless profile (#66)
- gui: circle-details sheet shows the three name vectors — chosen name, the relay-scoped adj-noun label, and the universal `#<12hex>` fingerprint (#36)
- gui: right-click context menu (Cut / Copy / Paste / Select all) on text fields (#67)
- gui: a custom share name set at publish now persists and is used on auto-republish (was basename-only) (#41)
- gui: the circle-details sheet is reachable — a per-circle "Details" header control opens it and "Close" dismisses it (#35)

## [0.31.1] — 2026-06-25

### Fixed

- GUI chat auto-scrolls to the newest message: a new message in the active room pins the transcript to the bottom when the reader is already at the bottom (always on your own send), and holds position when scrolled up reading history. (#84)
- GUI chat messages wrap and bubbles size to their content: a long or multi-line message wraps within a bubble capped at ~72% of the row instead of clipping to a fixed height. (#86)
- GUI chat column stays within the window: a long pasted draft or message no longer balloons the centre column off-screen (which dropped the roster and overflowed the composer). The centre column takes available width and the single-line composer scrolls its text within a fixed box. (#86)

### Changed

- GUI chat bubble colors reversed — other people's messages use the readable green bubble, your own messages use the dark bubble. (#85)

## [0.31.0] — 2026-06-24

### Added

- `daemonseed_core::heartbeat` — AES-256-GCM-sealed, ML-DSA-87-self-signed `MemberHeartbeat`, tier-split by key class (`seal_public_heartbeat` / `seal_circle_heartbeat` / `open_heartbeat`), distinct AAD `daemonseed/presence/heartbeat/v1`. (#74)
- `daemonseed_core::presence::PresenceTracker` — per-room member liveness keyed by sender pubkey, reaped after a multi-miss TTL; `next_heartbeat_interval` draws a jittered ~10–15s emit interval. (#74)
- TUI net actor emits a member heartbeat per subscribed room on the jittered timer and folds inbound beacons into a per-room presence tracker; roster surfacing deferred to #75/#77. (#74)
- `MemberHeartbeat` carries a provenance-bound `live_share_ids` digest; `ShareCatalog::reconcile_sharer` / `prune_sharer` fold it so share liveness rides the heartbeat. (#76)
- GUI net actor emits and ingests the lobby member heartbeat (mirroring the TUI), and the GUI surfaces the live Lobby roster: a persistent right-hand people column showing currently-present members by display name, with the `#12hex` fingerprint on hover and no decorators. (#75)

### Changed

- Share discovery liveness rides the heartbeat: the periodic reconcile-timer roll-call is retired — a full `ShareAnnouncement` fires only on change (publish/unpublish) plus the startup and manual-refresh roll-calls, while ongoing liveness and drop-detection ride the heartbeat digest. `PresenceTracker::reap` now returns the reaped members. (#76)
- Raise the shared application-channel `KEEPALIVE_TIMEOUT` 10s → 30s (GUI/TUI/CLI via `AppSession::open`) so a slow keepalive ack on a congested WAN no longer trips a spurious dead-connection; a genuine half-open is still detected within ~45s. (#80)

### Fixed

- GUI message send no longer breaks after a stream blip: a graceful per-stream end-of-stream on a live connection now re-subscribes just that stream and leaves the session intact, instead of tearing down the lobby + every circle + all serve tasks (the v0.30.0 regression that blocked all sends while the relay still showed connected). Only a re-subscribe that fails on a genuinely dead connection — or a flapping stream — tears down and reconnects. (#80)
- GUI no longer re-hashes published shares from scratch on every publish and connect-time auto-republish: each share gets its own persisted redb index file (`share-index-<12hex(root)>.redb` under the profile `IndexKey`) and indexes via `cached_or_hash`, so an unchanged share — including a large one at startup, and every share for a multi-share user — is cache-hits-only instead of a CPU-bound re-hash. A per-share file holds only one root's files, so one share's cache pass never evicts another's. (#81)

### Security

- Presence replay-freshness: the heartbeat ingest drops a beacon whose advisory timestamp is outside a freshness window (`presence::beacon_is_fresh`), so an untrusted relay replaying a captured beacon can pin a departed member present for at most the window rather than indefinitely. Bounds replay; the window value and a clock-free nonce alternative are open design points. (#78)

## [0.30.0] — 2026-06-23

### Added

- GUI auto-reconnect: after a dropped connection the network actor re-issues the connect on a capped exponential backoff (2s–30s), restoring the persisted display handle, circles, and shares like a fresh launch. (#71)
- h2 keepalive on the application channel (`http2_keep_alive_interval` + `keep_alive_timeout` + `keep_alive_while_idle`), so a half-open socket surfaces as an error within a bounded window. (#72)
- Circle-detail data path: a deterministic-label accessor derived from the net-contract rendezvous (adj-noun label, fingerprint fallback pre-join), a second compare vector alongside the `#<12hex>` fingerprint and independent of the chosen name. Detail-pane affordance deferred. (#36)
- `cargo xtask release-gate`: runs the full DoD gate (fmt, clippy workspace + gui/desktop, `test --workspace`, check-proto, isc-coverage) and exits non-zero on any red step, so a release tag cannot be cut on a red tree. (#62)
- Rename identity (core): `GuiState::rename_identity` sets a new display name and re-seals the at-rest blob (write-through) so it persists across unlock, and names a profile created nameless before #65; the cryptographic identity is unchanged. Command-palette UI and live-wire-handle update deferred. (#66)

### Fixed

- GUI no longer shows "connected" over a dead session: a dropped or half-open connection now surfaces `NetEvent::Disconnected` and the actor clears its stale session/circle/share state so no half-open session is reused. (#72)
- GUI opening the Public Shares tab while a circle is the active room follows the room to the Lobby, so the highlighted room matches the public context shown. (#70)
- GUI single-instance guard: a second client resolving the same profile root refuses to start (advisory PID lockfile on the resolved root, stale-lock reclaim) instead of opening the single-writer storage layer concurrently; `--portable` instances on different roots are unaffected. (#60)

### Changed

- Sync `Cargo.lock` to `oxicrypt` 0.17.0 (workspace crypto path-deps).

## [0.29.2] — 2026-06-22

Tester-facing GUI fixes plus a first-start display-name persistence fix.

### Added

- Windows build recipe (`packaging/windows/build-windows.sh`): cross-compiles a self-contained `daemonseed-gui.exe` for `x86_64-pc-windows-gnu` via cargo-zigbuild (zig static-links the mingw runtime; depends only on stock Windows 10+ DLLs).
- In-app release-version readout: a version line in the rail footer plus an About overlay (version, license, source) reachable from the command palette. (#59)
- Client-side unread dot on rail rooms: an unfocused room (circle or Lobby) shows a dot when a chat message arrives, cleared when the room gains focus. Chat-only. (#64)

### Changed

- Renamed the "Shares" tab (and its in-pane heading) to "Public Shares", distinct from "Circle shares".

### Fixed

- Command palette has a close (×) control, so it dismisses without selecting an item. (#58)
- Switching rooms while on a shares tab selects the tab matching the destination — a circle's "Circle shares", the Lobby's "Public Shares" — so public shares no longer appear available inside a circle.
- First-start re-seals the at-rest blob with the chosen display name, so a named identity keeps its name across unlock; previously the name was lost at next launch (peers saw the hash-only handle) unless a later write-through happened to re-seal. (#65)
- Right-clicking the Join phrase field pastes from the clipboard and refocuses; previously a right-click only moved focus off the field, leaving Ctrl-V as the sole paste path. (#63)

## [0.29.1] — GUI window-size default + build-version readout

Fresh-identity windows open at the intended landscape size, the running build
version is visible on the auth screens, and the ISC distribution drift-guard is
corrected to the unified-share-model registry counts.

### Added

- Build version shown on the GUI unlock and first-start screens. (#59)

### Fixed

- Fresh-identity GUI windows open at the landscape default size instead of square. (#54)
- ISC distribution drift-guard counts corrected to 97 positive / 55 negative /
  152 total, matching the unified-share-model registry additions (S30, A-S22, C77).

## [0.29.0] — Unified share model: relay-blind in-band share discovery

Shares move to fully relay-blind in-band discovery: sealed `ShareAnnouncement` /
`ShareRollCall` over the subscribe stream replace the relay share registry,
public-share content is sealed under the public room key, and the relay holds no
share directory. Plus first-start passphrase confirmation and GUI hands-on fixes.

### Added

- `ShareAnnouncement` wire message + `daemonseed-core::share_announce` seal/open
  (sealed under the public room key or a circle `cot_key`, ML-DSA self-signed;
  relay-agnostic). (#50)
- `daemonseed-core::share_seal` content sealing: `seal_public_share_frame` /
  `seal_circle_share_frame` (tier-guarded) + `open_share_frame` (generic over
  `AeadKey256`). (#49)
- `ShareRollCall` wire message + `daemonseed-core::share_rollcall` seal/open. (#52)
- `daemonseed-core::share_catalog` — client-side share discovery catalog
  (`ShareCatalog` apply / prune / remove). (#52)
- `daemonseed-core::share_announce::mint_share_id` — client-side 128-bit
  `share_id` minting. (#52)
- Desktop GUI window/taskbar icon on `AppWindow`. (#40)
- First-start backup confirmation as three single-word type-back fields (C34).
- Reproducible AppImage build recipe (`packaging/appimage/`, output to `dist/`).
- Optional wire-facing name persisted per published share
  (`PublishedShare { root, name }`). (#41)
- "Restored N shares from last session" label on the connect-time auto-republish
  path. (#34)
- First-run desktop-integration prompt + `--install` / `--remove` flags that
  register an XDG `.desktop` entry and hicolor icons.
- Desktop GUI window-size persistence across restarts (size only).
- First-start passphrase confirm re-entry — a second masked field that must match
  before sealing a new identity.

### Changed

- Key-class separation: `CotKey` → `CircleKey` and a distinct `PublicRoomKey`,
  both `AeadKey256`; non-substitutable (sealing a circle payload under a public
  key is a compile error). No wire change. (#49)
- Public-share content sealed under the public room key on the serve/fetch path
  (per-chunk SHA-384 integrity and the relay unchanged). (#52)
- TUI share publish / unpublish / refresh now run in-band — sealed
  `ShareAnnouncement` + `ShareRollCall` over the lobby, with a `ShareCatalog` and
  a reconcile timer — instead of the relay registry RPCs. (#52)
- GUI share publish / unpublish / refresh now run in-band — sealed
  `ShareAnnouncement` + `ShareRollCall` over the lobby, with a `ShareCatalog` and
  a reconcile timer — instead of the relay registry RPCs. (#53)
- Track oxicrypt 0.16.0 in the lockfile.
- Auto-republish on connect consumes the persisted per-share name
  (`PublishedShare.name`), falling back to the root basename. (#41)
- GUI trust copy: "sealed" → "encrypted".
- "Restored N shares…" shows as a tab-independent auto-dismissing banner on the
  Chat landing view. (#34)
- Desktop GUI window title is "Daemonseed".
- AppImage recipe emits a 256px PNG + top-level `.DirIcon`.
- The Shares-tab "Publish" button reads "Manage shares".
- The download-complete banner auto-dismisses after a 30s read. (#55)

### Fixed

- Circle rail/header no longer shows a stale "not yet connected" placeholder.
- Keyboard focus restored when the desktop window regains activation. (#39)
- The desktop GUI window size is remembered in the resolved profile root, so a
  `--portable` / `--config` instance keeps its own size instead of the shared XDG
  one.
- A long phrase/name in the circle-join and Publish-name fields is clipped to its
  box instead of overrunning to the window edge (the same `clip` fix the auth
  inputs already carry).
- A publisher's own shares now appear in their own Shares list, not only on other
  clients — own shares are merged into the snapshot since the relay never echoes
  an announcement back to its sender. (#53)
- The download folder picker defaults to the OS Downloads folder instead of `$HOME`.
- The chat composer regains focus when the circle-join dialog is closed (Esc or
  Close).
- The folder picker no longer hangs on a repeated publish — the pickers run on the
  app's long-lived runtime instead of a fresh per-pick one. (#33)

### Removed

- The relay share registry: the `PublishShare` / `UnpublishShare` /
  `ListPublicShares` PublicSpace RPCs, the `PublicShareListing` message, and the
  server-side `SharePublishRegistry`. (#51)
- The CLI's registry-backed `publish` / `unpublish` / `list-shares` subcommands. (#51)

## [0.28.0] — GUI auth-input hands-on fixes + global font pass (round 2)

Post-`v0.27.0` round-2 polish of the first-start / unlock auth surface, manually tested
on Ubuntu noble via an AppImage build.

- **Visible password mask + complete glyph coverage:** the software renderer now
  bundles DejaVu Sans as the default font, so the masked passphrase renders as `●`
  bullets (previously blank) and the share-tree disclosure carets render as real
  `▾`/`▶` chevrons (previously ASCII `v`/`>`). The font is vendored unmodified under
  the Bitstream Vera license.
- **First-start Enter-to-submit:** the 3-word backup type-back step submits on Enter;
  the recovery-phrase ("I've saved it") step also advances on Enter while the window
  holds focus.
- **Unlock clears on a wrong passphrase:** a failed unlock empties the field so the
  next attempt starts from a known-empty state.
- **Long-input containment:** a long or pasted entry in the single-line auth fields is
  clipped to its box instead of overrunning the window.

## [0.27.0] — GUI Shares-tab cleanup (round 1)

Post-`v0.26.0` cleanup of the GUI Shares tab and first-start flow, plus one core
refactor. Manually tested on Ubuntu noble via an AppImage build.

- **Publish-persistence:** published shares survive restart and auto-republish on
  Unlock — the share's root is written through to the at-rest seeds blob;
  explicit Unpublish forgets it, while a disconnect-reap restores it on reconnect.
- **First-start backup-verify is the C34 3-word type-back:** the C33 full-phrase
  round-trip is replaced by typing back 3 random words at cryptographically-chosen
  positions, with a non-consuming pre-check (a typo never destroys the sealed
  enrollment) and a fresh challenge per failed attempt. ISC-C47 amended to make C34
  the sole skip-backup confirmation.
- **Resizable window:** the GUI is no longer fixed at 1100×680 — it reflows to a
  720×480 floor so the shell and auth overlays no longer clip.
- **First-start focus:** auth fields focus on step entry and on error paths
  (confirm-mismatch, empty-name, save-failure), not just the initial screen.
- **Refactor:** the `human_bytes` display helper is consolidated into
  `daemonseed-core::format`; the TUI and GUI both delegate to it.

## [0.26.0] — GUI Shares tab: public-share browse, download & publish

The GUI gains the full public-share loop, matching the TUI's M16 surface.

- **Browse:** the Shares tab is an OS-style lazy-expand tree of the relay's public
  shares; each share previews its file manifest on first expand, with a manual
  Refresh and a ~3s comparative-real-time poll while the tab is open.
- **Download:** right-click any node (file / folder / whole share) → native folder
  picker → SHA-384-verified fetch to the chosen directory, with a rail-footer meter.
- **Publish:** a Publish overlay — choose a folder (optional name) → publish and serve
  it from disk for the session; a live-shares list with one-click Unpublish; your own
  shares are tagged "you" in the tree.
- **Fixes from the manual test:** enter a tokio runtime on the main thread so Slint's
  winit xdg-settings watcher (zbus, forced onto tokio by rfd→ashpd) no longer panics
  at startup; the Publish overlay stays open and reports its outcome; a guard refuses
  to publish the home / system directories; auth fields re-focus after a failed unlock.

## [0.25.0] — GUI persistent identity: first-start + Unlock + silent circle rejoin

The GUI gains an identity that survives a relaunch — the blocker to a multi-session
tester manual test.

- **First-start wizard:** passphrase (strength-gated) → 24-word recovery phrase →
  streamlined round-trip confirm → display name. Reuses the core `FirstStart` state
  machine and writes a sealed profile; no new crypto.
- **Daily-login Unlock:** opens the at-rest blob under the passphrase (wrong → "Wrong
  passphrase"), restores the stable display handle, and **silently re-joins** the
  circles recorded in the blob.
- **What persists:** the display name + circle *phrases* (the key is re-derived on
  rejoin, never stored). No message history is written — the no-client-history
  property holds. The connection proof stays ephemeral every connect (mirrors the
  TUI); persistence is a stable *display* identity, not a persisted connection key.
- **Crash fix carried in:** auth screens toggle with `visible:` (never `if`), so a
  screen change hides rather than destroys the focused field — avoiding a
  `partial_renderer` "RefCell already borrowed" teardown race.

## [0.24.0] — GUI affordances: persistent New/Join, command palette, edit-crash fix

Keyboard-first and discoverability polish on the GUI alpha, plus a crash fix.

- **Persistent New/Join entry:** the rail shows a "+ New circle / Join" entry
  whenever circles exist (the New/Join buttons previously vanished once you had a
  circle, leaving only the palette), so adding another circle is always one click.
- **Command palette + shortcuts:** Ctrl-K toggles the palette and Escape closes
  it; Ctrl+L (Lobby), Ctrl+N (New circle), Ctrl+J (Join) are bound directly.
  Overlays are mutually exclusive (no stacking); shortcut labels brightened. Global
  shortcuts are intentionally inert while a popup's text field has focus (text-entry
  mode); Escape / Enter / Close exit it.
- **Crash fix:** editing a circle phrase could crash the renderer ("RefCell already
  borrowed") because the status indicators toggled item-tree `if` conditionals
  mid-edit. They are now stable computed elements — editing changes only properties.

## [0.23.0] — GUI circle chat: circles talk on the relay

The circles created and joined in v0.22.0 now chat end-to-end-sealed over the
relay, completing the GUI alpha's core loop (public Lobby + circles).

- **Circle chat:** joining or creating a circle subscribes it to the relay;
  messages are sealed under the circle key and delivered to the other members.
  Each circle is independent (its own key and inbound reader); the public Lobby
  path is unchanged. Verified by an in-process round-trip and a live relay
  round-trip, then a two-client manual test.
- **Phrase-sharing affordances:** the new-circle phrase is editable and
  copyable (Copy to the clipboard, with a confirmation); the join field accepts
  the pasted phrase and auto-focuses. (Out-of-band phrase sharing is the alpha's
  tester crutch; an in-app DM is the production path, a later milestone.)

## [0.22.0] — GUI circle plumbing: join, create, and materialize circles

The second desktop GUI milestone — the circle rail becomes live. Circles are
created and joined from the UI and materialize into the rail. They do not yet
chat over the network; the circle network path is the next milestone.

- **Join a circle:** a phrase-entry overlay with a co-equal QR slot (reserved),
  a quiet "looks strong" reassurance (no numeric meter), and a pre-commit
  confirmation card. The join is gated on the ≥128-bit circle-entropy floor — a
  weak phrase is blocked and kept so it can be strengthened in place.
- **New circle:** a one-tap generated diceware phrase (copy / show-QR reserved /
  re-roll), founderless — the creator is simply the first member. Generation is
  rejection-sampled so the phrase always clears the same floor the join gate
  applies.
- **Materialization:** a joined or created circle is added to the rail at
  runtime and carries its derived circle-of-trust key and a rendezvous slot,
  ready for the circle network path. The client seeds with the Lobby only and
  shows an empty-state until the first circle exists.
- **Composer:** sending in a materialized circle is locally echoed for now (the
  circle network path is the next milestone); the public Lobby keeps sending
  real sealed messages. Switching circles autofocuses the composer.

## [0.21.0] — GUI foundation: interactive Slint shell + real public-Lobby chat

The first desktop GUI milestone — the `gui-alpha` foundation work, taken from a
static shell to real networked chat.

- **`daemonseed-gui` crate (Slint, software-renderer):** the three-zone shell —
  circle rail, conversation pane, tab nav (Chat / Shares / a "coming soon"
  circle-shares placeholder), command palette — with a `desktop` feature for a
  real window and an offscreen `--screenshot` mode for headless verification.
- **Interactive shell:** click-to-switch rail over a per-circle RAM state layer
  that retains each circle's draft and scroll position across switches; a real
  text composer and a scrollable transcript.
- **Real public-Lobby chat:** a net actor (dedicated-thread tokio runtime, live
  application session, ephemeral identity, mirroring the TUI) connects to the
  relay, auto-joins the default public room, and sends/receives real AEAD-sealed
  messages; the UI thread never blocks. Verified by a two-client live manual test
  on the relay.
- **`--x11` / `DAEMONSEED_X11=1` launch opt-in:** forces XWayland for testers on
  Wayland-in-a-VM (winit's Wayland pointer path drops clicks under VM software
  rendering); native Wayland stays the default.

Scope: the public Lobby only — circle chat (phrase entry), real shares fetch,
and persistent identity / first-start are subsequent milestones.

## [0.20.0] — M16, finished public share path

Completes the public share path as the reference implementation, plus the
post-smoke fixes from live two-daemon testing on the relay.

- **Fetch UX:** pre-fetch manifest preview, selective fetch, a collapsible
  folder tree, and a choosable download destination on the preview; multi-share
  publish from the Shares pane; the public-room sender is bound to its
  provenance pubkey (ISC-C57).
- **Serve-from-disk + 1 MiB sub-file chunking:** publish and serve a share of
  arbitrary size without loading it into memory — every wire frame stays
  relay-safe under the relay's 4 MB decode cap, transient serve RAM is one
  chunk per request, and a too-large manifest is refused at publish rather than
  stalling silently.
- **Chosen-destination download layout:** files land rebased to the selection
  root — a single selected file as its basename, a selected folder as
  `<dest>/<folder>/…` — and a leading `~` in the destination expands to `$HOME`.
- **No re-hash on relaunch:** the share index is reconciled (not cleared) when a
  remembered root re-indexes on unlock, so re-publishing an unchanged share
  reuses its cached chunk addresses instead of re-hashing every file.
- **Publish persistence:** a published share is remembered and auto-republishes
  on the next unlock once reconnected. The relay stays RAM-only and reaps on
  disconnect (ISC-S20), so each republish is a fresh, unlinkable share id.
- **Manifest-wait timeout:** fetching a share whose sharer is offline now errors
  cleanly instead of hanging until cancelled.

## [0.19.0] — M15, close the TUI gap

Brings the TUI to parity with the CLI for the full share loop, plus honest
coverage tooling.

- **Circle-entropy gate (ISC-C9):** a real ≥128-bit key-space estimator
  (`passphrase::strength::estimate_circle` — distinct BIP-39 words + a charset
  residue, with a zxcvbn low-end veto) driving a bits-driven join meter,
  replacing the M14 interim proxy.
- **Share publishing from the TUI:** publish / serve / unpublish a share via
  `[p]` / `[u]` on a defined share (define once, then publish — no separate
  Publish pane). Serving is session-scoped; the relay reaps on disconnect
  (ISC-S20).
- **Downloads:** a fetched share lands as named files in a per-share folder
  under a downloads root (`<profile>/downloads` in `--portable`, else the OS
  Downloads directory). Path-traversal-safe; nothing is written until the whole
  fetch verifies (ISC-C63/C64/C65, ISC-A-C31/A-C32).
- **Identity in chat + listings:** public-room posts and share listings carry
  the sender's display handle, so peers see the name rather than the `#hash`
  floor / "(operator)". The share-fetch overlay shows a progress gauge.
- **Coverage tooling:** the ISC registry `TOTAL` / `COVERED` are single-sourced
  in a new zero-dependency `daemonseed-isc` leaf crate read by both the
  integration tests and `xtask isc-coverage`; reconciled to the built ISA
  criteria (`TOTAL` 122 → 133, honest 100/133).

## [0.18.0] — M14, share-management surface + persistence

The TUI gains a **Define-Share** input box: type a local directory (`path` or
`path|label`) and the net actor opens the redb share index and cold-scans it on a
dedicated background thread — the command loop never blocks and the index stays
queryable during the scan (redb MVCC, ISC-A-C7). Defined roots **persist** in the
at-rest blob as a `share` directive (ISC-C21) and **re-index automatically** on the
next daily-login Unlock, mirroring circle rejoin. The share-index key is derived as
a **sibling of the at-rest key from a single Argon2id run** (domain-separated
HKDF-Expand, ISC-C3 / A-C6); the at-rest key output is byte-identical to before, so
existing blobs open unchanged. Also folds in the M13 deferrals: a circle-join
**entropy meter** with the ISC-C9 join gate, and a relay-independent **circle
fingerprint** (coded, not yet surfaced). Publishing remains operator/CLI-side; the
TUI is fetch + local-index only. No wire change.

## [0.17.0] — M13, persistence keystone

The at-rest seeds blob now persists display name, mute list, hidden-shares, and
circle membership (ISC-C51 / C15 / C16 / C59), restored on a daily-login Unlock;
circles silently rejoin without re-typing the phrase. A cached `SealingKey`
(`daemonseed_core::storage::seeds`) re-seals the blob on each mutation with no
second Argon2id (the Pi-4 floor); circle entropy + label are stored as hex
directive lines and stay non-mnemonic-derivable, so a mnemonic-only recovery
never reconstructs the social graph. This persists configuration, not history —
the no-client-history property is intact. No wire change.

## [0.16.0] — multi-circle carousel

Simultaneous membership in N circles (joining ADDS, never evicts), a split chat
view (lobby pane + active-circle carousel pane), arrow-key cycling of the active
circle, deterministic client-local labels, and per-circle surface isolation +
attribution (ISC-C59–C62 / A-C29 / A-C30). Purely client-side, no wire change.

## [0.15.1] — chat-surface precedence fix

Posts route to the joined circle rather than the auto-joined lobby, plus a
compose-box surface indicator. Client-only.

## [0.15.0] — alpha2 batch

Opaque server-assigned `share_id` (S21 / A-S15); share download
(S27–S29 / A-S20–A-S21); interactive public rooms — the auto-joined lobby
(S22–S26 / A-S16–A-S19 / C56–C58); client-identity lifecycle — first-start
persists the seeds blob + config + `.dseed`, daily-login Unlock, no-clobber of an
existing identity (C47–C51 / A-C26–A-C28); `--portable` mode forcing the CWD as
profile root (C52).

## [0.14.0] — M12, alpha1 MVP

The last two MVP-gate steps under one additive SemVer MINOR wire bump.
**Step 5** — user-publish file sharing: `PublishShare` / `UnpublishShare` /
`ListPublicShares` over the PublicSpace service; a RAM-only per-connection
registry (`SharePublishRegistry`), `publish` holds the connection open until
Ctrl-C, and `ShareReapGuard` reaps the share on real disconnect
(ISC-A-S1 / A-S5b / S4). **Step 6** — the federation introducer endpoint
(`FederationIntroducer` gRPC over the already-shipped
`IntroducerQuery`/`IntroducerResponse`) + the TUI Servers-pane refresh rendering
introducer-discovered candidates read-only, no keys, never auto-trusted
(ISC-S6 / S13 / C22 / A-C19). The full 4-daemon gate trips 10/10 → **MVP declared**.

## [0.13.0] — M11, MVP-gate client surfaces

The real interactive ratatui TUI driving the full transaction, M9 surface
wiring, public-space (MOTD + announcements) view, suite-deprecation policy
surfacing (fetch + ML-DSA verify + anti-rollback), and clean-device recovery
from a 24-word mnemonic / `.dseed` file — all over already-shipped, already-served
server APIs (no new wire protocol). Trips gate steps 3/7/8.

## [0.12.1] — M10-completion

Scaffolds the two platform-gated M10 ISCs as abstraction-only: C7
biometric/secure-enclave session-passphrase unlock and C20 OS-native autostart
(traits + opt-in `ProfileConfig` flags, default off; platform halves reserved to
M10-infra). Also brings every LAMA manifest (root + per-crate) to canonical
LAMA 0.1.

## [0.12.0] — M10-core, verifiable core

Release trust anchor + N-of-M ML-DSA-87 multi-sig verify
(`daemonseed_core::release`), the server boot-gate that refuses to boot on failed
verify (no boot-with-warning path), and the client update-lifecycle FSM
(verify-before-apply / never-auto-install / no-silent-downgrade /
wipe-and-log-on-failure). Plus the M9 per-key rate-limit RAII drop-guard and the
ISC-S20 coverage backfill. Closes S18 / A-S13 / C27 / A-C11.

## [0.11.0] — M9, abuse-resilience + chat affordances

Server: multi-granularity RAM-only rate limits (per-connection token bucket +
subscription/verify caps), per-identity-key connection table GC'd on disconnect,
uniform silent close (S17 / A-S12). Client: exponential+jitter reconnect backoff
with an 8-retry budget (C26); mute + hide-shares persisted in the seeds blob,
never leaked (C15 / C16 / A-C3); @-mention recognition + resolution as pure
functions with no new server-visible distinction (C17 / C18 / A-C4).

## [0.10.0] — M8, circle-of-trust relay + indexer

Circle-of-trust live relay (refcounted bidi Subscribe, reap-at-zero), flat
metadata-free circle key derivation, per-relay rendezvous addressing, a
content-addressed chunk store, and the encrypted incremental redb share indexer
with Pi-civility background scanning. Added ISC-S20.

## [0.9.0] — M7, suite deprecation + trust-event taxonomy

Suite deprecation policy (operator-signed, replay-protected cutoffs) + the
trust-event taxonomy (four affordance classes, closed `TrustEventKey` enum,
bounded encrypted audit log).

## [0.8.0] — M6, public space

The first post-Authenticated application service (PublicSpace gRPC). Verify-and-
serve signed announcement posts (S7) + MOTD (S9) against an operator signer
whitelist (S8) with a non-removable project-release entry; operator rating
taxonomy published, never enforced (S10 / A-S5b); public-share listing surface
(S4); client rating selection + filter plumbing (C19 / A-C5); AGPL-§13 source URL
advertised in the handshake ack; server filesystem isolation (A-S8). Closes 12
ISCs (55→67).

## [0.7.0] — M5, federation

Per-server trusted/untrusted trust slider with TOFU pinning + rotation notices
(C22), introducer responses that never carry public keys (S6), server-to-server
peering reusing the same slider (S12) with introduce-to-clients suppression (S13)
and active-attacker-resistant don't-introduce (A-S7), reference-client connection
cap (A-C10).

## [0.6.0] — M4b, identity-proof handshake

Post-HELLO identity-proof: mutual ML-DSA-87 envelopes bound to the TLS exporter
channel binding, ±5 min freshness + per-key replay counters, Versioned →
Authenticated type-state gate, uniform close on failure. Closes S19 / A-S14 /
A-C18 / A-S12 / A-S1.

## [0.5.0] — M4a, relay daemon

Server skeleton + TLS 1.3 on :443 with ALPN h2 + APP_HELLO + type-state
`Connection<Negotiating → Versioned>`; CLI connect initiator.

## [0.4.0] — M3, crypto-suite registry

Suite registry (CNSA 2.0 baseline), `suite_id` wire-tagging on at-rest artifacts,
read-old-write-new migration on touch, circle-metadata `min_suite_id` slot.

## [0.3.0] — M2, first-start + recovery

First-start type-state orchestrator, encrypted recovery file (`.dseed`),
bootstrap-anchor selection (canonical / manual-paste).

## [0.2.0] — M1, identity primitives

BIP-39 mnemonic, HKDF-derived ML-DSA-87 / ML-KEM-1024 keypairs, profile
substrate, at-rest seeds blob, handle format (adj-noun + 12-hex fingerprint).

## [0.1.0] — M0, scaffold

Pre-implementation findings, workspace scaffolding, proto-codegen pipeline.
