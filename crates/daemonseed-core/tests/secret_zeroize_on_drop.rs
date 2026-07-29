//! Behavioural proof that both arms of `redacted_secret_newtype!` clear a
//! secret's bytes before that memory is handed back to the allocator (#242).
//!
//! The obvious test is unsound. A `boxed`-arm secret lives in the `Box`'s own
//! allocation, and by the time the wrapper's `Drop` has run that allocation is
//! already freed — so recording the address, dropping, and reading it back is a
//! use-after-free, and worse, it is the kind that passes for years while proving
//! nothing: a just-freed block usually still holds its old bytes whether or not
//! anything wiped them.
//!
//! So the observation is taken at the only moment that is both *after* the wipe
//! and *before* the memory stops being ours: inside `GlobalAlloc::dealloc`. At
//! that point the allocator has been handed a still-valid pointer and its exact
//! layout, and reading it is ordinary, sound memory access. This file installs a
//! pass-through allocator that snapshots one watched block on its way out.
//!
//! The `inline` arm holds its secret in the value rather than behind a pointer,
//! so it is reached by the same witness through a `Box` — which puts the inline
//! array inside a heap block the allocator sees. Observing it directly, in
//! storage the test allocates and keeps, would need raw pointers, and
//! `daemonseed-core` is `#![forbid(unsafe_code)]`; that is also why this file is
//! an integration test rather than a unit test. Being its own binary has a
//! second benefit: the allocator hook applies only here, never to the crate's
//! ~970 unit tests.
//!
//! What these tests prove: at the instant a secret's storage is released, it
//! holds zeros rather than key material. What they do not prove: anything about
//! copies made before the drop, or about registers and stack spills the
//! optimiser may hold — no test in safe Rust can reach those. The companion
//! bound assertion in `secret_seed.rs` covers breadth, this covers depth.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use daemonseed_core::circle::key::{
    derive_circle_presence_veilid_owner_seed, derive_circle_veilid_owner_seed,
};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::dm::ratchet::EphemeralDecapKey;
use daemonseed_core::identity::keys::{Identity, derive_identity_keys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::public_room::derive_room_veilid_owner_seed;
use oxicrypt_ml_kem::DK_LEN;
use zeroize::Zeroizing;

/// Large enough for the biggest secret watched here, the ML-KEM decapsulation
/// key behind `EphemeralDecapKey`.
const SNAPSHOT_CAP: usize = 4096;

/// Address of the block being watched, or 0 when disarmed. A live allocation is
/// never at address 0, so 0 is an unambiguous "off".
static WATCH_ADDR: AtomicUsize = AtomicUsize::new(0);
/// How many bytes of the watched block to snapshot.
static WATCH_LEN: AtomicUsize = AtomicUsize::new(0);
/// How many bytes the snapshot actually holds. The reader uses this rather than
/// its own length, so a short capture reads short instead of running on into
/// whatever the previous test left in the buffer.
static CAPTURED_LEN: AtomicUsize = AtomicUsize::new(0);
/// Set once the watched block has actually been freed and snapshotted.
static CAPTURED: AtomicBool = AtomicBool::new(false);
/// The bytes the watched block held at the moment it was freed.
static SNAPSHOT: [AtomicU8; SNAPSHOT_CAP] = [const { AtomicU8::new(0) }; SNAPSHOT_CAP];
/// The watch is one global slot, so the tests take turns.
static GATE: Mutex<()> = Mutex::new(());

/// A pass-through allocator that copies one watched block's contents out on the
/// way to `System::dealloc`.
struct FreeWitness;

// SAFETY: every method forwards to `System` with the pointer and layout it was
// given, unchanged. The only added work is reading bytes from a block the
// allocator has just been handed — still mapped, still ours, and the read range
// lies inside the secret's own fully-initialized storage, which is what makes it
// a read of initialized memory rather than a read of `u8`'s permissiveness.
// Nothing on this path allocates, so there is no re-entry into the allocator.
unsafe impl GlobalAlloc for FreeWitness {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Forwarded rather than left to the default alloc-copy-dealloc, so this
        // binary keeps the system allocator's in-place growth. Nothing watched is
        // ever reallocated: every secret here is a fixed-size array.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCH_ADDR.load(Ordering::SeqCst) == ptr as usize {
            // Disarm before snapshotting: once this block is back with the
            // allocator its address can be handed out again, and a later free of
            // the reused block must not overwrite what we saw.
            WATCH_ADDR.store(0, Ordering::SeqCst);

            let len = WATCH_LEN
                .load(Ordering::SeqCst)
                .min(layout.size())
                .min(SNAPSHOT_CAP);
            for (i, slot) in SNAPSHOT.iter().enumerate().take(len) {
                // SAFETY: `i < len <= layout.size()`, so this stays inside the
                // block the allocator is being asked to free.
                slot.store(unsafe { *ptr.add(i) }, Ordering::SeqCst);
            }
            CAPTURED_LEN.store(len, Ordering::SeqCst);
            CAPTURED.store(true, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: FreeWitness = FreeWitness;

/// Build a secret, watch the block its bytes live in, drop it, and require that
/// the block was all zeros when the allocator got it back.
///
/// `locate` points at the secret's bytes *through the public accessor*, so the
/// watched block is the one the type actually stores its key material in.
fn assert_zeroed_when_freed<T>(name: &str, make: impl FnOnce() -> T, locate: impl Fn(&T) -> &[u8]) {
    let _gate = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    // Disarm first. Clearing `CAPTURED` while the watch is still live would let a
    // free landing in between leave it stale-true, which is the one state that
    // disables the "was it ever freed" control below.
    WATCH_ADDR.store(0, Ordering::SeqCst);
    CAPTURED.store(false, Ordering::SeqCst);
    CAPTURED_LEN.store(0, Ordering::SeqCst);

    let secret = make();
    // A copy of the secret, so it can be compared against what the allocator saw.
    // It is a duplicate of live key material, so it zeroizes on its own drop —
    // this test has no business leaking what it exists to prove gets wiped.
    let (addr, len, before) = {
        let bytes = locate(&secret);
        (
            bytes.as_ptr() as usize,
            bytes.len(),
            Zeroizing::new(bytes.to_vec()),
        )
    };

    assert!(
        len <= SNAPSHOT_CAP,
        "{name}: {len}-byte secret exceeds the {SNAPSHOT_CAP}-byte snapshot buffer"
    );
    // Control. Without it a type that never held a secret, or an accessor
    // pointing somewhere else, would sail through the zero assertion below.
    assert!(
        before.iter().any(|&b| b != 0),
        "{name}: the secret is all-zero before the drop, so this test proves nothing"
    );

    WATCH_LEN.store(len, Ordering::SeqCst);
    WATCH_ADDR.store(addr, Ordering::SeqCst);

    drop(secret);

    // Second control. If the block were never freed — a leak, or the accessor
    // pointing into some other allocation — the snapshot would still read as the
    // zeros it was initialised with, and the test would pass vacuously.
    assert!(
        CAPTURED.load(Ordering::SeqCst),
        "{name}: the watched block was never freed, so nothing was observed"
    );
    assert_eq!(
        CAPTURED_LEN.load(Ordering::SeqCst),
        len,
        "{name}: the snapshot is shorter than the secret, so part of it went unchecked"
    );

    let seen = Zeroizing::new(
        SNAPSHOT
            .iter()
            .take(len)
            .map(|b| b.load(Ordering::SeqCst))
            .collect::<Vec<u8>>(),
    );

    assert!(
        seen.iter().all(|&b| b == 0),
        "{name}: freed memory still held key material: {seen:02x?}"
    );
}

fn init() {
    let _ = oxicrypt_module::initialize();
}

/// The boxed arm, across three modules that use it, clears its heap buffer
/// before releasing it.
///
/// Four of the eleven boxed types, chosen for being cheap to construct from
/// outside the crate and for spanning both secret sizes the arm is used at. The
/// property under test is the macro arm's, not each type's — every one of the
/// eleven is the same expansion — and the remaining seven are held to it by the
/// compile-time bound in `secret_seed.rs`.
#[test]
fn boxed_arm_secrets_are_zeroed_before_their_memory_is_released() {
    init();

    assert_zeroed_when_freed(
        "CircleVeilidOwnerSeed",
        || derive_circle_veilid_owner_seed("correct horse battery staple", &CNSA_2_0).unwrap(),
        |s| s.as_bytes().as_slice(),
    );

    assert_zeroed_when_freed(
        "CirclePresenceVeilidOwnerSeed",
        || {
            derive_circle_presence_veilid_owner_seed("correct horse battery staple", &CNSA_2_0)
                .unwrap()
        },
        |s| s.as_bytes().as_slice(),
    );

    assert_zeroed_when_freed(
        "RoomVeilidOwnerSeed",
        || derive_room_veilid_owner_seed("general", &CNSA_2_0).unwrap(),
        |s| s.as_bytes().as_slice(),
    );

    // The DM ratchet's own boxed secret, and the only watched block that is not
    // 32 bytes — a `[u8; DK_LEN]` at 3168. It takes its bytes directly rather
    // than deriving them, which is the point: the wipe is the newtype's, not the
    // derivation's.
    assert_zeroed_when_freed(
        "EphemeralDecapKey",
        || EphemeralDecapKey::new(Box::new([0xA5u8; DK_LEN])),
        |s| s.as_bytes().as_slice(),
    );
}

/// The inline arm keeps its secret in the value itself, so it is observed by
/// moving a real identity-rooted secret into a `Box`: that puts the inline
/// `[u8; 32]` inside a heap block the witness can watch. The wrapper's `Drop`
/// wipes the array in place, and only then is the block released.
///
/// All three identity-rooted secrets come from one derivation, so this covers
/// the whole inline family that has a public constructor. The inline ratchet
/// keys (`RootKey`, `ChainKey`, `MessageKey`) are built only inside their own
/// module and are reachable here only by the compile-time bound in
/// `secret_seed.rs`; they share this exact macro arm, so the arm-level property
/// proved here is the one they rely on.
#[test]
fn inline_arm_secrets_are_zeroed_before_their_memory_is_released() {
    init();

    let mnemonic = Mnemonic::generate().unwrap();
    let keys = derive_identity_keys(&mnemonic, Identity::Primary).unwrap();

    assert_zeroed_when_freed(
        "VeilidNodeSeed",
        || Box::new(keys.veilid_node_seed),
        |s| s.as_bytes().as_slice(),
    );
    assert_zeroed_when_freed(
        "ShareRootIkm",
        || Box::new(keys.share_root_ikm),
        |s| s.as_bytes().as_slice(),
    );
    assert_zeroed_when_freed(
        "DmDoorbellSlotSecret",
        || Box::new(keys.dm_doorbell_slot_secret),
        |s| s.as_bytes().as_slice(),
    );
}
