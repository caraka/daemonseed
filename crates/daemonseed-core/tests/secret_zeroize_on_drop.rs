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
//! The witness also covers the two secrets the macro does not generate a wipe for:
//! `PersistedCircle::entropy`, a `Zeroizing<String>` cleared before its buffer is
//! released, and `VerifiedFirstContact::ss0`, a bare `[u8; SS0_LEN]` wiped by a
//! hand-written `Drop`. Neither is reachable from the compile-time `ZeroizeOnDrop`
//! bound in `secret_seed.rs` — they are multi-field structs, not macro-generated
//! newtypes — so this file is the only thing holding them to the property at all.
//!
//! `ss0` is what made the watch a *range inside* a block rather than a whole block:
//! it sits at a non-zero offset in a larger struct, so the witness fires on any
//! freed block that wholly contains the watched range and snapshots from the
//! watched address rather than from the block start. Because containment matching
//! asserts nothing about *which* block fired, every case additionally states the
//! `(offset, block_size)` it expects and the harness pins both — that pair is what
//! replaced the structural guarantee exact-block-start matching used to give for
//! free.
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
use daemonseed_core::dm::firstcontact::{ChannelRoots, ROOT_LEN, SS0_LEN, VerifiedFirstContact};
use daemonseed_core::dm::ratchet::EphemeralDecapKey;
use daemonseed_core::identity::keys::{Identity, derive_identity_keys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::public_room::derive_room_veilid_owner_seed;
use daemonseed_core::storage::seeds::PersistedCircle;
use oxicrypt_ml_dsa::PK_LEN;
use oxicrypt_ml_kem::{DK_LEN, EK_LEN};
use zeroize::Zeroizing;

/// Large enough for the biggest secret watched here, the ML-KEM decapsulation
/// key behind `EphemeralDecapKey`.
const SNAPSHOT_CAP: usize = 4096;

/// The size every 32-byte secret newtype watched here occupies — the block size
/// each such case expects the allocator to hand back.
const SEED_LEN: usize = 32;

/// Length and capacity of the circle phrase the `PersistedCircle` case builds.
/// They differ on purpose: production entropy is parsed out of a decrypted
/// plaintext and can carry slack, so the watched buffer carries slack too rather
/// than being the exact-fit buffer `to_owned()` would give.
const CIRCLE_PHRASE_LEN: usize = 57;
const CIRCLE_PHRASE_CAP: usize = 96;

/// Address of the watched bytes, or 0 when disarmed. A live allocation is never
/// at address 0, so 0 is an unambiguous "off". This is the start of the secret,
/// which may be a block start or an offset inside a larger block.
static WATCH_ADDR: AtomicUsize = AtomicUsize::new(0);
/// How many bytes from [`WATCH_ADDR`] to snapshot.
static WATCH_LEN: AtomicUsize = AtomicUsize::new(0);
/// Where the watched range sat inside the freed block, and how big that block
/// was. These are the structural half of the assertion: containment matching
/// alone says nothing about *which* block fired or *where* in it the accessor
/// pointed, so each case pins both and a mislocated watch fails loudly instead of
/// finding some other block that happens to contain the address.
static CAPTURED_OFFSET: AtomicUsize = AtomicUsize::new(0);
static CAPTURED_BLOCK: AtomicUsize = AtomicUsize::new(0);
/// Set once the watched block has actually been freed and snapshotted.
static CAPTURED: AtomicBool = AtomicBool::new(false);
/// Set when a watched range was carried through `realloc`. The watch is disarmed
/// there, so nothing is ever captured afterwards; this records *why*, so the
/// missing capture is not misread as a leak or a wrong accessor.
static REALLOCATED: AtomicBool = AtomicBool::new(false);
/// The bytes the watched block held at the moment it was freed.
static SNAPSHOT: [AtomicU8; SNAPSHOT_CAP] = [const { AtomicU8::new(0) }; SNAPSHOT_CAP];
/// The watch is one global slot, so the tests take turns.
static GATE: Mutex<()> = Mutex::new(());

/// A pass-through allocator that copies one watched byte range's contents out on
/// the way to `System::dealloc`.
struct FreeWitness;

/// Offset of the armed watch inside `[block, block + size)`, or `None` when the
/// watch is disarmed or its range does not lie wholly inside that block.
///
/// The watch is a byte *range*, not a block start, because an `inline` secret can
/// be a field at a non-zero offset inside a larger allocation. Whole-range
/// containment is both the "is this the secret's block" test and the bounds proof
/// for every `ptr.add(offset + i)` read: `watched >= block` makes `offset` the true
/// difference, and the two length comparisons cannot underflow given it.
fn watch_offset_in(block: usize, size: usize) -> Option<usize> {
    let watched = WATCH_ADDR.load(Ordering::SeqCst);
    let want = WATCH_LEN.load(Ordering::SeqCst);
    let offset = watched.wrapping_sub(block);
    (watched != 0 && watched >= block && offset <= size && want <= size - offset).then_some(offset)
}

// SAFETY: every method forwards to `System` with the pointer and layout it was
// given, unchanged. The only added work is reading bytes from a block the
// allocator has just been handed — still mapped, still ours. The read starts at
// the watched address rather than at the block start, so it may sit at an
// interior offset of a larger allocation; `dealloc` captures only when
// `watch_offset_in` says the whole watched range lies inside
// `[ptr, ptr + layout.size())`, which is what keeps every `ptr.add(offset + i)` in
// bounds. That range is the secret's own fully-initialized storage, which is what
// makes it a read of initialized memory rather than a read of `u8`'s
// permissiveness. Nothing on this path allocates, so there is no re-entry into the
// allocator.
unsafe impl GlobalAlloc for FreeWitness {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Forwarded rather than left to the default alloc-copy-dealloc, so this
        // binary keeps the system allocator's in-place growth.
        //
        // A watched range CAN be reallocated: `PersistedCircle::entropy` is a
        // `String`, not a fixed-size array. When it happens the old block may be
        // released here without ever reaching `dealloc`, so an armed watch would be
        // left pointing at memory that is no longer the secret's — and under
        // containment matching any larger block later handed out at that address
        // would satisfy it on ITS free, which is a false pass. So disarm, and
        // record that a realloc is why nothing was captured.
        if watch_offset_in(ptr as usize, layout.size()).is_some() {
            WATCH_ADDR.store(0, Ordering::SeqCst);
            REALLOCATED.store(true, Ordering::SeqCst);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(offset) = watch_offset_in(ptr as usize, layout.size()) {
            // Disarm before snapshotting: once this block is back with the
            // allocator its address can be handed out again, and a later free of
            // the reused block must not overwrite what we saw.
            WATCH_ADDR.store(0, Ordering::SeqCst);

            let len = WATCH_LEN.load(Ordering::SeqCst).min(SNAPSHOT_CAP);
            for (i, slot) in SNAPSHOT.iter().enumerate().take(len) {
                // SAFETY: `offset + i < offset + len <= layout.size()`, so this
                // stays inside the block the allocator is being asked to free.
                slot.store(unsafe { *ptr.add(offset + i) }, Ordering::SeqCst);
            }
            CAPTURED_OFFSET.store(offset, Ordering::SeqCst);
            CAPTURED_BLOCK.store(layout.size(), Ordering::SeqCst);
            CAPTURED.store(true, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: FreeWitness = FreeWitness;

/// Build a secret, watch the bytes it stores its key material in, drop it, and
/// require that those bytes were all zeros when the allocator got their block
/// back.
///
/// `locate` points at the secret's bytes *through the public accessor*, so the
/// watched range is the one the type actually stores its key material in. It may
/// be a whole heap block or a field inside a larger one; the witness accepts
/// either.
///
/// `expect` is `(offset, block_size)`: where the located bytes must sit inside the
/// block that gets freed, and how big that block must be. This is the structural
/// control. Containment matching by itself asserts nothing about *which* block
/// fired — an accessor that silently began returning an interior pointer, or a
/// pointer into a different allocation that happens to enclose the range, would
/// pass — so every case states its own layout and a mislocated watch fails on the
/// offset rather than on the bytes.
fn assert_zeroed_when_freed<T>(
    name: &str,
    expect: (usize, usize),
    make: impl FnOnce() -> T,
    locate: impl Fn(&T) -> &[u8],
) {
    let _gate = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    // Disarm first. Clearing `CAPTURED` while the watch is still live would let a
    // free landing in between leave it stale-true, which is the one state that
    // disables the "was it ever freed" control below.
    WATCH_ADDR.store(0, Ordering::SeqCst);
    CAPTURED.store(false, Ordering::SeqCst);
    REALLOCATED.store(false, Ordering::SeqCst);
    CAPTURED_OFFSET.store(0, Ordering::SeqCst);
    CAPTURED_BLOCK.store(0, Ordering::SeqCst);

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

    // Second control. If no block enclosing the watched range were ever freed — a
    // leak, or the accessor pointing into some other allocation — the snapshot
    // would still read as the zeros it was initialised with, and the test would
    // pass vacuously.
    assert!(
        !REALLOCATED.load(Ordering::SeqCst),
        "{name}: the watched buffer was reallocated, which disarms the watch — \
         nothing was observed, and this case cannot conclude anything"
    );
    assert!(
        CAPTURED.load(Ordering::SeqCst),
        "{name}: no freed block ever wholly contained the watched bytes, so nothing \
         was observed"
    );

    // Third control, and the structural one: the block that fired is the one this
    // case says holds the secret, at the offset it says. Without it, containment
    // matching would accept any enclosing block at any offset.
    let (want_offset, want_block) = expect;
    assert_eq!(
        CAPTURED_OFFSET.load(Ordering::SeqCst),
        want_offset,
        "{name}: the secret was freed at a different offset than this case expects, \
         so the accessor is not pointing where it says"
    );
    assert_eq!(
        CAPTURED_BLOCK.load(Ordering::SeqCst),
        want_block,
        "{name}: the freed block is not the size this case expects, so it is not the \
         allocation the secret was supposed to live in"
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

    // A `boxed` secret owns its whole heap block, so the accessor must hand back
    // that block's start: offset 0, and a block exactly the secret's size.
    assert_zeroed_when_freed(
        "CircleVeilidOwnerSeed",
        (0, SEED_LEN),
        || derive_circle_veilid_owner_seed("correct horse battery staple", &CNSA_2_0).unwrap(),
        |s| s.as_bytes().as_slice(),
    );

    assert_zeroed_when_freed(
        "CirclePresenceVeilidOwnerSeed",
        (0, SEED_LEN),
        || {
            derive_circle_presence_veilid_owner_seed("correct horse battery staple", &CNSA_2_0)
                .unwrap()
        },
        |s| s.as_bytes().as_slice(),
    );

    assert_zeroed_when_freed(
        "RoomVeilidOwnerSeed",
        (0, SEED_LEN),
        || derive_room_veilid_owner_seed("general", &CNSA_2_0).unwrap(),
        |s| s.as_bytes().as_slice(),
    );

    // The DM ratchet's own boxed secret, and the only watched block that is not
    // 32 bytes — a `[u8; DK_LEN]` at 3168. It takes its bytes directly rather
    // than deriving them, which is the point: the wipe is the newtype's, not the
    // derivation's.
    assert_zeroed_when_freed(
        "EphemeralDecapKey",
        (0, DK_LEN),
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

    // Deliberately outside the `GATE` window, and safe there. These two lines are
    // heavy allocation churn that runs concurrently with another test's armed
    // watch, but a watch is armed only while the secret it points at is still
    // LIVE — so no allocation this thread frees can be a block containing that
    // address, and containment matching therefore cannot fire on it. Address reuse
    // only becomes possible after the watched block is freed, by which point
    // `dealloc` has already disarmed. Moving them inside the gate is not possible
    // anyway: one derivation feeds all three cases below.
    let mnemonic = Mnemonic::generate().unwrap();
    let keys = derive_identity_keys(&mnemonic, Identity::Primary).unwrap();

    // An `inline` secret is the whole of its `Box`, so the block is the newtype's
    // own size and the array sits at its start.
    assert_zeroed_when_freed(
        "VeilidNodeSeed",
        (0, SEED_LEN),
        || Box::new(keys.veilid_node_seed),
        |s| s.as_bytes().as_slice(),
    );
    assert_zeroed_when_freed(
        "ShareRootIkm",
        (0, SEED_LEN),
        || Box::new(keys.share_root_ikm),
        |s| s.as_bytes().as_slice(),
    );
    assert_zeroed_when_freed(
        "DmDoorbellSlotSecret",
        (0, SEED_LEN),
        || Box::new(keys.dm_doorbell_slot_secret),
        |s| s.as_bytes().as_slice(),
    );
}

/// The two secrets the macro does not cover wipe themselves before their storage
/// is released.
///
/// These are the sites the compile-time `ZeroizeOnDrop` bound in `secret_seed.rs`
/// cannot reach: both are multi-field structs carrying one secret field beside
/// plaintext ones, so neither is a macro-generated newtype and neither can carry
/// the trait. They get there by different routes, and each case is the only thing
/// holding its route:
///
/// - `PersistedCircle::entropy` is a private [`Zeroizing`] `String`, so the wipe is
///   the field type's. Widening it back to a bare `String` leaves the whole suite
///   green but for this case.
/// - `VerifiedFirstContact::ss0` is a bare `[u8; SS0_LEN]` wiped by a hand-written
///   `Drop`. Deleting that `zeroize()` call leaves the whole suite green but for
///   this case.
#[test]
fn secrets_outside_the_macro_zero_themselves_before_their_memory_is_released() {
    init();

    // `entropy` is a `String`, so its bytes are their own heap block: offset 0, and
    // a block the size of the string's CAPACITY rather than its length. Built with
    // slack for that reason. Note what this case does and does not observe — the
    // accessor yields the live bytes only, so the assertion covers
    // `CIRCLE_PHRASE_LEN` of the buffer; the block-size assertion is what proves
    // the buffer genuinely carried slack, i.e. that this is the production shape.
    assert_zeroed_when_freed(
        "PersistedCircle",
        (0, CIRCLE_PHRASE_CAP),
        || {
            let mut phrase = String::with_capacity(CIRCLE_PHRASE_CAP);
            phrase.push_str("correct horse battery staple correct horse battery staple");
            assert_eq!(phrase.len(), CIRCLE_PHRASE_LEN);
            PersistedCircle::new(phrase, "the label is not a secret")
        },
        |c| c.entropy().as_bytes(),
    );

    // `ss0` is an inline `[u8; SS0_LEN]` field, so it is watched as a range at a
    // non-zero offset inside the boxed struct's own block — the case the witness was
    // generalised for. `offset_of!` / `size_of` state that structurally: offset 64
    // of 160 on the current layout, and an accessor that drifted to any other field
    // fails on the offset.
    //
    // The distinct filler bytes are a WEAKER control than they look, which is why
    // the offset assertion above carries the load. They catch only a HIGH-side slip
    // into `roots.ar` (0x44). A slip 1–7 bytes LOW lands in `body`'s length word —
    // `18 00 00 00 00 00 00 00` for a 24-byte body — so the snapshot would read as
    // zeros plus a zeroized `ss0` and pass vacuously. What the fillers guarantee is
    // narrow: no neighbouring field is all-zero *above* `ss0`.
    assert_zeroed_when_freed(
        "VerifiedFirstContact",
        (
            core::mem::offset_of!(VerifiedFirstContact, ss0),
            size_of::<VerifiedFirstContact>(),
        ),
        || {
            Box::new(VerifiedFirstContact {
                pk_lt: Box::new([0x11u8; PK_LEN]),
                pk_pc: Box::new([0x22u8; PK_LEN]),
                eph_ek: Box::new([0x33u8; EK_LEN]),
                seq: 7,
                sent_unix_ms: 1_700_000_000_000,
                body: "the body is not a secret".to_owned(),
                ss0: [0xA5u8; SS0_LEN],
                roots: ChannelRoots {
                    ar: [0x44u8; ROOT_LEN],
                    chan_id: [0x55u8; ROOT_LEN],
                },
            })
        },
        |v| v.ss0.as_slice(),
    );
}

/// The `realloc` disarm is itself a control, so hold it to being live.
///
/// A watched buffer that is reallocated may be released inside `realloc` without
/// ever reaching `dealloc`. If that branch stopped firing, the watch would be left
/// armed over memory that is no longer the secret's — and because containment
/// matching accepts any block enclosing the watched range, some *later, larger*
/// allocation handed out at that address would satisfy it on its own free. That is
/// a false pass in the exact direction this file exists to rule out, and it would
/// be invisible: every other case here watches a fixed-size array that never
/// moves, so nothing else exercises the branch and it could rot silently while the
/// suite stayed green.
///
/// The disarm is deliberately unconditional on whether the block actually moved.
/// `realloc` may grow in place and return the same pointer, and the witness cannot
/// know which happened before forwarding — so it gives up the watch either way
/// rather than guess.
#[test]
fn a_watched_buffer_that_is_reallocated_disarms_the_watch() {
    let _gate = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    WATCH_ADDR.store(0, Ordering::SeqCst);
    CAPTURED.store(false, Ordering::SeqCst);
    REALLOCATED.store(false, Ordering::SeqCst);
    CAPTURED_OFFSET.store(0, Ordering::SeqCst);
    CAPTURED_BLOCK.store(0, Ordering::SeqCst);

    let mut phrase = String::with_capacity(CIRCLE_PHRASE_LEN);
    phrase.push_str("correct horse battery staple correct horse battery staple");
    // Fill whatever slack `with_capacity` actually handed back, so the single push
    // below must reallocate rather than fitting in spare capacity. Asserting an
    // exact capacity here would be relying on an allocation-size guarantee the
    // standard library does not make.
    while phrase.len() < phrase.capacity() {
        phrase.push('x');
    }

    let addr = phrase.as_ptr() as usize;
    WATCH_LEN.store(phrase.len(), Ordering::SeqCst);
    WATCH_ADDR.store(addr, Ordering::SeqCst);

    // Control on the arming itself. Without it, a watch that never covered this
    // buffer would make the assertions below pass for the wrong reason — the same
    // vacuous-pass shape the rest of this file guards against.
    assert_eq!(
        watch_offset_in(addr, phrase.capacity()),
        Some(0),
        "the watch is not armed over the buffer this case is about to grow, so \
         nothing it observes afterwards means anything"
    );

    phrase.push('!');

    assert!(
        REALLOCATED.load(Ordering::SeqCst),
        "the realloc branch never fired, so a reallocated buffer would leave the \
         watch armed over memory that is no longer the secret's"
    );
    assert_eq!(
        WATCH_ADDR.load(Ordering::SeqCst),
        0,
        "the watch was left armed after its buffer was reallocated"
    );

    // The buffer that is freed here is the *new* one, which the watch no longer
    // points at. Nothing may be captured from it.
    drop(phrase);
    assert!(
        !CAPTURED.load(Ordering::SeqCst),
        "a block was captured after the watch should have been disarmed"
    );

    WATCH_ADDR.store(0, Ordering::SeqCst);
    REALLOCATED.store(false, Ordering::SeqCst);
}
