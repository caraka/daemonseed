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
//! The witness also covers the two secret-bearing structs the macro does not
//! generate: `PersistedCircle` and `VerifiedFirstContact`. Both are now on
//! `#[derive(Zeroize, ZeroizeOnDrop)]` rather than a hand-written `Drop` (#267),
//! so the cases below watch every field either struct stores on the heap, not the
//! one field a hand-written `Drop` happened to name — `PersistedCircle`'s
//! `entropy` AND `label`, and `VerifiedFirstContact`'s `ss0` AND `body`.
//!
//! That widening is the point of the change, and it is why `label` is watched at
//! all despite not being a secret. Under a hand-written `Drop` the test enumerated
//! the same field names the code did, so the two shared one assumption and a field
//! added to either struct was uncovered in both places at once. Under the derive
//! the default is a wipe, and `label` is the case that holds the default: it is
//! the field no author would think to add a `zeroize()` call for, and it is wiped.
//!
//! Neither struct carries a single `#[zeroize(skip)]`, so every field is wiped and
//! there is no opt-out to review. Four of the six heap-resident ones are watched
//! here (`entropy`, `label`, `ss0`, `body`) plus `pk_lt` as the `Box<[u8; N]>`
//! shape; `pk_pc` and `eph_ek` are the same shape as `pk_lt` and are held by the
//! same derive, and `seq`/`sent_unix_ms` are scalars this allocator hook cannot
//! see. The compile-time bound in `secret_seed.rs` now names both structs; before
//! this change it could not reach them at all.
//!
//! `VerifiedFirstContact`'s fields are private, because holding one is meant to be
//! the proof that its seal opened and its signatures verified (#265). This file
//! reaches them through the `testing`-gated constructor and accessors described
//! there, which this crate's own dev-dependency on itself switches on and nothing
//! else does.
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
//!
//! **Stack copies are outside this harness entirely.** `assert_zeroed_when_freed`
//! is a global-allocator hook: it watches a heap block and reads it at the moment
//! that block is handed back. A `Copy` secret sitting on a stack frame — a
//! `[u8; 32]` shared secret or a `[u8; DK_LEN]` decapsulation key inside a
//! `Result` a function has not yet returned from — is never allocated and never
//! freed, so nothing here observes it. That class is held by the in-place wipes
//! in `dm::reest` and `dm::ratchet`; no case in this file can go red on it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use daemonseed_core::circle::key::{
    derive_circle_presence_veilid_owner_seed, derive_circle_veilid_owner_seed,
};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::dm::firstcontact::{ChannelRoots, ROOT_LEN, SS0_LEN, VerifiedFirstContact};
use daemonseed_core::dm::ratchet::EphemeralDecapKey;
use daemonseed_core::dm::ratchet::ROOT_KEY_LEN;
use daemonseed_core::dm::resume::{
    CommittedRoot, DedupMemory, FreshAttempt, OwnSlot, ReEstState, ResumeRecord, RetainedRoot,
    Retention, SealedReEst, SendFloor, reroot,
};
use daemonseed_core::identity::keys::{Identity, derive_identity_keys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::public_room::derive_room_veilid_owner_seed;
use daemonseed_core::storage::seeds::{PersistedCircle, Seeds};
use oxicrypt_ml_dsa::{PK_LEN, SK_LEN as ML_DSA_SK_LEN};
use oxicrypt_ml_kem::{DK_LEN, EK_LEN};
use zeroize::Zeroizing;

/// Large enough for the biggest secret watched here, which since #314 is the
/// ML-DSA-87 signing key behind `ResumeRecord::s_pc` at 4 896 bytes — larger than
/// the ML-KEM decapsulation key that previously set this bound.
///
/// Derived from the constant rather than written as a literal, so a suite change
/// that grows the ML-DSA key cannot silently outrun the buffer. It tracks that key
/// only: a decapsulation key grown past it is caught by the length refusal below
/// instead — loudly, and at the case that needs it, but not by this derivation.
///
/// `assert_zeroed_when_freed` refuses a secret longer than this rather than
/// truncating it, which is what caught the 4 096 figure when the first #314 case
/// was added — a truncating snapshot would have compared only the first 4 096 bytes
/// and passed while the tail went unexamined.
const SNAPSHOT_CAP: usize = if ML_DSA_SK_LEN > 4096 {
    ML_DSA_SK_LEN
} else {
    4096
};

/// The size every 32-byte secret newtype watched here occupies — the block size
/// each such case expects the allocator to hand back.
const SEED_LEN: usize = 32;

/// Length and capacity of the circle phrase the `PersistedCircle` case builds.
/// They differ on purpose: production entropy is parsed out of a decrypted
/// plaintext and can carry slack, so the watched buffer carries slack too rather
/// than being the exact-fit buffer `to_owned()` would give.
const CIRCLE_PHRASE_LEN: usize = 57;
const CIRCLE_PHRASE_CAP: usize = 96;

/// The circle label, and the capacity its buffer is built with. Slack again, and
/// a capacity distinct from every other watched block here so the structural
/// block-size control cannot be satisfied by the wrong allocation.
const CIRCLE_LABEL_TEXT: &str = "the label is not a secret";
const CIRCLE_LABEL_CAP: usize = 72;

/// The circle phrase the `Seeds::circle_seen` key case stores, and the capacity
/// its buffer is built with.
///
/// The capacity carries deliberate slack so the block-size control has something
/// to assert: a production copy or reallocation collapses it to an exact fit and
/// the case notices. It is **not** here for distinctness from the other watched
/// capacities (96, 72, 128) — that reasoning belongs to the `ARM_SIZE`-armed cases
/// and this one is armed by address, so a same-sized allocation elsewhere cannot
/// be mistaken for it.
///
/// The phrase text differs from `PersistedCircle`'s because both hold the same
/// *kind* of secret, and a snapshot matching the wrong one would otherwise read as
/// a pass.
const CIRCLE_SEEN_PHRASE: &str = "a different phrase for the read high-water key";
const CIRCLE_SEEN_PHRASE_LEN: usize = 46;
const CIRCLE_SEEN_KEY_CAP: usize = 80;

/// The decrypted message the `VerifiedFirstContact::body` case builds, and the
/// length and capacity of its buffer. They differ for the same reason the circle
/// phrase's do: the production body is decoded out of a padded plaintext and can
/// carry slack, so the watched buffer carries slack too.
const DM_BODY_TEXT: &str = "meet me at the usual place, half past eight";
const DM_BODY_LEN: usize = DM_BODY_TEXT.len();
const DM_BODY_CAP: usize = 128;

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
/// The `Box<[u8; PK_LEN]>` block behind `VerifiedFirstContact::pk_lt` — the
/// public key's own heap allocation, exactly the array's size.
const ML_DSA_PK_BLOCK: usize = PK_LEN;
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

/// Size of the *next* allocation to arm the watch on, or 0 when disarmed.
///
/// The cases above all hold the secret in a value the test constructs, so they
/// arm by taking its address. `#343`'s secret is different in kind: it is a
/// buffer created and dropped entirely *inside* `Seeds::from_plaintext`, on an
/// error path, and it never escapes for a test to point at. Arming by allocation
/// size is how a watch reaches it — the first block of exactly this size handed
/// out after arming is the one the parser decoded into.
///
/// Deliberately not a scan of every freed block for the secret's bytes, which is
/// the obvious alternative: a block's tail can be uninitialized (`Vec` slack), and
/// reading it would be UB — the very thing whole-range containment above exists to
/// avoid. An exact-size block that the decoder filled is initialized to its last
/// byte, so reading all of it stays sound.
static ARM_SIZE: AtomicUsize = AtomicUsize::new(0);

/// How many matching allocations to let past before arming.
///
/// **Load-bearing, and the case is wrong without it.** On the path under test two
/// buffers of the secret's exact length are allocated in order: the decode buffer
/// inside `decode_hex_secret`, and the `to_owned()` copy it returns. The decode
/// buffer is freed at the end of that helper — *before* the label decode whose
/// failure this case is about — so arming on the first match observes a buffer
/// whose wipe says nothing about the entry point's error path. Skipping one match
/// puts the watch on the returned copy, which is the value still live when the
/// parser returns `Err`.
static ARM_SKIP: AtomicUsize = AtomicUsize::new(0);

/// How many allocations of the armed size were seen while armed.
///
/// Read by the case as a structural assertion: the path is documented to allocate
/// exactly two, and a count that is not two means the shape changed underneath the
/// skip above, which would silently move the watch to a different buffer.
static ARM_SEEN: AtomicUsize = AtomicUsize::new(0);

/// Point the existing address watch at a block of the armed size.
///
/// Called from `alloc`/`alloc_zeroed` so the rest of the machinery — the
/// containment test, the snapshot, `CAPTURED`, the realloc disarm — is reached
/// unchanged; only the way the watch gets armed is new. Disarms `ARM_SIZE` once it
/// arms, so a later same-sized allocation cannot move the watch off the block
/// being observed.
///
/// Allocates nothing, so there is no re-entry into the allocator.
fn arm_on_size(ptr: *mut u8, size: usize) {
    if ptr.is_null() || ARM_SIZE.load(Ordering::SeqCst) != size {
        return;
    }
    ARM_SEEN.fetch_add(1, Ordering::SeqCst);
    if ARM_SKIP.load(Ordering::SeqCst) > 0 {
        ARM_SKIP.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    ARM_SIZE.store(0, Ordering::SeqCst);
    WATCH_LEN.store(size, Ordering::SeqCst);
    WATCH_ADDR.store(ptr as usize, Ordering::SeqCst);
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
        let ptr = unsafe { System.alloc(layout) };
        arm_on_size(ptr, layout.size());
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        arm_on_size(ptr, layout.size());
        ptr
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

/// The address of a secret's bytes plus a zeroizing copy of them, which is all
/// [`assert_zeroed_when_freed`] needs from a `locate` closure.
///
/// It takes the two facts out by value rather than handing back a borrow, so a
/// secret reached through a scoped `with_bytes` accessor — where the return type
/// cannot borrow from the closure's argument, by design (#271) — can be witnessed
/// on the same harness as one reached through `as_bytes`. Returning a borrow was
/// the only thing tying this harness to the borrowing accessor shape.
///
/// **Every `locate` closure must go through this function**, and that is a
/// convention rather than a type: the tuple does not force the address and the
/// bytes to come from the same object, where the old `&[u8]` return did. A future
/// `locate` that hand-rolls the pair could watch one allocation and snapshot
/// another, and the harness would not notice.
fn at(bytes: &[u8]) -> (usize, Zeroizing<Vec<u8>>) {
    (bytes.as_ptr() as usize, Zeroizing::new(bytes.to_vec()))
}

/// Build a secret, watch the bytes it stores its key material in, drop it, and
/// require that those bytes were all zeros when the allocator got their block
/// back.
///
/// `locate` reaches the secret's bytes *through the public accessor* and hands
/// back [`at`]'s pair, so the watched range is the one the type actually stores
/// its key material in. It may be a whole heap block or a field inside a larger
/// one; the witness accepts either.
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
    locate: impl Fn(&T) -> (usize, Zeroizing<Vec<u8>>),
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
    let (addr, before) = locate(&secret);
    let len = before.len();

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
    let _ = daemonseed_core::kats::initialize_module_unsigned_test_binary();
}

/// Length of the circle entropy the #343 cases decode.
///
/// **A power of two, and that is load-bearing for the probe rather than
/// arbitrary.** `hex::decode` collects through a `Result` adapter whose
/// `size_hint` lower bound is 0, so the decoded buffer is grown geometrically
/// instead of reserved once: measured, 137 bytes decode into a 256-byte
/// allocation and 3 001 into a 4 096-byte one. At any such length the freed
/// block's size is not the secret's length, and a watch armed on the length
/// never fires — which reads as "observed nothing" rather than as a verdict.
/// At 4 096 the grown capacity lands exactly on the length, so the same watch
/// observes the buffer whether or not the fix is present, and the case can fail
/// for the right reason.
///
/// A 4 096-byte circle entropy is not a realistic phrase, and does not need to
/// be: the parser applies no length rule, and what is under test is the buffer's
/// lifetime, not its contents. It is also within `SNAPSHOT_CAP`.
const DECODE_SECRET_LEN: usize = 4096;

/// The circle entropy those cases decode, as its own bytes. Distinctive text
/// rather than random, so a failure message shows recognisably what leaked.
fn decode_secret() -> String {
    let mut s = String::with_capacity(DECODE_SECRET_LEN);
    while s.len() < DECODE_SECRET_LEN {
        s.push_str("circle-entropy-that-must-never-outlive-its-buffer ");
    }
    s.truncate(DECODE_SECRET_LEN);
    s
}

/// Lowercase hex of `bytes`, built without `hex::encode` so this helper cannot
/// itself leave an un-zeroized copy of what the case is about.
fn hex_of(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

/// Run `body`, watching the first heap block of exactly `DECODE_SECRET_LEN`
/// bytes allocated after arming, and hand back what that block held when it was
/// freed.
///
/// `Err` means the run observed nothing — which every caller must treat as
/// inconclusive rather than as a pass, since an unobserved block proves nothing
/// about its contents. The two reasons are reported separately because they call
/// for different fixes: a reallocation means the watch was disarmed mid-flight,
/// while nothing captured means the armed size never matched a freed block, and
/// the usual cause of the latter is a size that collides with an unrelated
/// allocation earlier on the path.
fn freed_bytes_of_decode_sized_block(
    skip: usize,
    body: impl FnOnce(),
) -> Result<(Zeroizing<Vec<u8>>, usize), &'static str> {
    let _gate = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    WATCH_ADDR.store(0, Ordering::SeqCst);
    CAPTURED.store(false, Ordering::SeqCst);
    REALLOCATED.store(false, Ordering::SeqCst);
    CAPTURED_OFFSET.store(0, Ordering::SeqCst);
    CAPTURED_BLOCK.store(0, Ordering::SeqCst);
    ARM_SKIP.store(skip, Ordering::SeqCst);
    ARM_SEEN.store(0, Ordering::SeqCst);
    ARM_SIZE.store(DECODE_SECRET_LEN, Ordering::SeqCst);

    body();

    ARM_SIZE.store(0, Ordering::SeqCst);
    ARM_SKIP.store(0, Ordering::SeqCst);
    WATCH_ADDR.store(0, Ordering::SeqCst);
    let seen = ARM_SEEN.swap(0, Ordering::SeqCst);

    if REALLOCATED.load(Ordering::SeqCst) {
        return Err("the watched block was reallocated, which disarms the watch");
    }
    if !CAPTURED.load(Ordering::SeqCst) {
        return Err(
            "no block of the watched size was freed while armed — most likely the \
             armed size matched an unrelated earlier allocation",
        );
    }
    Ok((
        Zeroizing::new(
            SNAPSHOT
                .iter()
                .take(DECODE_SECRET_LEN)
                .map(|b| b.load(Ordering::SeqCst))
                .collect::<Vec<u8>>(),
        ),
        seen,
    ))
}

/// The mirror control for the case below, and it must fail if the watch is broken.
///
/// Deliberately leaks the secret the way the parser used to: a plain `String` of
/// exactly the watched size, dropped with its bytes intact. If the size-armed
/// watch works at all, this run captures those bytes — so a green result here is
/// what licenses reading the real case's "no secret in the freed block" as
/// evidence rather than as silence. Without it, a watch that never fired would
/// make the real case pass for the wrong reason.
#[test]
fn the_size_armed_watch_captures_a_secret_that_is_not_wiped() {
    init();
    let needle = decode_secret();

    let (seen, allocations) = freed_bytes_of_decode_sized_block(0, || {
        // A bare `String`, allocated at exactly the watched size and dropped
        // without wiping — the pre-#343 shape, reproduced on purpose.
        let leaked: String = needle.clone();
        drop(leaked);
    })
    .unwrap_or_else(|why| {
        panic!("the control observed nothing ({why}), so no case here can conclude anything")
    });

    assert_eq!(
        allocations, 1,
        "the control is supposed to make exactly one allocation of the watched \
         size; {allocations} means it is not the clean single-buffer case the \
         real case's skip count is calibrated against"
    );
    assert_eq!(
        seen.as_slice(),
        needle.as_bytes(),
        "the control did not recover the bytes it deliberately leaked, so the \
         watch is not observing what it claims to"
    );
}

/// A malformed *label* must not strand the circle entropy that parsed before it
/// (#343).
///
/// The ordering is the whole point: the entropy decodes successfully, and the
/// very next line fails, returning from `from_plaintext` while the secret is
/// still live. Before #343 that secret was a bare `String` and dropped intact.
///
/// Reachable only through a corrupt or truncated at-rest blob — which is to say,
/// exactly when the recovery path runs.
#[test]
fn a_later_parse_error_does_not_strand_the_decoded_circle_entropy() {
    init();
    let needle = decode_secret();
    // Valid entropy hex, malformed label hex. `zz` is not hex, so the label
    // decode fails *after* the entropy has been decoded and while it is live.
    let payload = format!(
        "{}\ncircle {} zz\n",
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art",
        hex_of(needle.as_bytes()),
    );

    // Skip one: the first block of this size is `decode_hex_secret`'s decode
    // buffer, which is freed inside that helper, before the label decode this
    // case is about. The watch belongs on the copy it returns — the value still
    // live when the parser gives up.
    let (seen, allocations) = freed_bytes_of_decode_sized_block(1, || {
        let parsed = daemonseed_core::storage::seeds::Seeds::parse_plaintext_for_witness(&payload);
        // Pinned to the exact variant, not merely `is_err()`. A mnemonic that
        // failed to parse would also be an error, and would return *before* the
        // circle line — leaving this case watching a path the secret never
        // reaches, which reads as a pass once the watch is arranged correctly.
        assert!(
            matches!(
                parsed,
                Err(daemonseed_core::storage::seeds::BlobError::InvalidPlaintext)
            ),
            "expected InvalidPlaintext from the malformed label hex, got {parsed:?} \
             — this case is not exercising the error path it names"
        );
    })
    .unwrap_or_else(|why| {
        panic!(
            "this case observed nothing ({why}).\n\nThat is a FAILURE, not a skip. \
             The watch is armed on a block of exactly the secret's length, and the \
             fix is what makes one exist: `decode_hex_secret` decodes into a \
             right-sized `Zeroizing` buffer. Without it the parser decodes through \
             `hex::decode`, which grows geometrically — so the secret lives in an \
             over-sized buffer this watch cannot address, and reaches a ladder of \
             freed intermediate copies besides. Seeing nothing here means the \
             exact-size zeroizing buffer is gone."
        )
    });

    assert_eq!(
        allocations, 2,
        "the path is documented to allocate exactly two blocks of the secret's \
         length — the decode buffer and the copy returned from it — and saw \
         {allocations}. The skip count above is calibrated on that shape, so a \
         different count means the watch is no longer on the buffer this case \
         names, whatever the assertions below say"
    );
    assert_ne!(
        seen.as_slice(),
        needle.as_bytes(),
        "the decoded circle entropy was still in freed memory: the parser's \
         error path released it without wiping"
    );
    assert!(
        seen.iter().all(|&b| b == 0),
        "the freed block held something other than zeros after the parse error: {:02x?}",
        seen.as_slice()
    );
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
        |s| at(s.as_bytes()),
    );

    assert_zeroed_when_freed(
        "CirclePresenceVeilidOwnerSeed",
        (0, SEED_LEN),
        || {
            derive_circle_presence_veilid_owner_seed("correct horse battery staple", &CNSA_2_0)
                .unwrap()
        },
        |s| at(s.as_bytes()),
    );

    assert_zeroed_when_freed(
        "RoomVeilidOwnerSeed",
        (0, SEED_LEN),
        || derive_room_veilid_owner_seed("general", &CNSA_2_0).unwrap(),
        |s| at(s.as_bytes()),
    );

    // The DM ratchet's own boxed secret, and the only watched block that is not
    // 32 bytes — a `[u8; DK_LEN]` at 3168. It takes its bytes directly rather
    // than deriving them, which is the point: the wipe is the newtype's, not the
    // derivation's.
    assert_zeroed_when_freed(
        "EphemeralDecapKey",
        (0, DK_LEN),
        || EphemeralDecapKey::new(Box::new([0xA5u8; DK_LEN])),
        |s| at(s.as_bytes()),
    );
}

/// The inline arm keeps its secret in the value itself, so it is observed by
/// moving a real identity-rooted secret into a `Box`: that puts the inline
/// `[u8; 32]` inside a heap block the witness can watch. The wrapper's `Drop`
/// wipes the array in place, and only then is the block released.
///
/// All three identity-rooted secrets come from one derivation, so this covers
/// every inline-family secret that has a public constructor — with one caveat
/// since #271: `VeilidNodeSeed` is on the `inline_scoped` arm rather than
/// `inline`, so its case here proves the *scoped* arm's expansion, not this one's.
/// The two arms share their storage, `Zeroize` and `ZeroizeOnDrop` derives, which
/// is why they are witnessed together, but a change to one does not move the
/// other. The inline ratchet keys (`RootKey`, `ChainKey`, `MessageKey`) are built
/// only inside their own module and are reachable here only by the compile-time
/// bound in `secret_seed.rs`; they share the `inline` arm, so the arm-level
/// property proved by the two remaining cases is the one they rely on.
#[test]
fn inline_arm_secrets_are_zeroed_before_their_memory_is_released() {
    init();

    // **Under `GATE`, released before the cases below take it.** These two lines
    // are heavy allocation churn, and the reasoning that once excused running
    // them concurrently covers ADDRESS-armed watches only: such a watch is armed
    // only while its secret is live, so no free on this thread can match it.
    // `freed_bytes_of_decode_sized_block` arms on a block SIZE instead, and any
    // thread's free of that size satisfies the match — which made this churn a
    // real source of stolen captures once the file grew enough cases to overlap
    // it. Holding the gate across all three cases below would deadlock, since
    // each takes it itself; holding it for the derivation alone does not, and
    // one derivation still feeds all three.
    let keys = {
        let _churn_gate = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mnemonic = Mnemonic::generate().unwrap();
        derive_identity_keys(&mnemonic, Identity::Primary).unwrap()
    };

    // An `inline` secret is the whole of its `Box`, so the block is the newtype's
    // own size and the array sits at its start.
    assert_zeroed_when_freed(
        "VeilidNodeSeed",
        (0, SEED_LEN),
        || Box::new(keys.veilid_node_seed),
        |s| s.with_bytes(|b| at(b)),
    );
    assert_zeroed_when_freed(
        "ShareRootIkm",
        (0, SEED_LEN),
        || Box::new(keys.share_root_ikm),
        |s| at(s.as_bytes()),
    );
    assert_zeroed_when_freed(
        "DmDoorbellSlotSecret",
        (0, SEED_LEN),
        || Box::new(keys.dm_doorbell_slot_secret),
        |s| at(s.as_bytes()),
    );
}

/// Every heap-resident field of the two multi-field secret structs is zeroed
/// before its storage is released.
///
/// The sites the macro does not generate. Both structs now carry
/// `#[derive(Zeroize, ZeroizeOnDrop)]` (#267), so the case list is driven by what
/// the structs actually store rather than by which fields a hand-written `Drop`
/// remembered:
///
/// - `PersistedCircle::entropy` is a private [`Zeroizing`] `String`. It has two
///   independent wipes now — the field type's and the derive's — so this case no
///   longer goes red on the loss of either alone. That is a strictly better state
///   for the code and a weaker mutation signal for the test, which is why `label`
///   below exists.
/// - `PersistedCircle::label` is a plain `String` and is not a secret. It is here
///   as the load-bearing case for the derive: nothing but the derive wipes it, so
///   removing `Zeroize, ZeroizeOnDrop` from the struct leaves the whole suite green
///   but for this case. It stands in for the secret field somebody adds next.
/// - `ChannelRoots::rs0` is the retained re-establishment root — the one root of
///   the four that outlives establishment, and therefore the one a copy left in
///   freed memory would hand an attacker. It is the struct's last field, so the
///   watched range runs from its offset to the end of the struct and covers no
///   neighbour; what stands behind the case is the offset, not a filler contrast.
/// - `VerifiedFirstContact::ss0` is a bare `[u8; SS0_LEN]`, wiped only by the
///   derive. Removing the derive, or marking the field `#[zeroize(skip)]`, leaves
///   the whole suite green but for this case.
/// - `VerifiedFirstContact::body` is the decrypted message, wiped by the same
///   derive. It is a `String`, so it is watched as its own heap block rather than
///   as a range inside the struct — the two secrets on one struct take two
///   different routes through this witness (#266).
/// - `VerifiedFirstContact::pk_lt` is a public key, not a secret, and is the
///   `Box<[u8; N]>` shape. It is `label`'s counterpart for boxed fields, and it
///   pins the non-obvious half of the derive's reach: `Box<[u8; N]>` has no
///   `Zeroize` impl of its own, and is covered anyway because the call derefs.
///   Marking it `#[zeroize(skip)]` leaves the whole suite green but for this case.
#[test]
fn secrets_outside_the_macro_zero_themselves_before_their_memory_is_released() {
    init();

    // `entropy` is a `String`, so its bytes are their own heap block: offset 0, and
    // a block the size of the string's CAPACITY rather than its length. Built with
    // slack for that reason. Note what this case does and does not observe — the
    // accessor yields the live bytes only, so the assertion covers
    // `CIRCLE_PHRASE_LEN` of the buffer; the block-size assertion is what proves
    // the buffer genuinely carried slack, i.e. that this is the production shape.
    //
    // Two wipes now stand behind this case — `Zeroizing<String>` on the field and
    // the struct's derive — so it goes red only if BOTH are removed. `label` below
    // is what holds the derive on its own.
    assert_zeroed_when_freed(
        "PersistedCircle::entropy",
        (0, CIRCLE_PHRASE_CAP),
        || {
            let mut phrase = String::with_capacity(CIRCLE_PHRASE_CAP);
            phrase.push_str("correct horse battery staple correct horse battery staple");
            assert_eq!(phrase.len(), CIRCLE_PHRASE_LEN);
            PersistedCircle::new(phrase, circle_label())
        },
        |c| at(c.entropy().as_bytes()),
    );

    // The same struct's other field, and the only case here whose subject is not a
    // secret. It is watched precisely because nothing about it says "wipe me": it
    // is public, it is display text, and no hand-written `Drop` would ever have
    // named it. If it comes back zeroed, the wipe is the struct's default rather
    // than a per-field decision — which is the whole property #267 asked for, and
    // the one a future secret field will inherit. Watched the same way `entropy`
    // is, as its own heap block at offset 0 with the capacity as the block size.
    assert_zeroed_when_freed(
        "PersistedCircle::label",
        (0, CIRCLE_LABEL_CAP),
        || {
            let mut phrase = String::with_capacity(CIRCLE_PHRASE_CAP);
            phrase.push_str("correct horse battery staple correct horse battery staple");
            PersistedCircle::new(phrase, circle_label())
        },
        |c| at(c.label.as_bytes()),
    );

    // `ChannelRoots::rs0` is the retained re-establishment root, and it is the
    // one root of the four that survives establishment — `ss0` is deleted, and
    // with it the ratchet root, so `rs0` is what a copy of this struct left in
    // freed memory would hand an attacker: channel-resume authority for the rest
    // of the correspondence.
    //
    // Watched as a range inside the boxed struct's own block, the way `ss0` is,
    // with the offset taken structurally rather than assumed. `rs0` is the last
    // field, so the range from its offset to the end of the struct is the field
    // itself plus any tail padding — no neighbour falls inside it, and the
    // distinct fillers on `ar` and `chan_id` are not doing work here. The
    // structural offset is what holds the case: an accessor that drifted to
    // another field would report an address outside the watched range.
    //
    // Two wipes stand behind this case — `CommittedRoot`'s own `ZeroizeOnDrop`
    // and the struct's derive — so it is a weaker mutation signal than a
    // single-wipe case. It goes red on the shape that actually threatens it:
    // storing the root as a bare `[u8; ROOT_KEY_LEN]`, which has no wipe of its
    // own and which the struct's derive is then the only thing covering.
    assert_zeroed_when_freed(
        "ChannelRoots::rs0",
        (
            std::mem::offset_of!(ChannelRoots, rs0),
            size_of::<ChannelRoots>(),
        ),
        || {
            Box::new(ChannelRoots {
                ar: [0x44u8; ROOT_LEN],
                chan_id: [0x55u8; ROOT_LEN],
                rs0: CommittedRoot::from_bytes(&[0x66u8; ROOT_KEY_LEN]),
            })
        },
        |r| at(r.rs0.as_bytes()),
    );

    // `ss0` is an inline `[u8; SS0_LEN]` field, so it is watched as a range at a
    // non-zero offset inside the boxed struct's own block — the case the witness was
    // generalised for. `ss0_offset_for_test` / `size_of` state that structurally:
    // offset 64 of 160 on the current layout, and an accessor that drifted to any
    // other field fails on the offset. The offset comes from a `testing`-gated
    // accessor rather than `offset_of!` because the field is private (#265) and
    // `offset_of!` cannot see a private field from out here.
    //
    // The distinct filler bytes are a WEAKER control than they look, which is why
    // the offset assertion above carries the load. They catch only a HIGH-side slip
    // into `roots.ar` (0x44). A slip 1–7 bytes LOW lands in `body`'s length word —
    // `18 00 00 00 00 00 00 00` for a 24-byte body — so the snapshot would read as
    // zeros plus a zeroized `ss0` and pass vacuously. What the fillers guarantee is
    // narrow: no neighbouring field is all-zero *above* `ss0`.
    assert_zeroed_when_freed(
        "VerifiedFirstContact::ss0",
        (
            VerifiedFirstContact::ss0_offset_for_test(),
            size_of::<VerifiedFirstContact>(),
        ),
        || {
            Box::new(verified_first_contact(
                "the body is not a secret".to_owned(),
            ))
        },
        |v| at(v.ss0_for_test()),
    );

    // The decrypted message on the same struct. Unlike `ss0` it is a `String`, so
    // it is watched exactly as `PersistedCircle::entropy` is — its own heap block,
    // offset 0, block size the CAPACITY — and the struct it hangs off is left on
    // the stack, since the watched block is the string buffer rather than the
    // struct. Built with slack for the same reason as the circle phrase: the
    // production body is decoded out of a padded plaintext and carries slack, so an
    // exact-fit buffer would not be the production shape.
    //
    // What this case holds: `body` is wiped by the same hand-written `Drop` that
    // wipes `ss0`. Deleting `self.body.zeroize()` leaves the whole suite green but
    // for this case (#266).
    assert_zeroed_when_freed(
        "VerifiedFirstContact::body",
        (0, DM_BODY_CAP),
        || {
            let mut body = String::with_capacity(DM_BODY_CAP);
            body.push_str(DM_BODY_TEXT);
            assert_eq!(body.len(), DM_BODY_LEN);
            verified_first_contact(body)
        },
        |v| at(v.body().as_bytes()),
    );

    // The sender's long-term public key, which is not a secret and is the one
    // case here whose subject is a `Box<[u8; N]>`. It earns its place twice over.
    //
    // First, it is the boxed counterpart of the `label` case: nothing but the
    // struct's derive wipes it, so it holds the derive against a field shape a
    // secret is very likely to arrive in — an ML-KEM decapsulation key or a
    // sealed-frame buffer added to this struct later would be exactly this shape.
    //
    // Second, it pins a claim in the struct's own doc comment that is easy to get
    // backwards, and that this file's author did get backwards once: zeroize 1.8
    // has no `Zeroize for Box<[u8; N]>`, only `Box<[Z]>` and `Box<str>`, so the
    // derive appears not to cover it — but `field.zeroize()` auto-derefs to the
    // `[u8; N]` inside, which is covered, and the heap block is cleared in place.
    // "Appears not to be covered, is covered" is exactly the kind of claim that
    // wants a test rather than a comment.
    //
    // The `Box` owns its whole block, so this is offset 0 of a `PK_LEN` block,
    // and the struct is left on the stack — the watched allocation is the box's,
    // not the struct's.
    assert_zeroed_when_freed(
        "VerifiedFirstContact::pk_lt",
        (0, ML_DSA_PK_BLOCK),
        || verified_first_contact("the body is not a secret".to_owned()),
        |v| at(v.pk_lt()),
    );
}

/// A secret held as a map **key** clears itself before its storage is released.
///
/// The shape neither the macro nor a containing derive can reach, and the reason
/// it needs its own case rather than a line in the sweep above: `zeroize` 1.8 has
/// no `Zeroize` impl for `BTreeMap`, so `Seeds` cannot carry a
/// `#[derive(ZeroizeOnDrop)]` that would cover this the way `PersistedCircle`'s
/// covers `entropy` and `label`. The wipe here comes from the key newtype's own
/// inner `Zeroizing`, reached when the map drops its keys (#358).
///
/// **What this case proves, stated narrowly, because the obvious stronger claim
/// is false.** It proves that a secret held as a map *key* holds zeros at the
/// instant its storage is released. It does **not** isolate the `Zeroizing`
/// wrapper as the cause.
///
/// The wrapper is the second of two independent wipes: `CircleSeenKey`'s own
/// `#[derive(Zeroize, ZeroizeOnDrop)]` clears a plain `String` field over its full
/// capacity without any help. The `PersistedCircle::label` case is the in-repo
/// control for that — a plain `String`, watched by this same witness, asserted
/// zeroed. So swapping this key's `Zeroizing<String>` for a `String` leaves the
/// wipe intact.
///
/// Mutating the wrapper away *does* turn this case red, but by the block-size
/// control rather than by an unwiped byte: copying out of `Zeroizing` goes through
/// `Vec::to_vec`, which allocates exact-fit, so the capacity collapses from
/// `CIRCLE_SEEN_KEY_CAP` to the phrase length and the freed block is the wrong
/// size. That red is a capacity artifact, not a wipe signal — worth knowing before
/// anyone reads it as one.
///
/// The mutation that *would* isolate the wipe — dropping the derives while moving
/// the `String` in, so capacity survives and nothing clears it — is already killed
/// at compile time by `assert_zeroize_on_drop::<CircleSeenKey>()` in
/// `secret_seed.rs`. Breadth there, depth here, exactly as the file header says.
///
/// Watched as its own heap block at offset 0, sized by the string's CAPACITY, the
/// same route `PersistedCircle::entropy` takes. Note the construction below hands
/// `set_circle_seen` an owned `String`, while production reaches it from the GUI
/// with a `&str` — that branch allocates exact-fit, so it would give this case no
/// capacity slack to assert on. The wipe is identical either way, because it is
/// the key's own drop that performs it; the owned form is used here only so the
/// block-size control has something to say.
///
/// Two further limits, since this file's header asks for them to be explicit: only
/// the live `len` bytes are snapshotted, so spare capacity past the phrase is never
/// read; and nothing here reaches copies made before the drop, or registers and
/// stack spills. The `Clone` half of #358 is covered by construction rather than
/// by this case — a clone's key is another `Zeroizing` with its own wiping drop.
#[test]
fn a_secret_used_as_a_map_key_zeroes_itself_before_its_memory_is_released() {
    init();

    assert_zeroed_when_freed(
        "Seeds::circle_seen key",
        (0, CIRCLE_SEEN_KEY_CAP),
        || {
            let mut phrase = String::with_capacity(CIRCLE_SEEN_KEY_CAP);
            phrase.push_str(CIRCLE_SEEN_PHRASE);
            assert_eq!(
                phrase.len(),
                CIRCLE_SEEN_PHRASE_LEN,
                "the phrase constant and its length have drifted apart"
            );
            let mut seeds = Seeds::new(Mnemonic::generate().expect("generate a mnemonic"));
            assert!(
                seeds.set_circle_seen(phrase, 1),
                "the entry must actually be inserted, or the watch has no subject"
            );
            seeds
        },
        |s| at(s.circle_seen_first_key_bytes_for_test()),
    );
}

/// The circle label, in a buffer with deliberate slack so its block size is
/// `CIRCLE_LABEL_CAP` rather than whatever an exact fit would give.
fn circle_label() -> String {
    let mut label = String::with_capacity(CIRCLE_LABEL_CAP);
    label.push_str(CIRCLE_LABEL_TEXT);
    label
}

/// One fully-populated witness, with the filler bytes the `ss0` case's structural
/// control depends on.
///
/// Built through the `testing`-gated constructor: the fields are private so that
/// holding a `VerifiedFirstContact` really is the proof of verification its doc
/// comment claims (#265), and `open` is no substitute here — it controls neither
/// the neighbouring byte patterns nor `body`'s capacity, which are exactly the two
/// structural controls these cases pin.
fn verified_first_contact(body: String) -> VerifiedFirstContact {
    VerifiedFirstContact::new_for_test(
        Box::new([0x11u8; PK_LEN]),
        Box::new([0x22u8; PK_LEN]),
        Box::new([0x33u8; EK_LEN]),
        7,
        1_700_000_000_000,
        body,
        [0xA5u8; SS0_LEN],
        ChannelRoots {
            ar: [0x44u8; ROOT_LEN],
            chan_id: [0x55u8; ROOT_LEN],
            rs0: CommittedRoot::from_bytes(&[0x66u8; ROOT_KEY_LEN]),
        },
    )
}

/// **`Rerooted`'s two publicly reachable secret halves wipe before their storage
/// is released, and its `Debug` renders none of them.**
///
/// A re-establishment's outputs are the successor retained root and the resumed
/// channel's identifier; the third, the re-rooted ratchet root, has no accessor
/// outside the crate and so cannot be located from here — it is a
/// `dm::ratchet::RootKey`, held by that type's own inline-arm wipe and by the
/// compile-time bound in `secret_seed.rs`.
///
/// **The structural control here is weaker than the `ss0` case's, deliberately
/// and unavoidably.** `Rerooted`'s fields are private, so `offset_of!` cannot
/// reach them from an integration test; the offsets below are measured off the
/// accessors on a probe instance. That means a mislocated accessor would agree
/// with its own measurement. What the case still holds is that the two fields
/// occupy *different, non-overlapping* ranges inside one struct and that each is
/// zero when the struct's block is freed — so a build that dropped either wipe,
/// or aliased the two fields onto one value, fails here.
#[test]
fn a_rerooted_pairs_secret_halves_are_zeroed_before_their_memory_is_released() {
    init();

    let make = || {
        Box::new(
            reroot(
                &CommittedRoot::from_bytes(&[0x5cu8; ROOT_KEY_LEN]),
                &[0x09u8; 32],
            )
            .expect("the crypto module is operational"),
        )
    };

    // Offsets measured on a probe, then asserted to be distinct and inside the
    // struct — see the note above on why they are not taken from `offset_of!`.
    //
    // **Under `GATE`, and that is not optional.** Building a probe allocates,
    // and `a_later_parse_error_does_not_strand_the_decoded_circle_entropy` arms
    // its watch on a block SIZE rather than an address — so an allocation of
    // that size from any other thread can satisfy its match and steal the
    // capture. The `inline_arm` case's note about churn being safe outside the
    // gate holds only for address-armed watches. The guard is dropped before
    // `assert_zeroed_when_freed`, which takes the same lock itself.
    let probe_gate = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let probe = make();
    let base = std::ptr::from_ref::<daemonseed_core::dm::resume::Rerooted>(&*probe) as usize;
    let next_at = probe.next().as_bytes().as_ptr() as usize - base;
    let chan_at = probe.chan_id().as_ptr() as usize - base;
    let width = size_of::<daemonseed_core::dm::resume::Rerooted>();
    assert_ne!(next_at, chan_at, "the two outputs alias one range");
    assert!(
        next_at + ROOT_KEY_LEN <= width && chan_at + ROOT_KEY_LEN <= width,
        "an output falls outside the struct: next at {next_at}, chan_id at {chan_at}, \
         struct {width} bytes"
    );
    assert_ne!(
        probe.next().as_bytes().as_slice(),
        probe.chan_id().as_slice(),
        "the successor root and the channel identifier are one value"
    );
    drop(probe);
    drop(probe_gate);

    assert_zeroed_when_freed("Rerooted::next", (next_at, width), make, |r| {
        at(r.next().as_bytes())
    });
    assert_zeroed_when_freed("Rerooted::chan_id", (chan_at, width), make, |r| {
        at(r.chan_id())
    });
}

/// **Neither multi-secret re-establishment type renders its contents.**
///
/// A `Debug` that printed a root would put it in every log line and every panic
/// message that carried the value, which is a disclosure path no wipe reaches.
/// Both types hand-write `Debug` rather than deriving it, so this is the test
/// that a derive re-added later fails.
#[test]
fn the_re_establishment_types_render_redacted() {
    init();
    // Held for the whole body: rendering and deriving both allocate, and a
    // size-armed watch in another case can be satisfied by any thread's
    // allocation of the right size. See the note in the case above.
    let _gate = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    let rerooted = reroot(
        &CommittedRoot::from_bytes(&[0x5cu8; ROOT_KEY_LEN]),
        &[0x09u8; 32],
    )
    .expect("the crypto module is operational");
    let rendered = format!("{rerooted:?}");
    assert_eq!(rendered, "Rerooted(<redacted>)");
    for (name, bytes) in [
        ("next", rerooted.next().as_bytes().as_slice()),
        ("chan_id", rerooted.chan_id().as_slice()),
    ] {
        assert!(
            !rendered.contains(&hex_of(bytes)),
            "Rerooted's Debug rendered {name}"
        );
    }

    let roots = ChannelRoots {
        ar: [0x44u8; ROOT_LEN],
        chan_id: [0x55u8; ROOT_LEN],
        rs0: CommittedRoot::from_bytes(&[0x66u8; ROOT_KEY_LEN]),
    };
    let rendered = format!("{roots:?}");
    assert_eq!(rendered, "ChannelRoots(<redacted>)");
    for (name, bytes) in [
        ("ar", roots.ar.as_slice()),
        ("chan_id", roots.chan_id.as_slice()),
        ("rs0", roots.rs0.as_bytes().as_slice()),
    ] {
        assert!(
            !rendered.contains(&hex_of(bytes)),
            "ChannelRoots's Debug rendered {name}"
        );
    }

    // Positive control: `hex_of` really does produce the needle these assertions
    // look for, so a rendering that DID leak would be caught rather than missed.
    assert!(hex_of(&[0x44u8; ROOT_LEN]).contains("4444"));
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

/// One record, filled with distinct non-zero patterns so a slip into a
/// neighbouring field is visible rather than reading as an incidental zero.
///
/// Every input is reachable from out here without a `testing` gate: `ResumeRecord`
/// already exposes `new`, `s_pc` and `committed_root` publicly. Only the *offset*
/// of the inline field needed gating (#314), because `offset_of!` cannot see a
/// private field from outside the crate.
fn resume_record() -> ResumeRecord {
    ResumeRecord::new(
        Box::new([0xA7; ML_DSA_SK_LEN]),
        Box::new([0xB3; PK_LEN]),
        CommittedRoot::from_bytes(&[0xC5; ROOT_KEY_LEN]),
        ReEstState {
            reconnect_gen: 9,
            attempt: 1,
            last_seen_re_est: 0,
            own: Some(OwnSlot::new(
                10,
                77,
                SealedReEst::seal(FreshAttempt::first(), vec![0xD1; 64].into_boxed_slice())
                    .expect("a 64-byte frame is inside MAX_FRAME_LEN"),
                EphemeralDecapKey::new(Box::new([0x3d; DK_LEN])),
            )),
            acceptance: None,
            confirm: None,
            attempt_at_window_start: 2,
            reroot_ratchet_gen: 0,
        },
        Retention {
            retained: Some(RetainedRoot::new(
                CommittedRoot::from_bytes(&[0xE9; ROOT_KEY_LEN]),
                1_700_000_000_000,
            )),
            dedup: DedupMemory::new(),
            stopped: false,
        },
        SendFloor::new(7, 11),
    )
}

/// Where the retained root's bytes sit inside the record.
///
/// `Retention` holds it behind an `Option`, so the offset cannot be computed
/// from `ResumeRecord`'s layout alone the way `committed_root`'s can. The
/// accessor gives the address of the bytes themselves, and the watch is set over
/// the record's whole allocation — containment is what matches, and the accessor
/// is what pins which bytes are being read.
fn retained_root_bytes(r: &ResumeRecord) -> &[u8] {
    r.retained()
        .expect("the fixture retains a superseded root")
        .root()
        .as_bytes()
}

/// **The two secret halves of `ResumeRecord` are wiped before their memory is
/// released (#314).**
///
/// `s_pc` is a per-correspondent ML-DSA-87 signing key that is at-rest only and
/// **not mnemonic-derivable**: there is no re-derivation path, which is why the key
/// is in the record rather than fetched on resume. A `#[zeroize(skip)]` added to it
/// by mistake compiles, passes the whole suite, and silently stops wiping it. That
/// is the hole this closes.
///
/// The two fields exercise the two arms for different reasons. `s_pc` is `Box`ed,
/// so it owns its allocation and is watched at offset 0 of its own block.
/// `committed_root` is inline, so it is watched as a range inside the record's own
/// block at a declared offset — the case where the offset assertion carries the
/// load, because containment matching alone would accept any enclosing block.
///
/// **The distinct fillers are a weaker control than they look**, exactly as the
/// `ss0` case above says of its own: a slip off `committed_root` inside the record
/// lands in `window_anchor_ms` (`1_700_000_000_000`, five zero high bytes) or
/// `toward_c` (`3`), and both snapshot as zeros. What refuses a mispointed accessor
/// is the offset assertion, not the fillers.
///
/// **They are not equally exposed, and #314's premise was half right.** Measured by
/// mutation while writing this:
///
/// - Adding `#[zeroize(skip)]` to `s_pc` **is** a silent leak, and this test catches
///   it — the freed block came back full of the filler byte. `Box<[u8; SK_LEN]>`
///   is a plain array with no `Drop` of its own, so the record's derive is the only
///   thing wiping it.
/// - Adding `#[zeroize(skip)]` to `committed_root` changes **nothing**, and the same
///   mutation passes. `CommittedRoot` comes from `redacted_secret_newtype`'s inline
///   arm, which derives `ZeroizeOnDrop` on the newtype itself, so it wipes on its own
///   drop whatever the outer derive says.
///
/// That second measurement is why `CommittedRoot` was added to `secret_seed.rs`'s
/// compile-time bound sweep in this same change: it was the ONE macro-generated
/// newtype of twenty missing from it, and this case cannot stand in for it. A
/// hand-rolled `CommittedRoot` deriving only `Zeroize` passes everything here,
/// because this witness only ever sees the root inside a `ResumeRecord` whose own
/// derive wipes it in place — while `CommittedRoot::from_bytes` is `pub` and the
/// type is dropped standalone on `decode`'s error paths. The behavioural case and
/// the compile-time bound cover different halves and neither substitutes.
///
/// So the `committed_root` case here is a behavioural confirmation rather than a
/// guard against a reachable defect: the surviving mutation is the correct answer,
/// not a gap. Recorded because a future reader who mutates it and sees it pass
/// should reach that conclusion in one step instead of hunting a hole that is not
/// there.
#[test]
fn resume_record_secret_halves_are_zeroed_before_their_memory_is_released() {
    init();

    assert_zeroed_when_freed(
        "ResumeRecord::s_pc",
        (0, ML_DSA_SK_LEN),
        resume_record,
        |r| at(r.s_pc()),
    );

    assert_zeroed_when_freed(
        "ResumeRecord::committed_root",
        (
            ResumeRecord::committed_root_offset_for_test(),
            size_of::<ResumeRecord>(),
        ),
        || Box::new(resume_record()),
        |r| at(r.committed_root().as_bytes()),
    );

    // **The retained `RS_n` is deliberately NOT a case here.** It sits inside an
    // `Option<RetainedRoot>` inside `Retention`, and this harness matches a freed
    // block against a fixed offset in the record's own allocation — a shape an
    // `Option` payload does not reliably present, so a case written here cannot
    // be shown to be watching the bytes it names rather than the neighbouring
    // `Vec` and flag. `dm::resume`'s
    // `zeroizing_a_retained_root_wipes_its_root_and_its_stamp` calls that impl
    // directly instead, which is a probe whose subject is not in doubt.
    //
    // The fixture still carries a retained root, because it strengthens the two
    // cases above: it puts a second root in the record, so a watch that drifted
    // onto it would read a different filler rather than an incidental zero.
}

/// **The controls: the `#[zeroize(skip)]` neighbours must still be readable right
/// up to the drop.**
///
/// Without this the test above proves less than it appears to. If `ResumeRecord`
/// wiped *everything* — or if the record were somehow never populated — the zero
/// assertions would pass while telling us nothing about which fields the derive
/// actually covers. `pk_pc` is the peer's PUBLIC verifying key and is deliberately
/// skipped; its bytes must survive, and reading them back distinguishes "the
/// secret was wiped" from "the whole record was blank".
#[test]
fn the_record_is_populated_before_any_drop_so_the_wipe_cases_have_a_control() {
    init();
    let r = resume_record();
    assert!(
        r.pk_pc().iter().all(|&b| b == 0xB3),
        "the skipped public field did not survive construction, so the zeroize \
         cases above have no control"
    );
    assert!(
        r.s_pc().iter().any(|&b| b != 0),
        "the signing key is all-zero before any drop, so wiping it proves nothing"
    );
    assert!(
        r.committed_root().as_bytes().iter().any(|&b| b != 0),
        "the committed root is all-zero before any drop, so wiping it proves nothing"
    );
    assert!(
        retained_root_bytes(&r).iter().all(|&b| b == 0xE9),
        "the retained root is not the fixture's pattern before any drop, so wiping \
         it proves nothing"
    );
    assert_ne!(
        retained_root_bytes(&r),
        r.committed_root().as_bytes(),
        "the two roots share a filler, so a watch on one could pass on the other"
    );
}
