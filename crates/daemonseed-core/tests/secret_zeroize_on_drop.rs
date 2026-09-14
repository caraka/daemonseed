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
//! The witness also covers the secret-bearing struct the macro does not
//! generate: `PersistedCircle`. It is on `#[derive(Zeroize, ZeroizeOnDrop)]`
//! rather than a hand-written `Drop`, so the cases below watch every field it
//! stores on the heap, not the one field a hand-written `Drop` happened to name —
//! `entropy` AND `label`.
//!
//! That widening is the point of the change, and it is why `label` is watched at
//! all despite not being a secret. Under a hand-written `Drop` the test enumerated
//! the same field names the code did, so the two shared one assumption and a field
//! added to the struct was uncovered in both places at once. Under the derive
//! the default is a wipe, and `label` is the case that holds the default: it is
//! the field no author would think to add a `zeroize()` call for, and it is wiped.
//!
//! The struct carries no `#[zeroize(skip)]`, so every field is wiped and there is
//! no opt-out to review. The compile-time bound in `secret_seed.rs` names it.
//!
//! The witness fires on any freed block that wholly contains the watched range and
//! snapshots from the watched address rather than from the block start, so a watch
//! can be a range inside a block. Because containment matching
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
//! freed, so nothing here observes it; no case in this file can go red on it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use daemonseed_core::circle::key::{
    derive_circle_presence_veilid_owner_seed, derive_circle_veilid_owner_seed,
};
use daemonseed_core::crypto::suite::CNSA_2_0;
use daemonseed_core::identity::keys::{Identity, derive_identity_keys};
use daemonseed_core::identity::mnemonic::Mnemonic;
use daemonseed_core::public_room::derive_room_veilid_owner_seed;
use daemonseed_core::storage::seeds::{
    DecodedSecretBuffer, PersistedCircle, Seeds, observe_decoded_secret_buffers,
};
use zeroize::Zeroizing;

/// Large enough for the biggest secret watched here, the decode buffer case's
/// `DECODE_SECRET_LEN`.
///
/// `assert_zeroed_when_freed` refuses a secret longer than this rather than
/// truncating it — a truncating snapshot would compare only the first bytes and
/// pass while the tail went unexamined.
const SNAPSHOT_CAP: usize = DECODE_SECRET_LEN;

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
/// capacities (96, 72, 128): every watch here is armed by address, so a
/// same-sized allocation elsewhere cannot be mistaken for it.
///
/// The phrase text differs from `PersistedCircle`'s because both hold the same
/// *kind* of secret, and a snapshot matching the wrong one would otherwise read as
/// a pass.
const CIRCLE_SEEN_PHRASE: &str = "a different phrase for the read high-water key";
const CIRCLE_SEEN_PHRASE_LEN: usize = 46;
const CIRCLE_SEEN_KEY_CAP: usize = 80;

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
/// How many bytes were snapshotted, recorded at the moment of the snapshot.
///
/// Read instead of [`WATCH_LEN`], which by then may describe a later arming while
/// [`SNAPSHOT`] still holds the first capture — a pair that would report one
/// buffer's bytes under another's length.
static CAPTURED_LEN: AtomicUsize = AtomicUsize::new(0);
/// Every block this allocator has released, counted. A monotonic clock over
/// frees, so two frees can be ordered against each other without recording when
/// either happened.
static FREES: AtomicUsize = AtomicUsize::new(0);
/// The value of [`FREES`] at the moment the watched block was snapshotted.
static CAPTURED_AT_FREE: AtomicUsize = AtomicUsize::new(0);
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
///
/// `want` is the watched length, passed in rather than loaded here so a caller
/// that then reads the block uses the same value it was bounds-checked against.
/// Loading it twice would let a re-arming between the two loads produce a length
/// the containment test never approved.
fn watch_offset_in(block: usize, size: usize, want: usize) -> Option<usize> {
    let watched = WATCH_ADDR.load(Ordering::SeqCst);
    let offset = watched.wrapping_sub(block);
    (watched != 0 && watched >= block && offset <= size && want <= size - offset).then_some(offset)
}

/// How many decode buffers have been reported since the watch was reset.
///
/// A structural assertion for the cases that read it: a secret hex decode holds
/// its plaintext in two buffers in turn, so a count that is not two means the
/// decode no longer has the shape the case names.
static REPORTS: AtomicUsize = AtomicUsize::new(0);

/// Which of the decode's two buffers the current run watches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Watched {
    /// The buffer the decode returns, still live when a later field fails.
    Returned,
    /// The buffer the decode writes into, released before it returns.
    Scratch,
}

/// Set when the run watches [`Watched::Scratch`] rather than the returned buffer.
static WATCH_SCRATCH: AtomicBool = AtomicBool::new(false);

/// The address the watch was armed on, kept after `dealloc` clears
/// [`WATCH_ADDR`] so a case can still say which buffer it watched.
static ARMED_ADDR: AtomicUsize = AtomicUsize::new(0);
/// The address reported for the scratch buffer, and the value of [`FREES`] when
/// that report was made.
static SCRATCH_ADDR: AtomicUsize = AtomicUsize::new(0);
static SCRATCH_REPORTED_AT_FREE: AtomicUsize = AtomicUsize::new(0);
/// The value of [`FREES`] when the block at [`SCRATCH_ADDR`] was released, or 0
/// if it has not been.
static SCRATCH_FREED_AT: AtomicUsize = AtomicUsize::new(0);

/// Set while a case wants the arming of the watch to wait for the churn thread,
/// and set to the outcome of that wait.
static STRESS_WINDOW: AtomicBool = AtomicBool::new(false);
static CHURN_ADVANCED_WHILE_ARMED: AtomicBool = AtomicBool::new(false);
/// Rounds of same-sized allocation the churn thread has completed.
static CHURN_ROUNDS: AtomicUsize = AtomicUsize::new(0);
/// How long the arming will wait for the churn thread before giving up. Large
/// enough that only a churn thread which is not running can exhaust it.
const CHURN_SPIN_BOUND: u64 = 10_000_000;

/// Wait for the churn thread to complete at least one more round, so the watch is
/// provably armed while another thread is allocating blocks of the secret's
/// length. `false` means the bound expired.
///
/// Reads one atomic in a loop and allocates nothing, which is what the observer
/// contract requires of anything called from inside the decode.
fn wait_for_churn_round() -> bool {
    let start = CHURN_ROUNDS.load(Ordering::SeqCst);
    for _ in 0..CHURN_SPIN_BOUND {
        if CHURN_ROUNDS.load(Ordering::SeqCst) > start {
            return true;
        }
        std::hint::spin_loop();
    }
    false
}

/// Point the watch at the buffer a report names, and count every report.
///
/// The cases above all hold the secret in a value the test constructs, so they
/// arm by taking its address. #343's secret is different in kind: it is decoded
/// and dropped entirely *inside* `Seeds::from_plaintext`, on an error path, and it
/// never escapes for a test to point at. The decode reports each buffer it holds
/// that secret in while the buffer is still live, and this arms the watch on the
/// one the report identifies — so the watched block is the decode's own, named by
/// address. Nothing else in the process can be mistaken for it, whatever it
/// allocates and at whatever size, and nothing else reallocates it.
///
/// Most runs watch the returned buffer, which is the one still live when the
/// later field fails. The scratch buffer is released before the decode returns,
/// so a watch on it says nothing about the parser's error path — it has its own
/// case instead, which asserts what that buffer holds when it goes back.
///
/// Both reports are recorded whichever is watched. The scratch address and the
/// free-clock reading at each report are what let a case state that the two
/// buffers are different blocks and that they were released in the order the
/// decode's shape implies — an ordering a run that has merely captured zeros at
/// offset 0 of a right-sized block cannot distinguish.
///
/// Allocates nothing and takes no lock, so it is safe to run from inside the
/// decode with a watch already live.
fn arm_on_reported_buffer(kind: DecodedSecretBuffer, addr: usize, len: usize) {
    REPORTS.fetch_add(1, Ordering::SeqCst);
    let frees = FREES.load(Ordering::SeqCst);
    if kind == DecodedSecretBuffer::Scratch {
        SCRATCH_ADDR.store(addr, Ordering::SeqCst);
        SCRATCH_REPORTED_AT_FREE.store(frees, Ordering::SeqCst);
    }

    let wanted = if WATCH_SCRATCH.load(Ordering::SeqCst) {
        DecodedSecretBuffer::Scratch
    } else {
        DecodedSecretBuffer::Returned
    };
    if kind != wanted {
        return;
    }

    // Disarm before re-arming: between the two stores the length and the address
    // describe different blocks, and a free landing there would be bounds-checked
    // against a length that is not this block's.
    WATCH_ADDR.store(0, Ordering::SeqCst);
    WATCH_LEN.store(len, Ordering::SeqCst);
    ARMED_ADDR.store(addr, Ordering::SeqCst);
    WATCH_ADDR.store(addr, Ordering::SeqCst);

    if STRESS_WINDOW.load(Ordering::SeqCst) {
        CHURN_ADVANCED_WHILE_ARMED.store(wait_for_churn_round(), Ordering::SeqCst);
    }
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
        let want = WATCH_LEN.load(Ordering::SeqCst);
        if watch_offset_in(ptr as usize, layout.size(), want).is_some() {
            WATCH_ADDR.store(0, Ordering::SeqCst);
            REALLOCATED.store(true, Ordering::SeqCst);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let frees = FREES.fetch_add(1, Ordering::SeqCst) + 1;

        // The scratch buffer going back. Recorded once, so a block later handed
        // out at the same address cannot overwrite the reading.
        let scratch = SCRATCH_ADDR.load(Ordering::SeqCst);
        if scratch != 0 && ptr as usize == scratch && SCRATCH_FREED_AT.load(Ordering::SeqCst) == 0 {
            SCRATCH_FREED_AT.store(frees, Ordering::SeqCst);
        }

        // Loaded once, and the same value bounds the read below. Loading it again
        // for the loop would read past the block if an arming in between raised it
        // while `WATCH_ADDR` still named this one.
        let want = WATCH_LEN.load(Ordering::SeqCst);
        if let Some(offset) = watch_offset_in(ptr as usize, layout.size(), want) {
            // Disarm before snapshotting: once this block is back with the
            // allocator its address can be handed out again, and a later free of
            // the reused block must not overwrite what we saw.
            WATCH_ADDR.store(0, Ordering::SeqCst);

            let len = want.min(SNAPSHOT_CAP);
            for (i, slot) in SNAPSHOT.iter().enumerate().take(len) {
                // SAFETY: `offset + i < offset + len <= layout.size()`, so this
                // stays inside the block the allocator is being asked to free.
                slot.store(unsafe { *ptr.add(offset + i) }, Ordering::SeqCst);
            }
            CAPTURED_OFFSET.store(offset, Ordering::SeqCst);
            CAPTURED_BLOCK.store(layout.size(), Ordering::SeqCst);
            CAPTURED_LEN.store(want, Ordering::SeqCst);
            CAPTURED_AT_FREE.store(frees, Ordering::SeqCst);
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
/// The length is free to be anything the snapshot buffer can hold. The watch is
/// armed on the address the decode reports, not on an allocation size, so a
/// length that collides with unrelated allocations costs nothing and a length
/// whose buffer is grown past it cannot hide the buffer from the watch.
///
/// A 4 096-byte circle entropy is not a realistic phrase, and does not need to
/// be: the parser applies no length rule, and what is under test is the buffer's
/// lifetime, not its contents. It is within `SNAPSHOT_CAP`.
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

/// What the watched decode buffer looked like on its way back to the allocator.
struct FreedBuffer {
    /// The bytes the watched range held at the moment its block was freed.
    bytes: Zeroizing<Vec<u8>>,
    /// Where the watched range sat inside the freed block.
    offset: usize,
    /// How big the freed block was.
    block: usize,
    /// How many decode buffers were reported over the run.
    reports: usize,
    /// The address the watch was armed on.
    armed_addr: usize,
    /// The address reported for the scratch buffer, and the free-clock readings
    /// at its report, at its release, and at the watched block's snapshot.
    scratch_addr: usize,
    scratch_reported_at: usize,
    scratch_freed_at: usize,
    captured_at: usize,
}

/// Run `body` with the watch armed on whatever decode buffer is reported to
/// [`arm_on_reported_buffer`], and hand back what that block held when it was
/// freed.
///
/// `Err` means the run observed nothing — which every caller must treat as
/// inconclusive rather than as a pass, since an unobserved block proves nothing
/// about its contents. The two reasons are reported separately because they call
/// for different fixes: a reallocation means the watch was disarmed mid-flight,
/// while nothing captured means no freed block ever contained the reported
/// buffer. Each message carries the number of buffers reported, which separates
/// "the decode never ran, or reported nothing" from "it reported and the watch
/// still saw no free".
fn freed_bytes_of_reported_decode_buffer(
    watched: Watched,
    body: impl FnOnce(),
) -> Result<FreedBuffer, String> {
    let _gate = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    WATCH_ADDR.store(0, Ordering::SeqCst);
    WATCH_LEN.store(0, Ordering::SeqCst);
    CAPTURED.store(false, Ordering::SeqCst);
    REALLOCATED.store(false, Ordering::SeqCst);
    CAPTURED_OFFSET.store(0, Ordering::SeqCst);
    CAPTURED_BLOCK.store(0, Ordering::SeqCst);
    CAPTURED_LEN.store(0, Ordering::SeqCst);
    CAPTURED_AT_FREE.store(0, Ordering::SeqCst);
    ARMED_ADDR.store(0, Ordering::SeqCst);
    SCRATCH_ADDR.store(0, Ordering::SeqCst);
    SCRATCH_REPORTED_AT_FREE.store(0, Ordering::SeqCst);
    SCRATCH_FREED_AT.store(0, Ordering::SeqCst);
    REPORTS.store(0, Ordering::SeqCst);
    WATCH_SCRATCH.store(watched == Watched::Scratch, Ordering::SeqCst);
    observe_decoded_secret_buffers(Some(arm_on_reported_buffer));

    body();

    observe_decoded_secret_buffers(None);
    WATCH_ADDR.store(0, Ordering::SeqCst);
    WATCH_SCRATCH.store(false, Ordering::SeqCst);
    let reports = REPORTS.swap(0, Ordering::SeqCst);
    let len = CAPTURED_LEN.load(Ordering::SeqCst);

    if REALLOCATED.load(Ordering::SeqCst) {
        return Err(format!(
            "the watched buffer was reallocated, which disarms the watch; \
             {reports} decode buffers were reported"
        ));
    }
    if !CAPTURED.load(Ordering::SeqCst) {
        return Err(format!(
            "no freed block ever contained the reported buffer; {reports} decode \
             buffers were reported"
        ));
    }
    // A guard for a secret longer than any case here reports, and so a branch no
    // case exercises: every report is `DECODE_SECRET_LEN` and the snapshot buffer
    // is larger than that.
    if len > SNAPSHOT_CAP {
        return Err(format!(
            "the reported buffer is {len} bytes, past the {SNAPSHOT_CAP}-byte \
             snapshot buffer, so only part of it was recorded; {reports} decode \
             buffers were reported"
        ));
    }
    Ok(FreedBuffer {
        bytes: Zeroizing::new(
            SNAPSHOT
                .iter()
                .take(len)
                .map(|b| b.load(Ordering::SeqCst))
                .collect::<Vec<u8>>(),
        ),
        offset: CAPTURED_OFFSET.load(Ordering::SeqCst),
        block: CAPTURED_BLOCK.load(Ordering::SeqCst),
        reports,
        armed_addr: ARMED_ADDR.load(Ordering::SeqCst),
        scratch_addr: SCRATCH_ADDR.load(Ordering::SeqCst),
        scratch_reported_at: SCRATCH_REPORTED_AT_FREE.load(Ordering::SeqCst),
        scratch_freed_at: SCRATCH_FREED_AT.load(Ordering::SeqCst),
        captured_at: CAPTURED_AT_FREE.load(Ordering::SeqCst),
    })
}

/// The mirror control for the case below, and it must fail if the watch is broken.
///
/// Deliberately leaks the secret the way the parser used to: a plain `String`
/// dropped with its bytes intact. It is armed through the same function the
/// decode's observer calls, with the same argument shape, so it exercises every
/// step the real case depends on except the decode's own call. If arming on a
/// reported buffer works at all, this run captures those bytes — so a green
/// result here is what licenses reading the real case's "no secret in the freed
/// block" as evidence rather than as silence. Without it, a watch that never
/// fired would make the real case pass for the wrong reason.
#[test]
fn the_reported_buffer_watch_captures_a_secret_that_is_not_wiped() {
    init();
    let needle = decode_secret();

    let freed = freed_bytes_of_reported_decode_buffer(Watched::Returned, || {
        // A bare `String`, dropped without wiping — the pre-#343 shape,
        // reproduced on purpose. `clone` allocates an exact fit, so the block
        // freed is the string's own bytes and nothing else.
        let leaked: String = needle.clone();
        arm_on_reported_buffer(
            DecodedSecretBuffer::Returned,
            leaked.as_ptr() as usize,
            leaked.len(),
        );
        drop(leaked);
    })
    .unwrap_or_else(|why| {
        panic!("the control observed nothing ({why}), so no case here can conclude anything")
    });

    assert_eq!(
        freed.reports, 1,
        "the control reports exactly one buffer; a different count means it is \
         not the single-buffer case it is written as"
    );
    assert_eq!(
        (freed.offset, freed.block),
        (0, DECODE_SECRET_LEN),
        "the control's buffer owns its whole block, so it must be freed at \
         offset 0 of a block its own length"
    );
    assert_eq!(
        freed.bytes.len(),
        DECODE_SECRET_LEN,
        "the control snapshotted a different number of bytes than it armed on"
    );
    assert_eq!(
        freed.bytes.as_slice(),
        needle.as_bytes(),
        "the control did not recover the bytes it deliberately leaked, so the \
         watch is not observing what it claims to"
    );
}

/// The decode dispatches to the observer on the path that succeeds, not only on
/// the one that fails.
///
/// The cases either side of this one reach the observer through a payload whose
/// label is malformed, so all of them would stay green on a decode that reported
/// only while unwinding, or on a harness that reported from somewhere other than
/// the decode. This runs a payload that parses cleanly and asserts the same two
/// reports arrive — which is what says the reports come from the decode itself.
#[test]
fn a_successful_parse_reports_both_decode_buffers() {
    init();
    let needle = decode_secret();
    let payload = format!(
        "{RECOVERY_PHRASE}\ncircle {} {}\n",
        hex_of(needle.as_bytes()),
        hex_of(b"a circle label"),
    );

    let _gate = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    WATCH_ADDR.store(0, Ordering::SeqCst);
    WATCH_LEN.store(0, Ordering::SeqCst);
    REPORTS.store(0, Ordering::SeqCst);
    observe_decoded_secret_buffers(Some(arm_on_reported_buffer));

    let parsed = Seeds::parse_plaintext_for_witness(&payload);

    observe_decoded_secret_buffers(None);
    WATCH_ADDR.store(0, Ordering::SeqCst);
    let reports = REPORTS.swap(0, Ordering::SeqCst);

    assert!(
        parsed.is_ok(),
        "the payload this case is built on must parse cleanly, and it did not: \
         {parsed:?}"
    );
    assert_eq!(
        reports, 2,
        "a clean parse of one circle line reports the decode's two buffers; \
         {reports} means the decode is not reporting on the path that succeeds"
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
    let payload = parse_error_payload(&needle);

    let freed = freed_bytes_of_reported_decode_buffer(Watched::Returned, || {
        assert_bad_label(parse_with_bad_label(&payload));
    })
    .unwrap_or_else(|why| {
        panic!(
            "this case observed nothing ({why}).\n\nThat is a FAILURE, not a skip. \
                 The watch is armed on the buffer the secret hex decode reports, and \
                 the fix is what makes one exist: the decode writes into a right-sized \
                 `Zeroizing` buffer and reports it. Without it the parser decodes \
                 through `hex::decode`, which grows geometrically — so the secret \
                 reaches a ladder of freed intermediate copies, none of which is \
                 reported and none of which is wiped. Seeing nothing here means the \
                 exact-size zeroizing buffer is gone."
        )
    });

    assert_decoded_entropy_was_wiped(&freed, &needle);
}

/// The same case, run with another thread allocating, growing and freeing blocks
/// of exactly the secret's length for the whole time the watch is armed.
///
/// A watch armed on the first allocation of a chosen size can be taken by any
/// other allocation of that size, and a growth of the block it settled on
/// disarms it — so a case armed that way is only as reliable as the rest of the
/// process is quiet, and fails intermittently when it is not. Arming on the
/// buffer the decode reports removes both hazards: the address names one live
/// block, no other allocation shares it, and nothing else grows it. This is what
/// holds that claim to a run where the collision is guaranteed rather than
/// occasional.
///
/// The churn thread deliberately does **not** take `GATE`. Serialising it would
/// remove the very interference the case exists to survive.
///
/// The overlap is made deterministic rather than left to the scheduler: the
/// arming of the watch itself waits for the churn thread to complete a further
/// round before the decode is allowed to continue, so the interference is known
/// to have happened inside the armed window rather than merely somewhere in the
/// case. Nothing in the body panics, so the churn thread is always stopped and
/// joined.
#[test]
fn the_parse_error_case_holds_under_concurrent_same_sized_allocation() {
    init();
    let needle = decode_secret();
    let payload = parse_error_payload(&needle);

    let stop = Arc::new(AtomicBool::new(false));
    CHURN_ROUNDS.store(0, Ordering::SeqCst);
    CHURN_ADVANCED_WHILE_ARMED.store(false, Ordering::SeqCst);
    let churn = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                // Allocate at the secret's exact length, grow it — which is the
                // shape that disarms a watch pointing into it — then free both.
                let mut block = vec![0xEFu8; DECODE_SECRET_LEN];
                block.push(0xEF);
                CHURN_ROUNDS.fetch_add(1, Ordering::SeqCst);
                drop(block);
            }
        })
    };

    // Wait for the churn thread to be allocating before the body starts. Its loop
    // ends only when `stop` is set, which happens after the body returns, so a
    // non-zero count here means it was running for the whole of the body.
    while CHURN_ROUNDS.load(Ordering::SeqCst) == 0 {
        std::thread::yield_now();
    }
    let before = CHURN_ROUNDS.load(Ordering::SeqCst);

    // The body asserts nothing: a panic inside it would skip the stop below and
    // leave the churn thread spinning for the rest of the binary. It carries the
    // parse result out instead, and the variant is checked once the thread is
    // joined.
    let mut outcome = None;
    STRESS_WINDOW.store(true, Ordering::SeqCst);
    let freed = freed_bytes_of_reported_decode_buffer(Watched::Returned, || {
        outcome = Some(parse_with_bad_label(&payload));
    });
    STRESS_WINDOW.store(false, Ordering::SeqCst);

    stop.store(true, Ordering::SeqCst);
    churn.join().expect("the churn thread finished");
    let total = CHURN_ROUNDS.load(Ordering::SeqCst);

    assert_bad_label(outcome.expect("the body ran"));

    // Positive control on the interference itself. A churn thread that never
    // started, or that exited before the body ran, would leave this case
    // asserting exactly what the quiet case already does while reading as the
    // stronger claim.
    assert!(
        before > 0,
        "the churn thread had allocated nothing when the body began ({total} \
         rounds in total), so this case did not test what it names"
    );
    assert!(
        total > before,
        "the churn thread completed no round after the body began ({before} \
         rounds before, {total} in total), so nothing interfered with the watch"
    );
    assert!(
        CHURN_ADVANCED_WHILE_ARMED.load(Ordering::SeqCst),
        "the watch was armed and the churn thread completed no round within \
         {CHURN_SPIN_BOUND} spins, so the case cannot say the interference \
         overlapped the armed window"
    );

    let freed = freed.unwrap_or_else(|why| {
        panic!(
            "this case observed nothing ({why}) while another thread allocated \
             blocks of the secret's length. The watch is armed on the address the \
             decode reports, so no other allocation can take it and no other \
             thread's growth can disarm it — seeing nothing here means the watch \
             is armed on something other than the decode's own buffer."
        )
    });

    assert_decoded_entropy_was_wiped(&freed, &needle);
}

/// The recovery phrase every payload here opens with.
const RECOVERY_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art";

/// The payload the #343 cases parse: valid entropy hex, malformed label hex.
///
/// `zz` is not hex, so the label decode fails *after* the entropy has been
/// decoded and while it is still live.
fn parse_error_payload(needle: &str) -> String {
    format!(
        "{RECOVERY_PHRASE}\ncircle {} zz\n",
        hex_of(needle.as_bytes()),
    )
}

/// Parse that payload, handing the result back rather than judging it.
///
/// The verdict is [`assert_bad_label`]'s, and it is separate because a caller
/// that has a thread to stop must do so before anything can panic.
fn parse_with_bad_label(
    payload: &str,
) -> Result<Seeds, daemonseed_core::storage::seeds::BlobError> {
    Seeds::parse_plaintext_for_witness(payload)
}

/// Require the exact error the malformed label produces.
///
/// Pinned to the exact variant, not merely `is_err()`. A mnemonic that failed to
/// parse would also be an error, and would return *before* the circle line —
/// leaving the case watching a path the secret never reaches, which reads as a
/// pass once the watch is arranged correctly.
fn assert_bad_label(parsed: Result<Seeds, daemonseed_core::storage::seeds::BlobError>) {
    assert!(
        matches!(
            parsed,
            Err(daemonseed_core::storage::seeds::BlobError::InvalidPlaintext)
        ),
        "expected InvalidPlaintext from the malformed label hex, got {parsed:?} \
         — this case is not exercising the error path it names"
    );
}

/// The scratch buffer a secret hex decode writes into is zeroed before its
/// memory is released.
///
/// The other #343 cases watch the buffer the decode returns, and every one of
/// them stays green on a decode whose scratch buffer is a bare `Vec<u8>` — that
/// buffer is released before the decode returns, so nothing they observe touches
/// it, and it would carry the whole plaintext back to the allocator intact. This
/// case is what holds it.
#[test]
fn the_decodes_scratch_buffer_is_zeroed_before_its_memory_is_released() {
    init();
    let needle = decode_secret();
    let payload = parse_error_payload(&needle);

    let freed = freed_bytes_of_reported_decode_buffer(Watched::Scratch, || {
        assert_bad_label(parse_with_bad_label(&payload));
    })
    .unwrap_or_else(|why| {
        panic!(
            "this case observed nothing ({why}). The watch is armed on the \
             scratch buffer the decode reports, so seeing nothing means the \
             decode no longer writes into a buffer of its own."
        )
    });

    assert_eq!(
        freed.reports, 2,
        "the decode reports its scratch buffer and its returned copy; {} means \
         this case is not watching the buffer it names",
        freed.reports
    );
    assert_eq!(
        freed.armed_addr, freed.scratch_addr,
        "the watch was armed on a block other than the reported scratch buffer"
    );
    assert_eq!(
        (freed.offset, freed.block),
        (0, DECODE_SECRET_LEN),
        "the scratch buffer owns its whole block, so it must be freed at offset \
         0 of a block its own length"
    );
    assert_eq!(
        freed.bytes.len(),
        DECODE_SECRET_LEN,
        "fewer bytes were snapshotted than the scratch buffer holds, so the \
         zero assertion below covers only part of it"
    );
    assert_ne!(
        freed.bytes.as_slice(),
        needle.as_bytes(),
        "the decode's scratch buffer went back to the allocator holding the \
         plaintext it decoded"
    );
    assert!(
        freed.bytes.iter().all(|&b| b == 0),
        "the freed scratch block held something other than zeros: {:02x?}",
        freed.bytes.as_slice()
    );
}

/// The assertions both #343 cases make about the buffer the decode reported.
fn assert_decoded_entropy_was_wiped(freed: &FreedBuffer, needle: &str) {
    assert_eq!(
        freed.reports, 2,
        "a secret hex decode holds its plaintext in two buffers in turn — the \
         scratch buffer it writes into and the exact-fit copy it returns — and \
         this run saw {}. A different count means the decode no longer sizes its \
         own buffer, so the secret reaches freed intermediate copies that nothing \
         reports and nothing wipes",
        freed.reports
    );
    assert_eq!(
        (freed.offset, freed.block),
        (0, DECODE_SECRET_LEN),
        "the returned buffer owns its whole block, so it must be freed at offset \
         0 of a block its own length; a different pair means the watch settled on \
         some other allocation that merely contains the address"
    );
    // Both buffers are exact-fit blocks freed at offset 0 holding zeros, so
    // everything above is satisfied by either of them. These three separate
    // them: they are different blocks, and the scratch is the one released
    // first, since the decode drops it only after handing the copy back.
    assert_ne!(
        freed.armed_addr, freed.scratch_addr,
        "the watched buffer and the scratch buffer are the same block, so the \
         decode is reporting one allocation under both names"
    );
    assert!(
        freed.scratch_freed_at > freed.scratch_reported_at,
        "the scratch block was released before it was reported (reported at \
         free {}, released at free {}), so the address it reported was not its \
         own live buffer",
        freed.scratch_reported_at,
        freed.scratch_freed_at
    );
    assert!(
        freed.scratch_freed_at < freed.captured_at,
        "the watched block was released before the scratch block (watched at \
         free {}, scratch at free {}), which is the order the decode produces \
         only if the two are reported the other way round — so the watch is on \
         the scratch buffer rather than the copy that outlives the decode",
        freed.captured_at,
        freed.scratch_freed_at
    );
    assert_eq!(
        freed.bytes.len(),
        DECODE_SECRET_LEN,
        "fewer bytes were snapshotted than the secret holds, so the zero \
         assertion below covers only part of the freed block — and at zero \
         bytes it covers none of it"
    );
    assert_ne!(
        freed.bytes.as_slice(),
        needle.as_bytes(),
        "the decoded circle entropy was still in freed memory: the parser's \
         error path released it without wiping"
    );
    assert!(
        freed.bytes.iter().all(|&b| b == 0),
        "the freed block held something other than zeros after the parse error: {:02x?}",
        freed.bytes.as_slice()
    );
}

/// The boxed arm, across three modules that use it, clears its heap buffer
/// before releasing it.
///
/// Three of the boxed types, chosen for being cheap to construct from outside the
/// crate. The property under test is the macro arm's, not each type's — every
/// boxed type is the same expansion — and the rest are held to it by the
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
}

/// The inline arm keeps its secret in the value itself, so it is observed by
/// moving a real identity-rooted secret into a `Box`: that puts the inline
/// `[u8; 32]` inside a heap block the witness can watch. The wrapper's `Drop`
/// wipes the array in place, and only then is the block released.
///
/// All four identity-rooted secrets come from one derivation, so this covers
/// every inline-family secret that has a public constructor — with one caveat
/// since #271: `VeilidNodeSeed` and `DmChannelRootSecret` are on the
/// `inline_scoped` arm rather than `inline`, so their cases here prove the
/// *scoped* arm's expansion, not this one's.
/// The two arms share their storage, `Zeroize` and `ZeroizeOnDrop` derives, which
/// is why they are witnessed together, but a change to one does not move the
/// other.
#[test]
fn inline_arm_secrets_are_zeroed_before_their_memory_is_released() {
    init();

    // Heavy allocation churn, and it needs no gate. Every watch in this file
    // names one address, and a watch is armed only while its own secret is live
    // — so a block allocated or freed here is never the watched one, whatever
    // its size. One derivation feeds all three cases below, each of which takes
    // the gate itself.
    let mnemonic = Mnemonic::generate().unwrap();
    let keys = derive_identity_keys(&mnemonic, Identity::Primary).unwrap();

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
    assert_zeroed_when_freed(
        "DmChannelRootSecret",
        (0, SEED_LEN),
        || Box::new(keys.dm_channel_root),
        |s| s.with_bytes(|b| at(b)),
    );
}

/// Every heap-resident field of the multi-field secret struct is zeroed before its
/// storage is released.
///
/// The site the macro does not generate. The struct carries
/// `#[derive(Zeroize, ZeroizeOnDrop)]`, so the case list is driven by what it
/// actually stores rather than by which fields a hand-written `Drop`
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
        watch_offset_in(addr, phrase.capacity(), WATCH_LEN.load(Ordering::SeqCst)),
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
