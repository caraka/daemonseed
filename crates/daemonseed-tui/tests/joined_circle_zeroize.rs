//! Behavioural proof that the session copy of a circle phrase is cleared before
//! its buffer is handed back to the allocator (#268).
//!
//! `JoinedCircle::entropy` is the `cot_key` IKM (ISC-C8) held for the whole
//! session. #259 gave the at-rest form (`PersistedCircle::entropy`) and the GUI's
//! own copy a zeroizing container and named only those sites, so this one kept the
//! defect: a bare `String`, no wipe on drop, and a derived `Debug` that would print
//! the phrase.
//!
//! The method is `daemonseed-core`'s `tests/secret_zeroize_on_drop.rs`, reduced to
//! the single case this crate has. The reasoning is the same and worth restating,
//! because it is what makes the test sound rather than merely green: reading the
//! buffer *after* the drop would be a use-after-free, and the kind that proves
//! nothing — a just-freed block usually still holds its old bytes whether or not
//! anything wiped them. So the observation is taken at the only moment that is both
//! after the wipe and before the memory stops being ours, inside
//! `GlobalAlloc::dealloc`, where the allocator has been handed a still-valid
//! pointer and its exact layout.
//!
//! Being its own test binary is also what allows the `unsafe impl GlobalAlloc`
//! below: the library crate is `#![forbid(unsafe_code)]`, and the hook applies only
//! to this binary, never to the crate's ~200 unit tests.
//!
//! What this proves: at the instant the phrase's storage is released, it holds
//! zeros rather than the phrase. What it does not prove: anything about copies made
//! before the drop, or about registers and stack spills — no test in safe Rust can
//! reach those.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use daemonseed_tui::app::JoinedCircle;
use zeroize::Zeroizing;

/// Comfortably larger than the watched phrase.
const SNAPSHOT_CAP: usize = 1024;

/// The phrase this test watches, and the length and capacity of its buffer. They
/// differ on purpose: a production phrase is parsed out of user input or a decrypted
/// blob and can carry slack, so the watched buffer carries slack too rather than
/// being the exact-fit buffer `to_owned()` would give.
const PHRASE: &str = "correct horse battery staple correct horse battery staple";
const PHRASE_LEN: usize = PHRASE.len();
const PHRASE_CAP: usize = 96;

/// Address of the watched bytes, or 0 when disarmed. A live allocation is never at
/// address 0, so 0 is an unambiguous "off".
static WATCH_ADDR: AtomicUsize = AtomicUsize::new(0);
/// How many bytes from [`WATCH_ADDR`] to snapshot.
static WATCH_LEN: AtomicUsize = AtomicUsize::new(0);
/// Where the watched range sat inside the freed block, and how big that block was.
/// The structural half of the assertion: containment matching alone says nothing
/// about *which* block fired, so the case pins both and a mislocated watch fails
/// loudly instead of finding some other block that happens to contain the address.
static CAPTURED_OFFSET: AtomicUsize = AtomicUsize::new(0);
static CAPTURED_BLOCK: AtomicUsize = AtomicUsize::new(0);
/// Set once the watched block has actually been freed and snapshotted.
static CAPTURED: AtomicBool = AtomicBool::new(false);
/// Set when a watched range was carried through `realloc`, which disarms the watch.
/// Recorded so a missing capture is not misread as a leak.
static REALLOCATED: AtomicBool = AtomicBool::new(false);
/// The bytes the watched block held at the moment it was freed.
static SNAPSHOT: [AtomicU8; SNAPSHOT_CAP] = [const { AtomicU8::new(0) }; SNAPSHOT_CAP];

/// A pass-through allocator that copies one watched byte range out on its way to
/// `System::dealloc`.
struct FreeWitness;

/// Offset of the armed watch inside `[block, block + size)`, or `None` when the
/// watch is disarmed or its range does not lie wholly inside that block.
///
/// Whole-range containment is both the "is this the secret's block" test and the
/// bounds proof for every `ptr.add(offset + i)` read: `watched >= block` makes
/// `offset` the true difference, and the two length comparisons cannot underflow
/// given it.
fn watch_offset_in(block: usize, size: usize) -> Option<usize> {
    let watched = WATCH_ADDR.load(Ordering::SeqCst);
    let want = WATCH_LEN.load(Ordering::SeqCst);
    let offset = watched.wrapping_sub(block);
    (watched != 0 && watched >= block && offset <= size && want <= size - offset).then_some(offset)
}

// SAFETY: every method forwards to `System` with the pointer and layout it was
// given, unchanged. The only added work is reading bytes from a block the allocator
// has just been handed — still mapped, still ours. `dealloc` captures only when
// `watch_offset_in` says the whole watched range lies inside
// `[ptr, ptr + layout.size())`, which is what keeps every `ptr.add(offset + i)` in
// bounds; that range is the phrase's own fully-initialized storage. Nothing on this
// path allocates, so there is no re-entry into the allocator.
unsafe impl GlobalAlloc for FreeWitness {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // A watched `String` buffer CAN move. If it does, the old block may be
        // released here without ever reaching `dealloc`, leaving an armed watch
        // pointing at memory that is no longer the phrase's — and under containment
        // matching any larger block later handed out at that address would satisfy
        // it on ITS free, which is a false pass. So disarm, and record why.
        if watch_offset_in(ptr as usize, layout.size()).is_some() {
            WATCH_ADDR.store(0, Ordering::SeqCst);
            REALLOCATED.store(true, Ordering::SeqCst);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(offset) = watch_offset_in(ptr as usize, layout.size()) {
            // Disarm before snapshotting: once this block is back with the allocator
            // its address can be handed out again, and a later free of the reused
            // block must not overwrite what we saw.
            WATCH_ADDR.store(0, Ordering::SeqCst);

            let len = WATCH_LEN.load(Ordering::SeqCst).min(SNAPSHOT_CAP);
            for (i, slot) in SNAPSHOT.iter().enumerate().take(len) {
                // SAFETY: `offset + i < offset + len <= layout.size()`, so this stays
                // inside the block the allocator is being asked to free.
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

/// The session copy of a circle phrase is zeroed before its buffer is released.
///
/// Widening `JoinedCircle::entropy` back to a bare `String` leaves the whole suite
/// green but for this test.
///
/// No lock guards the watch, and it does not need one: this is the only test that
/// touches it, and the sibling test's allocation churn cannot fire it. A watch is
/// armed only while the phrase is still LIVE, so no block another thread frees in
/// that window can be one containing the watched address; address reuse becomes
/// possible only after the watched block is freed, by which point `dealloc` has
/// already disarmed.
#[test]
fn joined_circle_entropy_is_zeroed_before_its_memory_is_released() {
    let mut phrase = String::with_capacity(PHRASE_CAP);
    phrase.push_str(PHRASE);
    assert_eq!(phrase.len(), PHRASE_LEN);

    let circle = JoinedCircle::new(1, "Book Club", phrase);

    // A copy of the phrase to compare against what the allocator saw. It is a
    // duplicate of live secret material, so it zeroizes on its own drop — this test
    // has no business leaking what it exists to prove gets wiped.
    let (addr, len, before) = {
        let bytes = circle.entropy().as_bytes();
        (
            bytes.as_ptr() as usize,
            bytes.len(),
            Zeroizing::new(bytes.to_vec()),
        )
    };

    assert!(
        len <= SNAPSHOT_CAP,
        "the phrase exceeds the snapshot buffer"
    );
    // Control. Without it, an accessor pointing somewhere else — or a phrase that
    // was never stored — would sail through the zero assertion at the end.
    assert!(
        before.iter().any(|&b| b != 0),
        "the phrase is all-zero before the drop, so this test proves nothing"
    );

    WATCH_LEN.store(len, Ordering::SeqCst);
    WATCH_ADDR.store(addr, Ordering::SeqCst);

    drop(circle);

    // Second control. If no block enclosing the watched range were ever freed — a
    // leak, or the accessor pointing into some other allocation — the snapshot would
    // still read as the zeros it was initialised with, and this would pass vacuously.
    assert!(
        !REALLOCATED.load(Ordering::SeqCst),
        "the watched buffer was reallocated, which disarms the watch — nothing was \
         observed, and this test cannot conclude anything"
    );
    assert!(
        CAPTURED.load(Ordering::SeqCst),
        "no freed block ever wholly contained the watched bytes, so nothing was observed"
    );

    // Third control, and the structural one: the block that fired is the phrase's own
    // heap buffer, at its start. A `String` owns its whole block, so offset 0 — and
    // the block is the CAPACITY, which is also what proves the buffer genuinely
    // carried slack, i.e. that this is the production shape rather than an exact fit.
    assert_eq!(
        CAPTURED_OFFSET.load(Ordering::SeqCst),
        0,
        "the phrase was freed at a non-zero offset, so the accessor is not pointing \
         at the string's own buffer"
    );
    assert_eq!(
        CAPTURED_BLOCK.load(Ordering::SeqCst),
        PHRASE_CAP,
        "the freed block is not the size this test expects, so it is not the buffer \
         the phrase was supposed to live in"
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
        "freed memory still held the circle phrase: {seen:02x?}"
    );
}

/// The phrase must not reach a log surface either — `Zeroizing`'s own `Debug`
/// forwards to the value it wraps, so a derived `Debug` on `JoinedCircle` would
/// print it verbatim (#268, ISC-A-C1).
#[test]
fn joined_circle_never_debug_prints_its_phrase() {
    let circle = JoinedCircle::new(4, "Ops", PHRASE);

    // Control: the phrase really is on the value being rendered, so a rendering that
    // omits it is doing so by redaction and not because it was never there.
    assert_eq!(circle.entropy(), PHRASE);

    let rendered = format!("{circle:?}");
    assert!(
        !rendered.contains(PHRASE),
        "the circle phrase must never appear in Debug output: {rendered}"
    );
    // A substring, so a partial leak fails too.
    assert!(
        !rendered.contains("battery staple"),
        "no fragment of the circle phrase may appear in Debug output: {rendered}"
    );
    // And the redaction is a redaction, not an omission that hides a rename.
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(
        rendered.contains("Ops"),
        "the label is not a secret: {rendered}"
    );
}
