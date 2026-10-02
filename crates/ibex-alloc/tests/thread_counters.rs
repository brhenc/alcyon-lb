//! `thread_alloc_counters` counts the calling thread only, through every allocator entry.

use ibex_alloc::{thread_alloc_counters, CountingAllocator};

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator::new();

#[test]
fn counts_this_threads_allocations_and_not_another_threads() {
    let before = thread_alloc_counters();
    let mut v: Vec<u8> = Vec::with_capacity(64);
    v.extend_from_slice(&[1; 64]);
    v.reserve_exact(1024); // realloc, growing
    v.truncate(8);
    v.shrink_to_fit(); // realloc, shrinking
    drop(v);
    let d = before.diff(&thread_alloc_counters());
    assert_eq!((d.alloc_count, d.realloc_count, d.dealloc_count), (1, 2, 1), "{d:?}");
    assert_eq!(d.bytes_allocated, 64 + 1024, "{d:?}");
    assert_eq!(d.bytes_deallocated, (64 + 1024 - 8) + 8, "{d:?}");

    // Spawning allocates here; the other thread's allocation happens between the two
    // snapshots, while this thread only touches atomics.
    use std::sync::atomic::{AtomicU8, Ordering};
    static STEP: AtomicU8 = AtomicU8::new(0);
    let t = std::thread::spawn(|| {
        while STEP.load(Ordering::SeqCst) != 1 {
            std::hint::spin_loop();
        }
        drop(vec![0u8; 4096]);
        STEP.store(2, Ordering::SeqCst);
    });
    let before = thread_alloc_counters();
    STEP.store(1, Ordering::SeqCst);
    while STEP.load(Ordering::SeqCst) != 2 {
        std::hint::spin_loop();
    }
    let d = before.diff(&thread_alloc_counters());
    t.join().unwrap();
    assert_eq!(d.alloc_count, 0, "another thread's allocation was counted here: {d:?}");
}
