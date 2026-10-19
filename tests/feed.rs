use memguard::helper::NvmlFeed;

#[test]
fn helper_feed_delivers_records() {
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_memguard"));
    let mut feed = NvmlFeed::spawn_with_exe(exe, 20).expect("spawn helper");
    let start = memguard::mono_ns();
    while memguard::mono_ns() - start < 5_000_000_000 && feed.stats.records == 0 {
        feed.poll(memguard::mono_ns());
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(feed.stats.records > 0, "helper produced no records");
    if feed.stats.status == memguard::helper::STATUS_OK {
        assert!(feed.snapshot().valid);
        assert!(feed.age_ns(memguard::mono_ns()) < 5_000_000_000);
    } else {
        eprintln!(
            "NVML not available on this host (status {}); feed protocol still works",
            feed.stats.status
        );
    }
    feed.shutdown();
}
