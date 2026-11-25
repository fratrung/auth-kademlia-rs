//! Heap, disk and bytes written by a persistent store and by a custody, for
//! the version of the code it is built with. `run.sh` copies it into
//! `examples/` of a copy of the repository at each commit it measures.
//!
//!   probe_mem storage <dir> <records> <cycles>
//!   probe_mem custody <dir>
//!
//! The heap is what Rust allocates (a counting global allocator; the C code
//! of aws-lc allocates outside it). Writes are read from `/proc/self/io`:
//! `wchar`, the bytes passed to `write`, and `write_bytes`, the bytes sent to
//! the device, in pages of 4 KiB, without the journal of the file system.

use std::alloc::{GlobalAlloc, Layout, System};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use auth_kademlia_rs::auth_handler::did::PLACEHOLDER;
use auth_kademlia_rs::auth_handler::owner::OwnerTree;
use auth_kademlia_rs::custody::{Calendar, FileCustody};
use auth_kademlia_rs::storage::{
    ForgetfulStorage, IStorage, DEFAULT_MAX_STORAGE_BYTES, DEFAULT_TTL,
};
use auth_kademlia_rs::utils::digest_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};

struct Counting;
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let now = CURRENT.fetch_add(by, Relaxed) + by;
    PEAK.fetch_max(now, Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        CURRENT.fetch_sub(layout.size(), Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            if new_size >= layout.size() {
                grow(new_size - layout.size());
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn heap() -> usize {
    CURRENT.load(Relaxed)
}

fn reset_peak() {
    PEAK.store(heap(), Relaxed);
}

fn peak() -> usize {
    PEAK.load(Relaxed)
}

/// (bytes passed to write(), bytes sent to the device) so far.
fn io() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/self/io").expect("/proc/self/io");
    let field = |name: &str| -> u64 {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().parse().ok())
            .expect("a field of /proc/self/io")
    };
    (field("wchar:"), field("write_bytes:"))
}

/// (files, bytes of content, bytes of blocks on the device).
fn disk(dir: &Path) -> (usize, u64, u64) {
    let mut files = 0;
    let mut bytes = 0;
    let mut blocks = 0;
    for entry in std::fs::read_dir(dir).expect("the directory") {
        let meta = entry.expect("an entry").metadata().expect("metadata");
        if meta.is_file() {
            files += 1;
            bytes += meta.len();
            blocks += meta.blocks() * 512;
        }
    }
    (files, bytes, blocks)
}

fn rss_kb() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status");
    let field = |name: &str| -> u64 {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
            .unwrap_or(0)
    };
    (field("VmRSS:"), field("VmHWM:"))
}

/// A real position 0, as the testbed builds it.
fn real_record() -> Vec<u8> {
    let owner = OwnerTree::generate().expect("a tree");
    let public = owner.public_key(0).expect("position 0");
    let did = PLACEHOLDER;
    let initial = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{did}#k0"),
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": { "kty": "AKP", "alg": "ML-DSA-65", "pub": URL_SAFE_NO_PAD.encode(public) }
        }],
        "authentication": [format!("{did}#k0")],
        "service": [{
            "id": format!("{did}#device"),
            "type": "DeviceAgent",
            "serviceEndpoint": "http://example.com/device"
        }],
        "seq": 0,
    });
    let genesis = owner.genesis(&initial).expect("a genesis");
    owner.record(&genesis, &initial, 0).expect("position 0")
}

fn storage(dir: &Path, records: usize, cycles: usize) {
    let record = real_record();
    let keys: Vec<Vec<u8>> = (0..records as u64)
        .map(|i| digest_bytes(&i.to_be_bytes()).to_vec())
        .collect();
    println!("record_len {}", record.len());

    let before = heap();
    let (w0, d0) = io();
    let store =
        ForgetfulStorage::persistent(dir, DEFAULT_TTL, DEFAULT_MAX_STORAGE_BYTES).expect("a store");
    for key in &keys {
        store.insert_if_absent(key.clone(), record.clone());
    }
    let (w1, d1) = io();
    println!("heap_after_insert {}", heap() - before);
    println!("insert_wchar {} insert_device {}", w1 - w0, d1 - d0);
    let (files, bytes, blocks) = disk(dir);
    println!("disk_after_insert files {files} bytes {bytes} blocks {blocks}");

    // One day: each cycle every record is renewed, as a replica is when
    // another replica republishes it, then the renewals are flushed.
    let mut flush_peak = 0;
    for _ in 0..cycles {
        std::thread::sleep(Duration::from_millis(3));
        for key in &keys {
            store.insert_if_absent(key.clone(), record.clone());
        }
        reset_peak();
        let at = heap();
        let written = store.flush_renewals();
        flush_peak = flush_peak.max(peak() - at);
        assert_eq!(written, records, "every renewal flushed");
    }
    let (w2, d2) = io();
    println!(
        "day_cycles {cycles} day_wchar {} day_device {}",
        w2 - w1,
        d2 - d1
    );
    println!("flush_peak_extra_heap {flush_peak}");
    let (files, bytes, blocks) = disk(dir);
    println!("disk_after_day files {files} bytes {bytes} blocks {blocks}");
    println!("heap_after_day {}", heap() - before);
    drop(store);

    let before = heap();
    reset_peak();
    let reopened = ForgetfulStorage::persistent(dir, DEFAULT_TTL, DEFAULT_MAX_STORAGE_BYTES)
        .expect("the store again");
    println!(
        "reopen_heap {} reopen_peak_extra {}",
        heap() - before,
        peak() - before
    );
    println!("reopened_records {}", reopened.iter_all().len());
    let (rss, hwm) = rss_kb();
    println!("rss_kb {rss} hwm_kb {hwm}");
}

fn custody(dir: &Path) {
    let template: Value = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{PLACEHOLDER}#k0"),
            "type": "JsonWebKey2020",
            "controller": PLACEHOLDER,
            "publicKeyJwk": {"kty": "AKP", "alg": "ML-DSA-65"},
        }],
        "authentication": [format!("{PLACEHOLDER}#k0")],
        "service": [{
            "id": format!("{PLACEHOLDER}#device"),
            "type": "DeviceAgent",
            "serviceEndpoint": "https://device.example/agent",
        }],
    });
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let calendar = Calendar::new(now, 7 * 86_400).expect("a calendar");
    let (w0, d0) = io();
    let provisioned = FileCustody::provision(dir, calendar, &template).expect("provision");
    let (w1, d1) = io();
    drop(provisioned);
    println!("provision_wchar {} provision_device {}", w1 - w0, d1 - d0);
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .expect("dir")
        .map(|e| e.expect("entry"))
        .collect();
    names.sort_by_key(|e| e.file_name());
    for entry in names {
        let meta = entry.metadata().expect("meta");
        if meta.is_file() {
            println!(
                "file {} bytes {} blocks {}",
                entry.file_name().to_string_lossy(),
                meta.len(),
                meta.blocks() * 512
            );
        }
    }
    let before = heap();
    reset_peak();
    let opened = FileCustody::open(dir).expect("open");
    println!(
        "open_heap {} open_peak_extra {}",
        heap() - before,
        peak() - before
    );
    drop(opened);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = Path::new(&args[2]);
    match args[1].as_str() {
        "storage" => storage(
            dir,
            args[3].parse().expect("records"),
            args[4].parse().expect("cycles"),
        ),
        "custody" => custody(dir),
        other => panic!("unknown mode {other}"),
    }
}
