# Measurements of 2026-11-25: memory, disk and writes

The raw data behind R1 in `EXPERIMENTS.md`: what a node holds in memory and on
disk, what it writes to the device in a day, and what one round of
republication sends, before and after the file of renewals and the daily
republication (`f183e76`); and the custody files before and after their
SHA-256 (`e399e63`). No Docker: `run.sh` builds the probes of this folder from
a copy of the repository at each commit, and runs the nodes as processes on
loopback, one step at a time.

## Code

| Commit | What it measures |
|---|---|
| `f28c760` | custody files without their SHA-256 |
| `e399e63` | custody files with it; a renewal rewrites the file of its record, the republication and the flush run every hour |
| `f183e76` | renewals in one file, a record file written only when its record changes; republication and flush once a day |

Release builds, Rust 1.97.0-nightly, on the host of section 1 of
`EXPERIMENTS.md` (AMD Ryzen 7 4800H, 15 GB RAM, Linux 7.0); data directories on
ext4 on a SATA SSD.

## Files

- `run.sh`: every step, in order. `runner.log`: when each started and ended.
- `probe_mem.rs`: one persistent store, or one custody, in one process.
- `probe_node.rs`: one whole node (`Server`, a store on disk, 4 runtime
  threads and at most 4 blocking ones, as on a Raspberry Pi 4), driven
  through stdin; built with the feature `counters`. `cluster.py` starts 30 of
  them.
- `storage-<commit>-<records>-<cycles>.txt`: a store of `records` real
  records of position 0 (7024 bytes each, 32-byte keys), then one day of
  `cycles` rounds, each a renewal of every record (the same bytes stored
  again, as when another replica republishes it) and a flush
  (`flush_renewals`). Before `f183e76` a day had 24 of them, since then one;
  each code runs both to tell the file of renewals from the daily interval.
  - `heap_after_insert`: bytes Rust allocated for the store and its records;
  - `insert_wchar`, `insert_device`: bytes written to store the records, as
    passed to `write` and as sent to the device (`/proc/self/io`, pages of
    4 KiB, the journal of the file system not included);
  - `day_wchar`, `day_device`: the same for the whole day;
  - `flush_peak_extra_heap`: the most a flush allocated above what the store
    held;
  - `disk_after_*`: files, bytes and blocks of the data directory;
  - `reopen_heap`, `reopen_peak_extra`: the store opened again from its
    directory, after and at its peak.
- `custody-<commit>.txt`: a custody provisioned (`FileCustody::provision`):
  bytes written, its files with their size and blocks, and the heap of
  `FileCustody::open`.
- `cluster-<commit>-dids<M>.json`: 30 nodes, `k` = 20, `alpha` = 3; every
  node bootstraps twice from the first, then publishes `M` new DIDs; then one
  round of republication, node after node, each republishing the records no
  other node renewed since the round started. Each field gives the minimum,
  median and maximum over the nodes:
  - `idle_*`: before any publication; `loaded_*`: 5 s after the last one;
  - `rss_kb`, `hwm_kb`: the memory of the process as the kernel counts it,
    now and at its highest (`/proc/self/status`); `heap`: what Rust
    allocated;
  - `records`, `routing`: records held, contacts in the routing table;
  - `round_*`: the round of republication: records republished, seconds,
    bytes sent in all (UDP payloads with the KADF header, from the counters),
    per node and by message type. The order of the round puts most of the
    work on the first nodes; a network whose nodes started at different times
    spreads it, and only the total matters;
  - `data_dir_bytes`: the data directory at the end.

## How to reproduce

```bash
experiments/2026-11-25-memory-and-writes/run.sh <work dir outside the repository>
```

It needs about 1 GB in the work directory and ports 17100 to 17129 on
loopback.
