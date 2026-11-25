# Experiments

This file collects the experiments that validate how AuthKademlia nodes and the
DHT behave, run on the Docker testbed (`testbed/`) against the current code:
how fast a record is published, rotated and read, what it costs in traffic,
what an attacker who reads the network can achieve, and how many copies of a
record survive crashes; and, without Docker, what a node takes in memory
and on disk and what it writes (R1). The measurements that led to fixes are in
`testbed/README.md` and in the commit history; they are not repeated here.

The results are those of the current record format (ADR 0006): a DID commits
to a tree of 64 rotation keys, a record proves its own key against the DID, an
empty replica stores a verified record unless a node shows it a higher one,
and no rule counts votes. Each experiment compares them with the earlier
format (ADR 0005: a chain of versions, checked at empty replicas by a quorum
of answers) and, where it was measured, with `main` before it (ADR 0004).

Each experiment states the question it answers, how it is run, what is
measured, the results and how to read them. The raw data of the current runs
is in `experiments/2026-11-23-adr0006/` (section 1); that of the comparisons
in `experiments/2026-11-11-adr0005/` and `experiments/2026-11-11-owner-outage/`.

## Contents

1. [Environment](#1-environment)
2. [What is measured](#2-what-is-measured)
3. [E1. Publication and read latency](#3-e1-publication-and-read-latency)
4. [E2. Traffic per publication and per read](#4-e2-traffic-per-publication-and-per-read)
5. [E3. The empty-replica check](#5-e3-the-empty-replica-check)
6. [E4. Rotation and a replica restarted empty](#6-e4-rotation-and-a-replica-restarted-empty)
7. [A1. Race and burst attacks on a restarted replica](#7-a1-race-and-burst-attacks-on-a-restarted-replica)
8. [A2. Persistent attacker and restarts](#8-a2-persistent-attacker-and-restarts)
9. [A3. A forged position 1 right after position 0](#9-a3-a-forged-position-1-right-after-position-0)
10. [A4. Nodes that lie in `FindHash`](#10-a4-nodes-that-lie-in-findhash)
11. [A5. Spoofed answers under guessed message ids](#11-a5-spoofed-answers-under-guessed-message-ids)
12. [L1. Copies over time with churn and liars](#12-l1-copies-over-time-with-churn-and-liars)
13. [L2. Replicas lost while the owner is offline](#13-l2-replicas-lost-while-the-owner-is-offline)
14. [L3. What readers get in the worst case](#14-l3-what-readers-get-in-the-worst-case)
15. [D1. Crashes with records on disk](#15-d1-crashes-with-records-on-disk)
16. [R1. Memory, disk and writes of a node](#16-r1-memory-disk-and-writes-of-a-node)
17. [Summary](#17-summary)
18. [How to reproduce](#18-how-to-reproduce)

## 1. Environment

**Code.** ADR 0006, branch `feat/merkle-committed-rotation-keys` at `b4b8ef0`,
testbed image `auth-kademlia-testbed:adr0006`; for D1, the same code with the
testbed's `--data-dir` (image `auth-kademlia-testbed:adr0006-data`, the
code of `9e9b72e`), then with the fix that D1 led to (`03336ab`, section 15).
Release
builds with Rust 1.98.1 and the counters of `src/counters.rs`, which only
count. All runs on 2026-11-23. The comparisons are the runs of 2026-11-11:
ADR 0005 (images `adr0005-final`, and `adr0005-push` for L2 and L3) and
`main` at `424b76f` (ADR 0004: UUID DIDs, updates authorized by an
`auth_signature`).

**Records.** ML-DSA-65 (ADR 0003), 256-bit ids and keys (ADR 0004). A record
of ADR 0006 carries the proof of its key: the activation code (32 bytes), the
genesis and the path to the root (192 bytes). It is about 7.0 KB, 6 fragments,
against about 6.5 KB and 5 fragments for ADR 0005. A rotation is a STORE of
the next position: there is no UPDATE request.

**Host.** AMD Ryzen 7 4800H (8 cores, 16 threads), 15 GB RAM, Linux 7.0,
Docker 29.10.0 (29.9.2 on 2026-11-11). All containers share the host's CPU
and kernel; no CPU limit per container.

**Host limits.** Raised as `testbed/README.md` requires for more than about
30 nodes: the neighbour table (`gc_thresh1..3` = 4096, 16384, 32768) and the
per-CPU receive backlog (`net.core.netdev_max_backlog` = 16384). With the
default backlog the host drops datagrams between containers without any
emulated loss; every run records the drops of the host (second column of
`/proc/net/softnet_stat`, before and after the run) in `runner.log`. Two steps
had drops: the traffic run under loss of E2 (508) and the outage run of the
first run of D1 (398); every other step had none.

**Network.** One node per container. `tc netem` delays each container's
egress, so a request and its answer cross two delays.

| Profile | RTT | Source |
|---|---|---|
| `lan` | no delay added (Docker bridge, about 0.16 ms) | |
| `wan-eu` | 13.6 ms | Verizon backbone, Europe, monthly average |
| `wan-atlantic` | 70.4 ms | Verizon backbone, Trans-Atlantic, monthly average |

Loss, when set, applies per direction. 0.5% is Verizon's delivery target (at
least 99.5% of packets).

**Nodes.** 3 seeds; every node bootstraps from them. Node ids are derived from
container names. Storage is in memory, so a restarted node is empty, except
in D1, where every node keeps its records on disk. Unless an experiment says
otherwise: 127 nodes, `k` = 20, `alpha` = 3, owner `node-1`. An empty replica
asks the other 19 replicas for the hash of their record; no rule counts
their answers.

**Sample sizes.** 20 rounds per configuration, 40 with loss, 10 for the
counter runs of rotations. A p95 over 20 samples is the 19th value: read it as
"the slowest rounds", not as a precise percentile.

**Data.** `experiments/2026-11-23-adr0006/` holds `run_experiments.sh`, which
ran every step of sections 3 to 14 one after the other with one network at a
time, `run_data_dir.sh` for D1 (run before and after its fix, in
`data-dir/before-fix/` and `data-dir/`), their logs with the host drops of
each step, and for each step what it printed and the data of every round
(JSON). Its `README.md` explains the file names.

## 2. What is measured

| Metric | Definition |
|---|---|
| Publication time | `Server::set_detailed` timed inside the owner: lookup of the `k` closest nodes, then a STORE to each, including each empty replica's network check; it ends when every replica has answered or timed out |
| Outcome | `complete` (every node that answered holds the record), `degraded` (some replica unavailable), `rejected` |
| Readable by the first watcher | Three other nodes read the DID in a loop from 0.5 s before the publication; time from the start of the publication to the first successful read (containers share the host clock) |
| Reads right after | Every other node reads the DID once after the publication |
| Remote read time | `Server::get` on a node without a local copy |
| Rotation time | `Server::set_detailed` of the next position, timed inside the owner (testbed `update`); on `main` and ADR 0005, `Server::update`, the replay to replicas that missed versions included |
| What a replica holds | By the signing key of its record: the current position, an older one, another record (forged), or nothing |
| Traffic | Datagrams and bytes sent by all nodes, by message type, from the counters (`ctl <node> counters`). Bytes are UDP payloads including the 12-byte KADF header, without IP, UDP and Ethernet headers (42 bytes per datagram on Ethernet). It is the volume one operation sends over the whole network, not a rate |
| Check | For each STORE to an empty replica: how it ended (`accepted`, `superseded` by a higher record it was shown, `invalid`), rounds of its lookup, duration; the claims of a higher position that no node showed (`unshown_claims`), and the checks that fetched claimed records, with their whole duration |
| Resends | Requests sent again, split by whether the peer's round trip was measured when the request was first sent |

Reading the counters runs `docker exec` in all 127 containers just before and
after each operation, which loads the host. Latency (E1, E4) is therefore
measured in separate runs without counters; the times of the counter runs are
not used as latency.

## 3. E1. Publication and read latency

**Question.** How long does a first publication take in a network of 127
nodes, can every other node read the record right after, and does the record
format change it?

**Setup.** The owner publishes a new DID each round (position 0), 20 rounds
(40 with loss), on each profile.

**Results.** Every read right after found the record. Every publication was
`complete`, but one of the 40 under loss: `degraded`, one replica of 20 did
not answer its STORE within `RPC_TIMEOUT` (2.5 s); every one of the 126 other
nodes read the record right after.

| Profile | Format | Publication, median (p95) | First watcher, median (p95) | Reads right after | Remote read, median (p95) |
|---|---|---|---|---|---|
| LAN | `main` | 7.8 ms (10.4) | 6.0 ms (7.8) | 2520/2520 | 1.7 ms (6.9) |
| LAN | ADR 0005 | 9.0 ms (11.0) | 6.3 ms (8.1) | 2520/2520 | 1.9 ms (7.0) |
| LAN | **ADR 0006** | 9.1 ms (11.2) | 7.3 ms (9.2) | 2520/2520 | 2.0 ms (7.2) |
| WAN Europe | `main` | 88.4 ms (93.5) | 62.3 ms (69.8) | 2520/2520 | 15.6 ms (45.3) |
| WAN Europe | ADR 0005 | 90.8 ms (97.9) | 64.5 ms (80.4) | 2520/2520 | 16.1 ms (46.3) |
| WAN Europe | **ADR 0006** | 90.8 ms (93.7) | 63.1 ms (74.5) | 2520/2520 | 15.8 ms (43.9) |
| WAN Trans-Atlantic | `main` | 419 ms (440) | 300 ms (308) | 2520/2520 | 72.2 ms (215) |
| WAN Trans-Atlantic | ADR 0005 | 433 ms (438) | 306 ms (319) | 2520/2520 | 72.5 ms (216) |
| WAN Trans-Atlantic | **ADR 0006** | 436 ms (439) | 302 ms (352) | 2520/2520 | 72.4 ms (216) |
| WAN Europe, 0.5% loss, 40 rounds | `main` | 158 ms (592, max 1080) | 68.5 ms (119) | 5040/5040 | 15.6 ms (26.7) |
| WAN Europe, 0.5% loss, 40 rounds | ADR 0005 | 177 ms (625, max 1095) | 69.3 ms (173) | 5040/5040 | 15.8 ms (22.2) |
| WAN Europe, 0.5% loss, 40 rounds | **ADR 0006** | 161 ms (717, max 2532) | 68.5 ms (120) | 5040/5040 | 15.8 ms (43.7) |

**Reading.**
- A first publication takes as long as with ADR 0005, within a few
  milliseconds on every profile, though its record is one fragment longer.
  Each replica checks the record's tree proof before asking: hashes only,
  no signature.
- On WAN a publication still takes about 6 round trips: the owner's lookup,
  the STORE, and in between each replica's check (E3). The record is readable
  one to one and a half round trips before the owner's call returns.
- A remote read takes about one round trip in the median: the format does
  not change a read.
- Under loss the spread is made of resends. The degraded round is the one
  maximum, 2532 ms: a STORE of 6 fragments and its resends that did not get
  through. The traffic run under loss (E2) had 40 of 40 `complete`; one
  degraded publication in 80 is too few to attribute to the sixth fragment.

## 4. E2. Traffic per publication and per read

**Question.** What does a first publication cost the network, and what does a
remote read cost?

**Setup.** As E1, with `--watchers 0 --counters`: no node reads during the
publication, and the counters of every node are read before the publication,
0.3 s after it, and after the reads that follow. LAN, WAN Europe and WAN Europe
with 0.5% loss. The host dropped 508 datagrams during the run under loss,
none during the others.

**Results.** Medians per publication, all nodes together, ADR 0006:

| Message | LAN | WAN Europe | WAN Europe, 0.5% loss |
|---|---|---|---|
| `Store` (owner to replicas) | 140.2 KiB, 120 | 140.2 KiB, 120 | 150.7 KiB, 129 |
| `FindHash` (check questions) | 33.2 KiB, 400 | 33.2 KiB, 400 | 33.6 KiB, 405 |
| `FindValueNodes` (answers with closer nodes) | 416.9 KiB, 377 | 444.3 KiB, 400 | 429.6 KiB, 388 |
| `FindHashHit` (answers with a hash) | 1.5 KiB, 26 | 0, 0 | 1.2 KiB, 20 |
| `FindNode`, `FindNodeResult` (owner's lookup) | 23.9 KiB, 40 | 23.9 KiB, 40 | 23.9 KiB, 40 |
| **Total** (with `Received`, `StoreResult`) | **617 KiB, 1000 datagrams** | **642 KiB, 1000** | **640 KiB, 1016** |

The totals of the earlier formats, with the same setup:

| | LAN | WAN Europe | WAN Europe, 0.5% loss | `Store` |
|---|---|---|---|---|
| `main` | 620 KiB, 980 | 630 KiB, 980 | 629 KiB, 993 | 128.8 KiB, 100 |
| ADR 0005 | 615 KiB, 980 | 632 KiB, 982 | 632 KiB, 994 | 130.8 KiB, 100 |
| ADR 0006 | 617 KiB, 1000 | 642 KiB, 1000 | 640 KiB, 1016 | 140.2 KiB, 120 |

A remote read, averaged over about 2100 reads per run (4200 with loss):

| | LAN | WAN Europe | WAN Europe, 0.5% loss |
|---|---|---|---|
| `main` | 18.2 KiB, 17.1 datagrams | 18.1 KiB, 17.0 | 18.9 KiB, 17.6 |
| ADR 0005 | 18.5 KiB, 17.1 | 18.6 KiB, 17.2 | 19.1 KiB, 17.6 |
| ADR 0006 | 20.1 KiB, 20.2 | 19.3 KiB, 19.5 | 20.4 KiB, 20.4 |

A read served from a local copy sends nothing.

**Reading.**
- A first publication costs about the same as before, 617 to 642 KiB and
  1000 datagrams at `k` = 20: 1.5% more than ADR 0005 in WAN Europe. The
  record's proof adds about 0.55 KB and a sixth fragment to each of the 20
  STOREs, 9 KiB in all.
- About 70% of the bytes are the answers to the replicas' checks: at a first
  publication no node holds the record, so each node asked answers with its
  20 closest contacts instead of a hash, and each of the 20 replicas asks about
  20 nodes. The owner's lookup is now a node lookup (`FindNode`), whose
  answers were counted with `FindValueNodes` before.
- A remote read costs 4 to 9% more: two or three holders answer with the
  whole record, one fragment longer each, before the reader takes the first
  valid one and cancels the rest.

## 5. E3. The empty-replica check

**Question.** How does the check of an empty replica end, how many rounds and
how long does it take, for a position 0 and for a later position? It must fit
within `STORE_LOOKUP_TIMEOUT` (2 s), fetches included.

**Setup.** The counter runs of E2 (position 0 at every replica) and of E4 (a
later position at a replica restarted empty), on every profile.

**Results: position 0, the publications of E2.** Every check ended
`accepted`: no node held another record, and none claimed a higher position.

| | LAN ADR 0005 | LAN ADR 0006 | WAN Europe ADR 0005 | WAN Europe ADR 0006 | 0.5% loss ADR 0005 | 0.5% loss ADR 0006 |
|---|---|---|---|---|---|---|
| Checks | 398 | 397 | 397 | 396 | 794 | 790 |
| Lookup in 1 round / 2 rounds / more | 378 / 20 / 0 | 365 / 32 / 0 | 376 / 21 / 0 | 378 / 18 / 0 | 770 / 24 / 0 | 768 / 22 / 0 |
| Mean duration | 4.7 ms | 3.9 ms | 27.6 ms | 29.3 ms | 41.0 ms | 45.1 ms |
| Resends to measured / never measured peers | 0 / 0 | 0 / 0 | 15 / 0 | 73 / 0 | 454 / 4 | 521 / 0 |

**Results: a later position, the counter runs of E4.** Each round one
replica restarted empty checks the position the owner's rotation sends it. 10
rounds per profile.

| | LAN | WAN Europe | WAN Trans-Atlantic | WAN Europe, 0.5% loss |
|---|---|---|---|---|
| Checks, all `accepted` | 10 | 10 | 10 | 10 |
| Lookup in 1 round / 2 rounds | 4 / 6 | 1 / 9 | 1 / 9 | 2 / 8 |
| Mean lookup duration | 1.7 ms | 42.5 ms | 202 ms | 49.5 ms |
| Checks that fetched a record | 0 | 0 | 0 | 0 |

**Reading.**
- The check of a position 0 behaves as before: one round, sometimes two,
  about two round trips in WAN Europe.
- The check of a later position asks only for hashes: the other replicas
  answer with the hash of the same position, which claims nothing higher, and
  the replica stores the record. Under ADR 0005 it fetched the version before
  when a node still held it (6 of 40 checks); now it fetches only a record
  claimed at a higher position (A4). It fits within `STORE_LOOKUP_TIMEOUT` on
  every profile: about 3 round trips across the Atlantic.

## 6. E4. Rotation and a replica restarted empty

**Question.** How long does a rotation take, what does it cost, and is a
replica that restarted empty filled with the new position? On `main` such a
replica refused the owner's new version while the old one was still on other
replicas (the gap that ADR 0005 closed).

**Setup.** Each round the owner publishes a new DID; one replica holding it
crashes and restarts empty; the owner publishes the next position. 20 rounds
per profile without counters (time), 10 with counters (traffic, checks).

**Results.** Every rotation was `complete`, and every replica that did not
restart and every read by the other 126 nodes had the new position.

| Profile | Format | Rotation, median (p95) | Restarted replica holds the new position, timing runs | The same, counter runs |
|---|---|---|---|---|
| LAN | `main` | 6.4 ms (7.4) | 16/20 | 7/10 |
| LAN | ADR 0005 | 5.7 ms (6.8) | 20/20 | 10/10 |
| LAN | **ADR 0006** | 5.2 ms (6.4) | **20/20** | **10/10** |
| WAN Europe | `main` | 122 ms (127) | 18/20 | 6/10 |
| WAN Europe | ADR 0005 | 109 ms (122) | 20/20 | 10/10 |
| WAN Europe | **ADR 0006** | 92.4 ms (98.1) | **20/20** | **10/10** |
| WAN Trans-Atlantic | `main` | 579 ms (583) | 19/20 | 8/10 |
| WAN Trans-Atlantic | ADR 0005 | 509 ms (579) | 20/20 | 10/10 |
| WAN Trans-Atlantic | **ADR 0006** | 436 ms (440) | **20/20** | **10/10** |
| WAN Europe, 0.5% loss | `main` | 122 ms (211) | 9/20 | 3/10 |
| WAN Europe, 0.5% loss | ADR 0005 | 178 ms (255) | 20/20 | 10/10 |
| WAN Europe, 0.5% loss | **ADR 0006** | 123 ms (578) | **20/20** | **10/10** |

Traffic per rotation, counter runs, medians, all nodes together:

| | `main` | ADR 0005 | ADR 0006 |
|---|---|---|---|
| The record to the replicas | `Update`, 194.3 KiB, 160 datagrams | `Update`, 131.9 KiB, 100 | `Store`, 141.2 KiB, 120 |
| **Total**, LAN / WAN Europe / Trans-Atlantic / 0.5% loss | 247 / 248 / 247 / 253 KiB | 170 / 170 / 168 / 171 KiB | 172 / 172 / 171 / 178 KiB |

**Reading.**
- **A replica that restarted empty gets the new position every time**, as
  with ADR 0005: the other replicas hold the position before, which claims
  nothing higher, so its check stores the record (E3).
- **A rotation is 15% faster than with ADR 0005 on WAN** (92 instead of 109
  ms in Europe, 436 instead of 509 across the Atlantic): it is one
  publication, a node lookup and the STOREs, with no UPDATE and no replay of
  the version before to a replica that missed it.
- A rotation sends about as much as with ADR 0005, 172 KiB, and 30% less
  than `main`: the 20 copies of the record take 141 KiB instead of 132, one
  fragment more each, and the rest is the owner's node lookup (24 KiB) and the
  restarted replica's check.
- Under loss the median is 55 ms shorter than with ADR 0005, the p95 longer:
  the tail is made of resends of a longer record.

## 7. A1. Race and burst attacks on a restarted replica

**Question.** Can an attacker that reads all traffic get a forged record onto
a replica that has just restarted empty, by racing the owner's rotation?

**Setup.** The attacker runs in the host's network namespace: it sees every
container's packets and can send its own, but cannot change or drop the
owner's. It forges a record with the owner's DID, the genesis and the
position it saw, self-signed with a key of its own, which the tree does not
commit to. No extra delay. 10 nodes, `k` = 3, on three profiles, then 127
nodes, `k` = 20, WAN Europe.

**Procedure.** Each round: the owner publishes a new DID; one of its replicas
crashes and restarts empty; the owner publishes the next position. In `race`
mode the attacker sends one forged STORE to the replica as soon as it sees
the rotation; in `burst` mode 64 at once from 16 ports.

**Results.** 20 rounds each; the restarted replica was empty before the
rotation in every round.

| Network, mode | Format | Attacker wins | Restarted replica holds the owner's record / stays empty | Owner's rotation | Other replicas intact | Plain reads returning a forged record | Forged STOREs answered |
|---|---|---|---|---|---|---|---|
| 10 nodes, LAN, race | ADR 0005 | 0/20 | 20 / 0 | 20/20 | 31/31 | 0/60 | 51, all `Conflict` |
| 10 nodes, LAN, race | **ADR 0006** | 0/20 | 20 / 0 | 20/20 | 37/37 | 0/60 | 57, all `InvalidRecord` |
| 10 nodes, WAN Europe, race | `main` | 0/20 | 15 / 5 | 20/20 | 35/35 | 0/60 | |
| 10 nodes, WAN Europe, race | ADR 0005 | 0/20 | 20 / 0 | 20/20 | 35/35 | 0/60 | 55, all `Conflict` |
| 10 nodes, WAN Europe, race | **ADR 0006** | 0/20 | 20 / 0 | 20/20 | 35/35 | 0/60 | 55, all `InvalidRecord` |
| 10 nodes, WAN Trans-Atlantic, race | ADR 0005 | 0/20 | 20 / 0 | 20/20 | 38/38 | 0/60 | 58, all `Conflict` |
| 10 nodes, WAN Trans-Atlantic, race | **ADR 0006** | 0/20 | 20 / 0 | 20/20 | 33/33 | 0/60 | 53, all `InvalidRecord` |
| 10 nodes, WAN Europe, burst | `main` | 0/20 | 14 / 6 | 20/20 | 34/34 | 0/60 | |
| 10 nodes, WAN Europe, burst | ADR 0005 | 0/20 | 20 / 0 | 20/20 | 36/36 | 0/60 | 3584, all `Conflict` |
| 10 nodes, WAN Europe, burst | **ADR 0006** | 0/20 | 20 / 0 | 20/20 | 36/36 | 0/60 | 3584, all `InvalidRecord` |
| 127 nodes, WAN Europe, race | ADR 0005 | 0/20 | 20 / 0 | 20/20 | 377/377 | 0/60 | 357, all `Conflict` |
| 127 nodes, WAN Europe, race | **ADR 0006** | 0/20 | 20 / 0 | 20/20 | 374/374 | 0/60 | 316, all `InvalidRecord` |
| 127 nodes, WAN Europe, burst | ADR 0005 | 0/20 | 20 / 0 | 20/20 | 379/379 | 0/60 | 20,928, all `Conflict` |
| 127 nodes, WAN Europe, burst | **ADR 0006** | 0/20 | 20 / 0 | 20/20 | 373/373 | 0/60 | 18,240, all `InvalidRecord` |

The `main` rows are the baseline of 2026-11-11. The attacker sent its forged
STORE 0.4 to 1.8 ms (median) after seeing the rotation.

**Reading.**
- No forged record was stored. A forged record is now refused by its form,
  before any check or signature: its key and code do not form a leaf that
  reaches the root its DID commits to, which only the owner's tree does
  (`InvalidRecord`). Under ADR 0005 the replica had to find the genuine
  version first (`Conflict`).
- The restarted replica always gets the owner's record, as with ADR 0005.

## 8. A2. Persistent attacker and restarts

**Question.** What does an attacker achieve that sends forged records for
every DID it sees, to every node, all the time?

**Setup.** In `persist` mode the attacker learns DIDs from the STOREs it sees
and, every 100 ms, sends a forged STORE for each DID seen in the last 20 s to
every node. 10 nodes, `k` = 3, WAN Europe, then 127 nodes, `k` = 20, WAN
Europe.

**Procedure.** Each round: the owner publishes a new DID; after 0.5 s one of
its replicas crashes and restarts empty; 3 s later the script reads what the
restarted replica holds, how many nodes hold a forged record of that DID, and
what three plain reads return. A control run without the attacker comes
first.

**Results.** 20 rounds each; the same for `main`, ADR 0005 and ADR 0006 but
for the answers:

| Network | Restarted replica: owner's / forged / empty | Owner's publication | Nodes holding a forged record | Plain reads returning it |
|---|---|---|---|---|
| 10 nodes, no attacker | 0 / 0 / 20 | complete 20/20 | 0/180 | 0/60 |
| 10 nodes, persistent attacker | 0 / 0 / 20 | complete 20/20 | 0/180 | 0/60 |
| 127 nodes, no attacker | 0 / 0 / 20 | complete 20/20 | 0/2520 | 0/60 |
| 127 nodes, persistent attacker | 0 / 0 / 20 | complete 20/20 | 0/2520 | 0/60 |

What the attacker's forged STOREs got:

| Network | ADR 0005 | ADR 0006 |
|---|---|---|
| 10 nodes | `Conflict` 29,826, no answer 3075 | `InvalidRecord` 35,701, no answer 188 |
| 127 nodes | `Conflict` 168,281, no answer 167,871 | `InvalidRecord` 365,435, no answer 146 |

**Reading.**
- No node took a forged record. A forged position 0 does not bind to the DID,
  and a forged later position does not reach the root.
- **A forged STORE no longer costs a network check.** Under ADR 0005 a node
  that held nothing ran a check for each forged STORE, and beyond 256 at once
  dropped the STORE unanswered (`MAX_STORE_LOOKUPS`): half of the forged
  STOREs at 127 nodes. A record whose form fails starts no lookup, so the
  nodes answered every forged STORE but 146: 365,435, twice as many as ADR
  0005 answered in all.
- Without a rotation, the restarted replica is still empty after 3 s in every
  round: its neighbours do not notice a node that comes back within about a
  second, so they send it nothing. The holders' republication (hourly when
  this was run, daily since `f183e76`, R1), or the owner's next rotation or
  republication, fills it (L1). With its records on disk it
  comes back with them (D1).

## 9. A3. A forged position 1 right after position 0

**Question.** Right after the owner publishes position 0, whose code is now
public, can a forged position 1, with the owner's DID and genesis but a key
of the attacker's, get onto any node?

**Setup.** In `successor` mode the attacker answers each STORE of a position
0 it sees with a forged position 1 to the same node, at once. 10 nodes,
`k` = 3, WAN Europe, then 127 nodes, `k` = 20, WAN Europe.

**Procedure.** Each round: the owner publishes a new DID; 3.5 s later the
script reads how many nodes hold a forged record and what three plain reads
return. No replica restarts.

**Results.** 20 rounds each.

| Network | Format | Forged positions 1 sent | Answered | Nodes holding a forged record | Plain reads returning it | Owner's publication |
|---|---|---|---|---|---|---|
| 10 nodes, `k` = 3 | ADR 0005 | 55 | all `Conflict` | 0/180 | 0/60 | complete 20/20 |
| 10 nodes, `k` = 3 | **ADR 0006** | 55 | all `InvalidRecord` | 0/180 | 0/60 | complete 20/20 |
| 127 nodes, `k` = 20 | ADR 0005 | 367 | all `Conflict` | 0/2520 | 0/60 | complete 20/20 |
| 127 nodes, `k` = 20 | **ADR 0006** | 353 | all `InvalidRecord` | 0/2520 | 0/60 | complete 20/20 |

**Reading.** The forged position 1 was sent about 1 ms after the owner's
position 0, and no node took it, whether it held position 0 or nothing: the
leaf of the attacker's key and any code does not reach the root, and the code
of position 1 is not public until the owner publishes it. Under ADR 0005 a
holder checked the key against `nextKeyHash`, and an empty node had to hear
version 0 from the others first.

## 10. A4. Nodes that lie in `FindHash`

**Question.** How many nodes that lie in the check of an empty replica does it
take to block a publication, or the filling of a replica restarted empty?

**Setup.** A testbed switch, compiled only with the `testbed` feature
(`ctl <node> lie on`), makes a node answer every `FindHash`, for any key, with
a position far ahead and a made-up hash it never serves; it stores and serves
records as usual. Each round the liars are the replicas closest to the key,
those every check asks: 0, 1, 12, 13 (the ADR 0005 quorum) and 18, every
replica but the owner and the one restarted. 127 nodes, `k` = 20, WAN Europe,
the procedure of E4 with counters.

**What ADR 0006 predicts.** A claim refuses nothing unless the node shows a
record that proves it. The replica fetches one record per distinct claim
above the position offered, from the closest node that made it, at most
`k − 1`, all at once; a liar serves its real record, which does not hash to
its claim, and the replica stores the record it was sent. Under ADR 0005 one
claim refused a later version (the single liar's veto), and a quorum of
claims a version 0.

**Results.** 20 rounds each.

| Liars | Publication of position 0 | Restarted replica holds the new position | Claims not shown | Reads by every other node | Rotation, median | Traffic per rotation | Check, mean |
|---|---|---|---|---|---|---|---|
| 0 | complete 20/20 | 20/20 | 0 | 2520/2520 | 92.5 ms | 175 KiB | 45 ms |
| 1 | complete 20/20 | 20/20 | 20 | 2520/2520 | 108 ms | 182 KiB | 55 ms |
| 12 | complete 20/20 | 20/20 | 240 | 2520/2520 | 110 ms | 262 KiB | 64 ms |
| 13 | complete 20/20 | 20/20 | 260 | 2520/2520 | 110 ms | 270 KiB | 64 ms |
| 18 | complete 20/20 | 20/20 | 360 | 2520/2520 | 116 ms | 310 KiB | 111 ms |

Every publication stored 20 replicas, and every check of the restarted
replica ended `accepted`. With ADR 0005, under the same setup, 1 and 12
liars kept the restarted replica empty in 20 of 20 rounds, and 13 refused
every first publication (`NewerVersion`), leaving every honest replica empty.

**Reading.**
- **Liars block nothing**, up to every replica but the one checking: the
  single liar's veto and the quorum veto of ADR 0005 are gone.
- What a liar costs is a fetch: each one adds about 7 KiB to a rotation
  (its record, fetched and dropped), and the check's mean grows from 45 to
  111 ms with 18 liars. The fetches are bounded by `k − 1` per check.
- A liar cannot make a replica refuse the current record. It can only keep
  to itself a higher record it holds, which an empty replica then does not
  see.

## 11. A5. Spoofed answers under guessed message ids

**Question.** Message ids are drawn at random for each request. Can an
attacker who does not read them get a forged `FindHash` answer accepted by a
replica, by sending it from the address of the node the replica asked, and
what does a forged answer achieve when it is accepted?

**Setup.** In `spoof` mode the attacker answers each `FindHash` it sees with 64
answers claiming a position far ahead, sent to the asking replica from the
address and port of the node asked (a raw socket writes the IP header), under
random message ids. As a control, the same with the ids read on the wire: it
shows the spoofed answers reach the replica when their id is right. 127
nodes, `k` = 20, WAN Europe, the procedure of E4 with counters.

**Results.** 20 rounds each.

| Spoofed answers under | Format | Checks of the restarted replica | Claims not shown | Restarted replica holds the new position |
|---|---|---|---|---|
| random ids | ADR 0005 | `accepted` 20 | | 20/20 |
| random ids | **ADR 0006** | `accepted` 20 | 0 | 20/20 |
| the ids read on the wire (control) | ADR 0005 | `accepted` 5, `newer_claimed` 45 | | 5/20 |
| the ids read on the wire (control) | **ADR 0006** | `accepted` 20 | 53 | **20/20** |

Every first publication was `complete`.

**Reading.**
- Under random ids no spoofed answer was taken.
- Under the ids read on the wire, 53 spoofed answers were taken, as claims of
  a higher position that the node asked never showed: they refused nothing.
  Under ADR 0005 they blocked the repair in 15 of 20 rounds. An attacker that
  reads the traffic can still answer for the nodes asked, with the power of
  a liar (A4): it can hide a higher record, not refuse the current one.

## 12. L1. Copies over time with churn and liars

**Question.** How many replicas keep the current position over time while
nodes crash and come back empty, with 0, 1 or 13 liars near the key?

**Setup.** The owner publishes a new DID and rotates once. For 10 minutes,
every 10 s one of the `k` replicas other than the owner and the liars crashes
and comes back empty; every 60 s the owner sends its current record again
with the saved bytes (`republish`, which the application does at least once
every 24 hours); every 5 s the script counts what the replicas hold. 127
nodes, `k` = 20, WAN Europe.

**Results.** 600 s, 59 crashes of a replica and 9 republications per run, 120
samples. Copies of the current position on the replicas other than the owner
(20, or 19 when the owner is one of the `k` closest):

| Liars | ADR 0005: copies, median (min, max) | ADR 0005: samples below 13 | ADR 0006: copies, median (min, max) | ADR 0006: samples below 13 |
|---|---|---|---|---|
| 0 | 18 (15, 20) | 0/120 | 18 (15, 20) | 0/120 |
| 1 | 15 (10, 20) | 26/120 | 18 (15, 20) | 0/120 |
| 13 | 13 (13, 13), all on the liars | 0/120, but no honest copy | 18 (15, 20) | 0/120 |

Every republication was `complete`.

**Reading.**
- Each crash takes a copy away and nothing fills it until the owner's
  republication, which fills every empty replica at once: the copies go from
  20 down to 15 and back every minute. The holders' republication, hourly
  then, did not run: the records were younger than an hour.
- **The liars change nothing**: the copies follow the same cycle with 0, 1 or
  13 of them. Under ADR 0005 one liar kept the record below 13 copies a fifth
  of the time, and 13 liars kept every honest replica empty.
- The time scale is compressed: a crash every 10 s and a republication every
  60 s stand for rarer crashes and a republication at least every 24 hours.
  With its records on disk a replica does not lose its copy in a crash (D1).

## 13. L2. Replicas lost while the owner is offline

**Question.** How does the record recover when several replicas lose their
copy at once, for example in a power cut at one site, while the owner is
offline?

**Setup.** The owner publishes a new DID and rotates once, then is frozen
(`docker pause`, so that it keeps its records and does not answer). M of the
replicas holding the current position crash and come back empty at once, with
M = 4, 7, 8, 12 and 16. Each replica that still holds the record then sends it
to the `k` nodes closest to the key, one after the other, as the holders'
republication does (testbed command `push`), and the script counts what the
replicas hold. The owner then comes back and sends its current record again
with the saved bytes, and the replicas are counted once more. 5 rounds per M,
a new DID each, 127 nodes, `k` = 20, WAN Europe. No host drops.

**Results.** Rounds in which every replica held the current position again
after the holders' republication (copies then, median of 5; 20 replicas, or
19 when the owner is one of the `k` closest):

| Replicas lost | Holders left | `main` | ADR 0005 | ADR 0006 | ADR 0006, after the owner's return |
|---|---|---|---|---|---|
| 4 | 15–16 | 5/5 (20) | 5/5 (20) | 5/5 (20) | 5/5 |
| 7 | 12–13 | 5/5 (20) | 4/5 (20) | 5/5 (20) | 5/5 |
| 8 | 11–12 | 5/5 (20) | 0/5 (12) | 5/5 (19) | 5/5 |
| 12 | 7–8 | 5/5 (20) | 0/5 (8) | 5/5 (20) | 5/5 |
| 16 | 3–4 | 5/5 (20) | 0/5 (4) | 5/5 (20) | 5/5 |

**Reading.**
- **The holders refill every empty replica**, down to 4 holders left, as on
  `main`: an empty replica stores the verified record a holder sends unless a
  node shows it a higher one. Under ADR 0005 an empty replica needed a quorum
  of holders, and below it the copies waited for the owner.
- Unlike `main`, an empty replica takes no forged record when no holder is
  left to contradict it (L3).
- A record whose holders all lose their copy waits for the owner, who
  republishes at least once every 24 hours and when it comes back online.
  With records on disk a crash loses no copy (D1).

## 14. L3. What readers get in the worst case

**Question.** In the situation of L2, with the owner offline and an attacker
that keeps sending forged records to every node: does a reader get the
owner's record, a forgery, or nothing? Two readers: a node that has been in
the network all along, and a node that joins at that moment, with an empty
routing table.

**Setup.** As L2: 127 nodes, `k` = 20, WAN Europe, the owner frozen after one
rotation, M = 8, 12, 16 or 20 replicas holding the current position restarted
empty at once, 5 rounds each, then the holders' republication. In addition:
- a persistent attacker (`attack.py start --mode persist --period 1000
  --did-ttl 60`): for 60 s after it sees a DID it sends every node, every
  second, a forged record of it, with the owner's DID and a key of its own;
- after the holders' republication, with the owner still offline, every node
  but the owner reads the DID once (126 readers), and 3 nodes kept outside the
  network (130 in all) join it, bootstrap from the seeds and read it once;
- the owner then comes back and republishes, and the 126 nodes read again.

A read is classified by the key that signed what it got: one of the owner's
positions, the forged key that the attacker logged for that DID, or nothing.
No read got a record signed by any other key. The host dropped no datagram
during the ADR 0006 run, against 4,089 on `main` and 1,931 on ADR 0005.

**Results.** All 20 rounds; reads written owner's / forged / nothing:

| | `main` | ADR 0005 | ADR 0006 |
|---|---|---|---|
| Forged STOREs the nodes stored | 29,865 | 0 | **0** |
| Reads by the nodes in the network | 1,172 / 1,228 / 120 | 1,328 / 0 / 1,192 | 1,890 / **0** / 630 |
| Reads by the nodes that joined | 27 / 32 / 1 | 24 / 0 / 36 | 45 / **0** / 15 |
| Reads after the owner's return | | 2,097 / 0 / 423 | **2,520** / 0 / 0 |
| First publications complete / degraded / failed | 11 / 4 / 5 | 10 / 6 / 4 | **20 / 0 / 0** |

ADR 0006, by replicas lost:

| Replicas lost | Reads in the network | Reads by joiners | After the owner's return |
|---|---|---|---|
| 8 | 630 / 0 / 0 | 15 / 0 / 0 | all replicas restored, 630 / 0 / 0 |
| 12 | 630 / 0 / 0 | 15 / 0 / 0 | all restored, 630 / 0 / 0 |
| 16 | 630 / 0 / 0 | 15 / 0 / 0 | all restored, 630 / 0 / 0 |
| 20 | 0 / 0 / 630 | 0 / 0 / 15 | all restored, 630 / 0 / 0 |

The attacker sent 270,446 forged STOREs: 89,870 were answered
`InvalidRecord` and 180,576 got no answer, in the same proportion as under
ADR 0005 (221,624, of which 163,005 unanswered). They come from one address,
in bursts of up to 15,000 in 5 s, and a node keeps at most 8 partial messages
per sender (`MAX_REASSEMBLY_ENTRIES_PER_PEER`).

**Reading.**
- **No node stored a forged record and no reader got one**, in the network or
  just joined.
- **While one holder remains, every reader gets the owner's record**, and
  the holders refill every empty replica (L2). With every replica lost the
  readers get nothing until the owner returns, and then every read gets its
  record; on `main` they got the attacker's forgery.
- **The attacker no longer costs availability.** Every first publication
  reached every replica, against half of them under ADR 0005: a forged STORE
  is refused by its form and starts no check, so the checks of the empty
  replicas are not flooded and hear from the nodes they ask.
- These readers make plain reads, which take the first record that verifies.
  This attacker does not answer reads; one that reads the traffic could answer
  a lookup for the nodes asked with a record of its own DID, which a read of
  the owner's DID refuses, or with a superseded record of the owner's, which
  a read returns. The application compares the key with the one bound in the
  credential (`DESIGN.md`, section 8).

## 15. D1. Crashes with records on disk

**Question.** With a data directory, a replica writes each new record to the
device before it acknowledges it, and serves its records again after a
restart (`ForgetfulStorage::persistent`). What do the crashes of A2, E4, L1
and L2 do then?

**Setup.** `testbed.py up --data-dir`: every node keeps its records in a
directory of its container, which survives `docker kill` and `docker start`,
the crash used in every experiment. The kill stops the process, not the
machine: what the process wrote stays in the host's page cache, so the run
tests the restart, not the flush; the order of the writes is tested by the
unit tests of `src/storage.rs` and `src/durable.rs`. 127 nodes, `k` = 20,
WAN Europe, the procedures of A2 (with and without the persistent attacker),
E4, L1 (no liars) and L2 (M = 4, 8, 12, 16, 20). Run twice: first on the
code of the campaign, which showed the fault below, then with its fix. No
host drops in the second run; 398 during L2 in the first.

**Results.**

| Experiment | Records in memory | Records on disk, first run | Records on disk, with the fix |
|---|---|---|---|
| A2: a replica restarted without a rotation holds the owner's record | 0/20 | 20/20 | **20/20** |
| A2, persistent attacker: the same | 0/20 | 20/20, no forged record on any node | **20/20**, no forged record on any node |
| E4: the restarted replica holds the new position | 20/20 | 20/20 | 20/20 |
| E4: reads by every other node get the current position | 2520/2520 | 2059/2520, 461 the position before | **2520/2520** |
| L1: copies of the current position, median (min, max) | 18 (15, 20), of 20 | 19 (19, 19), of 19 | **20 (20, 20)**, of 20 |
| L2: copies right after M replicas crashed at once, M = 4 to 20 | 20 − M | all, also with M = 20 | **all**, also with M = 20 |

In L1 the owner was one of the `k` closest in the first run, so 19 other
replicas; in L2 a round with 19 copies is one where the owner is one of
them.

**Reading.**
- **A crash no longer costs a copy.** A replica restarted with its directory
  serves its record at once, without waiting for a republication, also with
  every replica of the DID crashed together and the owner offline.
- **The fault of the first run: a replica that restarted with records sent
  them to nodes outside the `k` closest.** In E4 the readers got the position
  before in 461 reads. The restarted node met the seeds and the nodes of its
  bootstrap lookup with an almost empty routing table, and the replication
  to a newly met node (`replicate_to`, Kademlia §2.5) sends a record to any
  node it cannot tell is farther than its own `k` closest. Those nodes took
  the position before the rotation, which goes to the `k` closest only: 2
  extra holders per restart in a check with 30 nodes and `k` = 3. They were
  authentic records, and their holders repair themselves at their next
  republication (hourly then), when the replicas answer `Stale`; until then they
  served the position before, and a GET with a local copy does not ask the
  network.
- **The fix:** a node that starts with records sends them to nobody until a
  lookup of its own id is over, at the end of its bootstrap or, for a node
  with no seed that answered, once a contact answers
  (`KademliaProtocol::note_joined`); the nodes it meets meanwhile still enter
  its table. A node that starts empty is unchanged, so every other
  experiment stands. With the fix every read got the current position, and
  a rotation took as long (54.8 ms median against 52.8 ms).
- With the attacker, the first run left 546,568 forged STOREs unanswered and
  lasted 3 min 24 s; with the fix 238, in 2 min 33 s, as with records in
  memory (146, 2 min 29 s). The extra STOREs of the restarted replicas are
  the only difference between the two runs; how they made the nodes leave
  the forged STOREs unanswered was not measured.

## 16. R1. Memory, disk and writes of a node

**Question.** How much memory and disk does a node take, what does a replica
with its records on disk write to the device in a day, and what does the
republication send? Until `e399e63` a renewal rewrote the file of its record,
and the republication and the flush ran every hour; since `f183e76` the
renewals go to one file, a record file is written only when its record
changes, and both run once a day. What did that change?

**Setup.** No Docker: `experiments/2026-11-25-memory-and-writes/run.sh`
builds its probes from a copy of the repository at each commit and runs them
on the host of section 1, one step at a time, with the data directories on
ext4 on a SATA SSD. Its `README.md` defines every field.
- **One store** (`ForgetfulStorage::persistent`) of real records of
  position 0 (7,024 bytes): 20, about what a node holds with DID records
  only (`k` = 20, one DID per node), and 1000. A day is 24 rounds of renewals
  and flushes before `f183e76` and one since; each code runs both, to tell
  the file of renewals from the interval. Heap is what Rust allocates (the C
  code of aws-lc allocates outside it); writes are the bytes the kernel sends
  to the device (`/proc/self/io`), in pages of 4 KiB, without the journal of
  the file system.
- **Whole nodes**: 30 processes on loopback, `k` = 20, `alpha` = 3, each with
  4 runtime threads and at most 4 blocking ones, as on a Raspberry Pi 4, its
  records on disk and the counters on. Every node publishes 1 new DID, or 10;
  then one round of republication, node after node, each republishing the
  records no other node renewed since the round started, as each node does
  once a day.
- **The custody**: one DID provisioned at `f28c760`, before the SHA-256 of
  its files, and at `e399e63`.

**Results.** Bytes written to the device in a day:

| Records | Before (24 a day) | File of renewals, 24 a day | Old files, once a day | Since `f183e76` (once a day) |
|---|---|---|---|---|
| 20 | 3.75 MiB | 96 KiB | 160 KiB | **4 KiB** |
| 1000 | 187.5 MiB | 1.78 MiB | 7.81 MiB | **76 KiB** |

The store, before and since `f183e76`:

| | 20 records | 1000 records |
|---|---|---|
| Heap of the records | 150 KiB, both | 6.84 MiB, both |
| Allocated by a flush, above the records | 22.7 KiB, now 1.9 KiB | 76.6 KiB, now 72.7 KiB |
| Highest heap while opening the directory | 155 KiB, now 158 KiB | 6.89 MiB, now 6.97 MiB |
| Data directory | 20 files, 160 KiB of blocks; now one more, the renewals, 1.5 KiB | 1000 files, 7.81 MiB; now one more, 72 KiB |

Whole nodes, median of 30:

| | Before | Since `f183e76` |
|---|---|---|
| Memory of the process (RSS), no record | 6.20 MiB, of which 0.29 MiB of heap | 6.22 MiB, 0.29 MiB of heap |
| With 1 DID per node: records held, RSS, heap | 19, 8.04 MiB, 0.46 MiB | 19.5, 8.07 MiB, 0.47 MiB |
| With 10 DIDs per node | 208.5, 9.58 MiB, 1.77 MiB | 197.5, 9.60 MiB, 1.70 MiB |
| Highest RSS, 10 DIDs, round included | 9.72 MiB | 9.73 MiB |
| Threads | 6 | 6 |
| Data directory, 10 DIDs | 1.49 MiB | 1.46 MiB |
| One round of republication, 30 DIDs, sent by all nodes | 4.90 MiB | 4.89 MiB |
| The same, 300 DIDs | 48.9 MiB | 48.9 MiB |
| Rounds a day | 24 | **1** |

The custody: each of its three files is 32 bytes longer (`tree` 2,134,
`secrets` 4,134, `state` 7,089 bytes), on as many blocks as before (4, 8 and
8 KiB); opening it allocates the same 11.2 KiB.

**Reading.**
- **A replica of 20 records writes 4 KiB a day instead of 3.75 MiB**: 1.4 MiB
  a year instead of 1.34 GiB, on the SD card of a cheap device. Before, every
  hourly flush rewrote the 7 KB file of each record to move its expiry; the
  file of renewals alone divides the writes by 40, the daily interval by 24,
  both by about 960. A day now costs one page of the device, and one file
  renamed and synced instead of 480; the journal of the file system, not
  counted here, falls with them.
- **The memory of the records is unchanged**: a record of 7,024 bytes takes
  about 7,170 with its key and its entry. A flush allocates less than
  before. Opening the directory reads the renewals into a map first: 80 KiB
  more at the highest for 1000 records, freed once the records are loaded.
- **A whole node takes about 6.2 MiB with no record**, of which 0.3 MiB of
  heap: the rest is the program, its libraries and the stacks of its 6
  threads, and does not grow with the records. With the records of DIDs only
  (about `k`) it takes 8 MiB, with ten times as many 9.6 MiB. The same
  before and since `f183e76`.
- **One record costs about 167 KiB per round of republication** in the
  network: 84% the `k` − 1 copies of the record, the rest the node lookup
  and the checks of the replicas that did not hold it. With one DID per node
  that is 167 KiB sent per node and per round, as much received: 3.9 MiB a
  day before, 167 KiB since. In the round of the probe the first nodes do
  most of the work, because they run first; in a network whose nodes started
  at different times it is spread, and only the total counts.
- **Limits.** The host is x86-64, not a Raspberry Pi: the part of the memory
  that does not depend on the records will differ on ARM. 30 nodes only; the
  owner's daily republication of its own record, the same before and since,
  is not counted; nor is the Python interpreter of a node run through the
  binding.

## 17. Summary

Validated on the code of ADR 0006:
- **Publication and availability.** 100 first publications in a network of
  127 nodes (`k` = 20), in LAN, WAN Europe, WAN Trans-Atlantic and WAN Europe
  with 0.5% loss: 99 `complete` and one `degraded` under loss (a replica of
  20 did not answer in time), and all 12,600 reads right after found the
  record. Latency as with ADR 0005; traffic 1.5% higher (about 640 KiB per
  publication), reads 4 to 9% higher, for a record one fragment longer.
- **Rotation.** A replica restarted empty gets the new position 120 times of
  120. A rotation is 15% faster than with ADR 0005 on WAN and sends as much
  (172 KiB, 30% less than `main`).
- **Forged records.** None stored in 160 rounds of race, burst and
  persistent attacks at 10 and 127 nodes, nor in 40 rounds of a forged
  position 1 right after position 0: every forged STORE that got an answer
  got `InvalidRecord`, without a network check.
- **Liars and spoofed answers.** Up to 18 liars of 19 replicas, and spoofed
  answers under the ids read on the wire, blocked no publication and no
  filling of a restarted replica. A liar costs a fetch of about 7 KiB.
- **Replicas lost with the owner offline.** The holders refill every empty
  replica down to 4 holders left; with every replica lost the copies wait for
  the owner. With records on disk a crash loses no copy, and a restarted
  replica sends its records to nobody until it has joined: every read gets
  the current position (D1).
- **Readers in the worst case**, with the owner offline, replicas lost and a
  persistent attacker: no forged record stored or read, every first
  publication complete, every reader served while a holder remains.

Measured costs and limits:
- **A replica that restarts empty without a rotation** stays empty until a
  republication, once a day since `f183e76`: its neighbours do not notice a
  node that comes back within a second. With records on disk it does not
  restart empty.
- **An attacker that reads the traffic** can answer for other nodes, with the
  power of a liar: it can hide a higher record from an empty replica, not
  refuse the current one.
- **Traffic of a first publication**: about 640 KiB at `k` = 20, 70% of it in
  the answers to the replicas' checks.
- **Tail under loss**: publications of 0.7 to 2.5 s in the slowest rounds
  under 0.5% loss.
- **Memory and writes** (R1): a whole node takes about 6.2 MiB with no
  record and 8 MiB with the records of DIDs only; a replica of 20 records on
  disk writes 4 KiB a day, against 3.75 MiB before `f183e76`; a round of
  republication costs about 167 KiB per record in the network, once a day
  instead of every hour.

## 18. How to reproduce

Host limits, once per boot:

```bash
sudo sysctl -w net.ipv4.neigh.default.gc_thresh1=4096 net.ipv4.neigh.default.gc_thresh2=16384 net.ipv4.neigh.default.gc_thresh3=32768
sudo sysctl -w net.core.netdev_max_backlog=16384
```

The images, from commit `b4b8ef0`, and for D1 from `9e9b72e`, which adds
`--data-dir` to the testbed (the first run), or from `03336ab`, its fix:

```bash
testbed/testbed.py build --tag auth-kademlia-testbed:adr0006
testbed/testbed.py build --tag auth-kademlia-testbed:adr0006-data
```

Every experiment, one network at a time, as run on 2026-11-23:

```bash
experiments/2026-11-23-adr0006/run_experiments.sh all   # or: compare, attacks, outage
experiments/2026-11-23-adr0006/run_data_dir.sh
```

L3 is analysed with the two scripts of the 2026-11-11 campaign:

```bash
python3 experiments/2026-11-11-owner-outage/reads/check_forged.py <run>.json <attacker-log>.txt
python3 experiments/2026-11-11-owner-outage/reads/digest_reads.py <run>.json
```

R1 needs neither Docker nor the host limits; its work directory holds the
copies of the repository, the builds and the data directories:

```bash
experiments/2026-11-25-memory-and-writes/run.sh <work dir outside the repository>
```

The comparisons of 2026-11-11 are reproduced as their own README files say:
`experiments/2026-11-11-adr0005/` and `experiments/2026-11-11-owner-outage/`.

One step by hand, for example E1 on WAN Europe:

```bash
testbed/testbed.py up --nodes 127 --k 20 --alpha 3 --profile wan-eu --image auth-kademlia-testbed:adr0006 --no-build
testbed/measure.py publish --rounds 20
testbed/testbed.py down
```

Each run writes its rounds to `testbed/.generated/` (not in the repository).
