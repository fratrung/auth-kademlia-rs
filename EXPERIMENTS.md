# Experiments

This file collects the experiments that validate how AuthKademlia nodes and the
DHT behave, run on the Docker testbed (`testbed/`) against the current code:
how fast a record is published, rotated and read, what it costs in traffic,
and what an attacker who reads the network can achieve. The measurements that
led to fixes are in `testbed/README.md` and in the commit history; they are not
repeated here.

Each experiment states the question it answers, how it is run, what is
measured, the results and how to read them. The raw data of every run is in
`experiments/2026-11-11-adr0005/` (section 1), and that of L2 and L3 in
`experiments/2026-11-11-owner-outage/`.

## Contents

1. [Environment](#1-environment)
2. [What is measured](#2-what-is-measured)
3. [E1. Publication and read latency](#3-e1-publication-and-read-latency)
4. [E2. Traffic per publication and per read](#4-e2-traffic-per-publication-and-per-read)
5. [E3. The empty-replica check](#5-e3-the-empty-replica-check)
6. [E4. Rotation and a replica restarted empty](#6-e4-rotation-and-a-replica-restarted-empty)
7. [A1. Race and burst attacks on a restarted replica](#7-a1-race-and-burst-attacks-on-a-restarted-replica)
8. [A2. Persistent attacker and restarts](#8-a2-persistent-attacker-and-restarts)
9. [A3. A forged version 1 right after version 0](#9-a3-a-forged-version-1-right-after-version-0)
10. [A4. Nodes that lie in `FindHash`](#10-a4-nodes-that-lie-in-findhash)
11. [A5. Spoofed answers under guessed message ids](#11-a5-spoofed-answers-under-guessed-message-ids)
12. [L1. Copies over time with churn and liars](#12-l1-copies-over-time-with-churn-and-liars)
13. [L2. Replicas lost while the owner is offline](#13-l2-replicas-lost-while-the-owner-is-offline)
14. [L3. What readers get in the worst case](#14-l3-what-readers-get-in-the-worst-case)
15. [Summary](#15-summary)
16. [How to reproduce](#16-how-to-reproduce)

## 1. Environment

**Code.** ADR 0005 (self-certifying DIDs, a pre-rotated chain of versions),
branch `feat/self-certifying-did-and-pre-rotation`, testbed image
`auth-kademlia-testbed:adr0005-final`. For the comparisons, `main` at
`424b76f` (ADR 0004: UUID DIDs, updates authorized by an `auth_signature`),
image `auth-kademlia-testbed:main-424b76f`. Both are release builds with
Rust 1.98.1 and the counters of `src/counters.rs`, which only count. All runs
on 2026-11-11.

**Records.** ML-DSA-65 (ADR 0003), 256-bit ids and keys (ADR 0004). A version
0 is about 6.5 KB, a later version about 6.6 KB (it adds `prev`), 5 fragments
each. On `main` an UPDATE also carries the 3309-byte `auth_signature`: 8
fragments; on the branch it carries the record only: 5 fragments.

**Host.** AMD Ryzen 7 4800H (8 cores, 16 threads), 15 GB RAM, Linux 7.0,
Docker 29.9.2. All containers share the host's CPU and kernel; no CPU limit
per container.

**Host limits.** Raised as `testbed/README.md` requires for more than about
30 nodes: the neighbour table (`gc_thresh1..3` = 4096, 16384, 32768) and the
per-CPU receive backlog (`net.core.netdev_max_backlog` = 16384). With the
default backlog the host drops datagrams between containers without any
emulated loss; every run records the drops of the host (second column of
`/proc/net/softnet_stat`, before and after the run) in `runner.log`.

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
container names; storage is in memory, so a restarted node is empty. Unless an
experiment says otherwise: 127 nodes, `k` = 20, `alpha` = 3, owner `node-1`.
With `k` = 20 an empty replica asks the other 19 and needs 13 votes
(`store_quorum`).

**Sample sizes.** 20 rounds per configuration, 40 with loss, 10 for the
counter runs of rotations. A p95 over 20 samples is the 19th value: read it as
"the slowest rounds", not as a precise percentile.

**Data.** `experiments/2026-11-11-adr0005/` holds `run_experiments.sh`, which
ran every step below one after the other with one network at a time, its log
with the host drops of each step, and for each step what it printed and the
data of every round (JSON). Its `README.md` explains the file names.

## 2. What is measured

| Metric | Definition |
|---|---|
| Publication time | `Server::set_detailed` timed inside the owner: lookup of the `k` closest nodes, then a STORE to each, including each empty replica's network check; it ends when every replica has answered or timed out |
| Outcome | `complete` (every node that answered holds the record), `degraded` (some replica unavailable), `rejected` |
| Readable by the first watcher | Three other nodes read the DID in a loop from 0.5 s before the publication; time from the start of the publication to the first successful read (containers share the host clock) |
| Reads right after | Every other node reads the DID once after the publication |
| Remote read time | `Server::get` on a node without a local copy |
| Rotation time | `Server::update` timed inside the owner, from the call to the confirmation, the replay to replicas that miss versions included |
| What a replica holds | By the signing key of its record: the current version, an older one, another record (forged), or nothing |
| Traffic | Datagrams and bytes sent by all nodes, by message type, from the counters (`ctl <node> counters`). Bytes are UDP payloads including the 12-byte KADF header, without IP, UDP and Ethernet headers (42 bytes per datagram on Ethernet) |
| Check | For each STORE to an empty replica: how it ended, rounds of its lookup, duration; on the branch also the checks that fetched the version before (R5), with their whole duration |
| Resends | Requests sent again, split by whether the peer's round trip was measured when the request was first sent |

Reading the counters runs `docker exec` in all 127 containers just before and
after each operation, which loads the host. Latency (E1, E4) is therefore
measured in separate runs without counters; the times of the counter runs are
not used as latency.

## 3. E1. Publication and read latency

**Question.** How long does a first publication take in a network of 127
nodes, can every other node read the record right after, and does ADR 0005
change it?

**Setup.** The owner publishes a new DID each round (version 0), 20 rounds (40
with loss), on each profile, on both images.

**Results.** Every publication was `complete` and every read right after found
the record, on both images.

| Profile | Image | Publication, median (p95) | First watcher, median (p95) | Reads right after | Remote read, median (p95) |
|---|---|---|---|---|---|
| LAN | `main` | 7.8 ms (10.4) | 6.0 ms (7.8) | 2520/2520 | 1.7 ms (6.9) |
| LAN | ADR 0005 | 9.0 ms (11.0) | 6.3 ms (8.1) | 2520/2520 | 1.9 ms (7.0) |
| WAN Europe | `main` | 88.4 ms (93.5) | 62.3 ms (69.8) | 2520/2520 | 15.6 ms (45.3) |
| WAN Europe | ADR 0005 | 90.8 ms (97.9) | 64.5 ms (80.4) | 2520/2520 | 16.1 ms (46.3) |
| WAN Trans-Atlantic | `main` | 419 ms (440) | 300 ms (308) | 2520/2520 | 72.2 ms (215) |
| WAN Trans-Atlantic | ADR 0005 | 433 ms (438) | 306 ms (319) | 2520/2520 | 72.5 ms (216) |
| WAN Europe, 0.5% loss, 40 rounds | `main` | 158 ms (592, max 1080) | 68.5 ms (119) | 5040/5040 | 15.6 ms (26.7) |
| WAN Europe, 0.5% loss, 40 rounds | ADR 0005 | 177 ms (625, max 1095) | 69.3 ms (173) | 5040/5040 | 15.8 ms (22.2) |

**Reading.**
- ADR 0005 leaves a first publication about as fast as before on WAN: 3%
  slower in the medians (2.4 ms in Europe, 14 ms across the Atlantic). In LAN,
  where the time is mostly processing, it is 1.2 ms slower (15%). Each replica
  now checks the form of version 0 before asking (canonical JSON, the hash of
  the hashed form); the difference is not attributed further. Under loss the medians differ by 18 ms within a spread
  of hundreds of milliseconds made of resends.
- On WAN a publication still takes about 6 round trips (Europe 6.7,
  Trans-Atlantic 6.1): the owner's lookup, the STORE, and in between each
  replica's check (E3). The record is readable one to one and a half round
  trips before the owner's call returns.
- A remote read takes about one round trip in the median, on both images: a
  read is unchanged by ADR 0005.
- Against the results before ADR 0003 and 0004 (Dilithium-2, 160-bit ids):
  LAN 7.8 ms, WAN Europe 84.8, Trans-Atlantic 401, with loss 164. ML-DSA-65
  records and 256-bit ids cost little in time.

## 4. E2. Traffic per publication and per read

**Question.** What does a first publication cost the network, and what does a
remote read cost?

**Setup.** As E1, with `--watchers 0 --counters`: no node reads during the
publication, and the counters of every node are read before the publication,
0.3 s after it, and after the reads that follow. LAN, WAN Europe and WAN Europe
with 0.5% loss, both images.

**Results.** Medians per publication, all nodes together.

| Message | LAN `main` | LAN ADR 0005 | WAN Europe `main` | WAN Europe ADR 0005 | 0.5% loss `main` | 0.5% loss ADR 0005 |
|---|---|---|---|---|---|---|
| `Store` (owner to replicas) | 128.8 KiB, 100 | 130.8 KiB, 100 | 128.8 KiB, 100 | 130.8 KiB, 100 | 135.3 KiB, 105 | 137.4 KiB, 105 |
| `FindHash` (check questions) | 33.2 KiB, 400 | 33.2 KiB, 400 | 33.2 KiB, 400 | 33.3 KiB, 401 | 33.6 KiB, 405 | 33.5 KiB, 404 |
| `FindValueNodes` (answers with closer nodes) | 454.5 KiB, 411 | 447.0 KiB, 403 | 465.3 KiB, 420 | 465.7 KiB, 420 | 460.7 KiB, 416 | 463.4 KiB, 418 |
| `FindHashHit` (answers with a hash) | 0.7 KiB, 14 | 1.0 KiB, 17 | 0, 0 | 0, 0 | 0.5 KiB, 9 | 0.8 KiB, 14 |
| `FindValue` (owner's lookup) | 1.7 KiB, 20 | 1.7 KiB, 20 | 1.7 KiB, 20 | 1.7 KiB, 20 | 1.7 KiB, 20 | 1.7 KiB, 20 |
| **Total** (with `Received`, `StoreResult`) | **620 KiB, 980 datagrams** | **615 KiB, 980** | **630 KiB, 980** | **632 KiB, 982** | **629 KiB, 993** | **632 KiB, 994** |

A remote read, averaged over about 2100 reads per run (4200 with loss):

| | LAN | WAN Europe | WAN Europe, 0.5% loss |
|---|---|---|---|
| `main` | 18.2 KiB, 17.1 datagrams | 18.1 KiB, 17.0 | 18.9 KiB, 17.6 |
| ADR 0005 | 18.5 KiB, 17.1 | 18.6 KiB, 17.2 | 19.1 KiB, 17.6 |

A read served from a local copy sends nothing.

**Reading.**
- A first publication costs the same on both images, about 630 KiB and 980
  datagrams at `k` = 20. Version 0 is about 100 bytes larger (`seq` and
  `nextKeyHash`): 2 KiB more in the 20 STOREs.
- About 73% of the bytes are the answers to the replicas' checks: at a first
  publication no node holds the record, so each node asked answers with its
  20 closest contacts instead of a hash, and each of the 20 replicas asks about
  20 nodes. Against the runs before ADR 0003 and 0004 (503 KiB), these answers
  grew with 256-bit ids (357 to about 460 KiB) and the STOREs with ML-DSA-65
  records (120 to about 130 KiB).
- A remote read sends three requests at once (`alpha`), and two or three
  holders answer with the whole record before the reader takes the first valid
  one and cancels the rest.

## 5. E3. The empty-replica check

**Question.** How does the check of an empty replica end, how many rounds and
how long does it take, and on the branch, how long does it take when it must
fetch the version before (R5)? ADR 0005 requires that check, fetch included,
to fit within `STORE_LOOKUP_TIMEOUT` (2 s) on the WAN profiles.

**Setup.** The counter runs of E2 (checks of version 0, R2) and of E4 (checks
of a later version at a replica restarted empty, R5), on every profile.

**Results: version 0 (R2), the publications of E2.** Every check ended
`none_or_same` on `main` and `accepted` with ADR 0005: no node held another
record.

| | LAN `main` | LAN ADR 0005 | WAN Europe `main` | WAN Europe ADR 0005 | 0.5% loss `main` | 0.5% loss ADR 0005 |
|---|---|---|---|---|---|---|
| Checks | 400 | 398 | 399 | 397 | 793 | 794 |
| Lookup in 1 round / 2 rounds / more | 381 / 19 / 0 | 378 / 20 / 0 | 389 / 10 / 0 | 376 / 21 / 0 | 781 / 12 / 0 | 770 / 24 / 0 |
| Mean duration | 3.9 ms | 4.7 ms | 26.3 ms | 27.6 ms | 40.7 ms | 41.0 ms |
| Resends to measured / never measured peers | 0 / 0 | 0 / 0 | 41 / 0 | 15 / 0 | 547 / 2 | 454 / 4 |

**Results: a later version (R5), the counter runs of E4.** Each round one
replica restarted empty checks the version the owner's rotation sends it. ADR
0005 only, 10 rounds per profile; `main` has no such check.

| | LAN | WAN Europe | WAN Trans-Atlantic | WAN Europe, 0.5% loss |
|---|---|---|---|---|
| Checks, all `accepted` | 10 | 10 | 10 | 10 |
| Checks that fetched version N−1 | 2, all within 10 ms | 3, all within 100 ms | 1, within 500 ms | 0 |
| Mean lookup duration | 1.7 ms | 44.1 ms | 151 ms | 152 ms |

**Reading.**
- The check of a version 0 behaves as before: one round, sometimes two, about
  two round trips in WAN Europe.
- **The check of a later version fits within `STORE_LOOKUP_TIMEOUT` (2 s)** on
  every profile, with its fetch: at most 500 ms across the Atlantic, where a
  round trip is 70 ms. ADR 0005 asked to stop and ask before changing the
  timeout if it did not fit; it fits. The samples are few (6 fetches); A4 adds
  the checks of 20 more rounds in WAN Europe.
- A check fetches version N−1 only when some node asked still holds it. Most
  checks find the other replicas already on version N, which vote for it
  without a fetch.

## 6. E4. Rotation and a replica restarted empty

**Question.** How long does a rotation take, what does it cost, and is a
replica that restarted empty filled with the new version? On `main` such a
replica refused the owner's STORE of the new version while the old one was
still on other replicas (the known gap that ADR 0005 closes).

**Setup.** Each round the owner publishes a new DID; one replica holding it
crashes and restarts empty; the owner rotates its key (`update`). 20 rounds
per profile without counters (time), 10 with counters (traffic, checks),
both images.

**Results.** Every rotation was confirmed, and every replica that did not
restart and every read by the other 126 nodes had the new version, on both
images.

| Profile | Image | Rotation, median (p95) | Restarted replica holds the new version, timing runs | The same, counter runs |
|---|---|---|---|---|
| LAN | `main` | 6.4 ms (7.4) | 16/20 | 7/10 |
| LAN | ADR 0005 | 5.7 ms (6.8) | **20/20** | **10/10** |
| WAN Europe | `main` | 122 ms (127) | 18/20 | 6/10 |
| WAN Europe | ADR 0005 | 109 ms (122) | **20/20** | **10/10** |
| WAN Trans-Atlantic | `main` | 579 ms (583) | 19/20 | 8/10 |
| WAN Trans-Atlantic | ADR 0005 | 509 ms (579) | **20/20** | **10/10** |
| WAN Europe, 0.5% loss | `main` | 122 ms (211) | 9/20 | 3/10 |
| WAN Europe, 0.5% loss | ADR 0005 | 178 ms (255) | **20/20** | **10/10** |

On `main` the restarted replica stayed empty in 34 of 120 rounds; its check
ended `other` in 16 of the 40 counter rounds: another replica still held the
old version, so it refused the new one (the known gap). With ADR 0005 it held
the new version in 120 of 120.

Traffic per rotation, counter runs, medians, all nodes together:

| | `main` | ADR 0005 |
|---|---|---|
| `Update` | 194.3 KiB, 160 datagrams | 131.9 KiB, 100 datagrams |
| `Update` datagrams per `UpdateResult` | 8.00 (8.53 with loss) | 5.00 (5.05 with loss) |
| The owner's read of a copy first (`FindValue`, `FindValueHit`) | 16.1 KiB, 15 datagrams | none |
| **Total**, LAN / WAN Europe / Trans-Atlantic / 0.5% loss | 247 / 248 / 247 / 253 KiB | 170 / 170 / 168 / 171 KiB |

**Reading.**
- **The known gap is closed.** A replica that restarted empty gets the new
  version every time: the owner's UPDATE gets `MissingPrevious`, and its
  STORE of the new version passes R5 at once, since the other replicas
  already hold it or its predecessor.
- **A rotation costs about 31% less traffic**, 170 KiB instead of 247: an
  UPDATE carries the record only, 5 fragments instead of 8, and the owner no
  longer reads a copy before sending.
- A rotation takes about as long, or less, without loss. Under loss its median
  is 56 ms longer: the owner now fills the restarted replica every time, a
  check and a STORE more, where on `main` the replica stayed empty in 11 of 20
  rounds.

## 7. A1. Race and burst attacks on a restarted replica

**Question.** Can an attacker that reads all traffic get a forged record onto
a replica that has just restarted empty, by racing the owner after an UPDATE?

**Setup.** The attacker runs in the host's network namespace: it sees every
container's packets and can send its own, but cannot change or drop the
owner's. Since ADR 0005 it forges a version with the owner's DID and the
`prev` of the version it saw, self-signed with a key of its own, which no
version committed to. No extra delay. 10 nodes, `k` = 3 (as before ADR 0005),
then 127 nodes, `k` = 20, WAN Europe.

**Procedure.** Each round: the owner publishes a new DID; one of its replicas
crashes and restarts empty; the owner rotates its keys (UPDATE). In `race`
mode the attacker sends one forged STORE to the replica as soon as it sees the
UPDATE; in `burst` mode 64 at once from 16 ports.

**Results.** 20 rounds each. On the branch the restarted replica was empty
before the update in every round.

| Network, mode | Image | Attacker wins | Restarted replica holds the owner's record / stays empty | Owner's update | Other replicas intact | Plain reads returning a forged record | Forged STOREs answered |
|---|---|---|---|---|---|---|---|
| 10 nodes, LAN, race | ADR 0005 | 0/20 | 20 / 0 | confirmed 20/20 | 31/31 | 0/60 | 51, all `Conflict` |
| 10 nodes, WAN Europe, race | `main` | 0/20 | 15 / 5 | confirmed 20/20 | 35/35 | 0/60 | |
| 10 nodes, WAN Europe, race | ADR 0005 | 0/20 | 20 / 0 | confirmed 20/20 | 35/35 | 0/60 | 55, all `Conflict` |
| 10 nodes, WAN Trans-Atlantic, race | ADR 0005 | 0/20 | 20 / 0 | confirmed 20/20 | 38/38 | 0/60 | 58, all `Conflict` |
| 10 nodes, WAN Europe, burst | `main` | 0/20 | 14 / 6 | confirmed 20/20 | 34/34 | 0/60 | |
| 10 nodes, WAN Europe, burst | ADR 0005 | 0/20 | 20 / 0 | confirmed 20/20 | 36/36 | 0/60 | 3584, all `Conflict` |
| 127 nodes, WAN Europe, race | ADR 0005 | 0/20 | 20 / 0 | confirmed 20/20 | 377/377 | 0/60 | 357, all `Conflict` |
| 127 nodes, WAN Europe, burst | ADR 0005 | 0/20 | 20 / 0 | confirmed 20/20 | 379/379 | 0/60 | 20,928, all `Conflict` |

The `main` rows are the baseline of 2026-11-11 (the answers the attacker got
were in its log, which was not kept). The attacker sent its forged STORE 0.4 to
2.2 ms (median) after seeing the UPDATE.

**Reading.**
- No forged version was stored, on either image. A forged version N carries
  the owner's `prev` but a key that version N−1 did not commit to: the empty
  replica either hears another version N from the other replicas, or fetches
  version N−1 and finds it commits to another key.
- **The restarted replica now always gets the owner's version**: 20 of 20 in
  every network, against 15 and 14 of 20 on `main`, where it stayed empty
  while another replica still held the old version (the known gap, E4).

## 8. A2. Persistent attacker and restarts

**Question.** What does an attacker achieve that sends forged records for
every DID it sees, to every node, all the time?

**Setup.** In `persist` mode the attacker learns DIDs from the STOREs and
UPDATEs it sees and, every 100 ms, sends a forged STORE for each DID seen in
the last 20 s to every node. 10 nodes, `k` = 3, WAN Europe, then 127 nodes,
`k` = 20, WAN Europe.

**Procedure.** Each round: the owner publishes a new DID; after 0.5 s one of
its replicas crashes and restarts empty; 3 s later the script reads what the
restarted replica holds, how many nodes hold a forged record of that DID, and
what three plain reads return. A control run without the attacker comes
first.

**Results.** 20 rounds each.

| Network | Image | Restarted replica: owner's / forged / empty | Owner's publication | Nodes holding a forged record | Plain reads returning it |
|---|---|---|---|---|---|
| 10 nodes, no attacker | `main` | 0 / 0 / 20 | complete 20/20 | 0/180 | 0/60 |
| 10 nodes, persistent attacker | `main` | 0 / 0 / 20 | complete 20/20 | 0/180 | 0/60 |
| 10 nodes, no attacker | ADR 0005 | 0 / 0 / 20 | complete 20/20 | 0/180 | 0/60 |
| 10 nodes, persistent attacker | ADR 0005 | 0 / 0 / 20 | complete 20/20 | 0/180 | 0/60 |
| 127 nodes, no attacker | ADR 0005 | 0 / 0 / 20 | complete 20/20 | 0/2520 | 0/60 |
| 127 nodes, persistent attacker | ADR 0005 | 0 / 0 / 20 | complete 20/20 | 0/2520 | 0/60 |

With ADR 0005 the attacker's forged STOREs were answered `Conflict` 29,826
times and not answered 3075 times on 10 nodes, `Conflict` 168,281 times and not
answered 167,871 times on 127 nodes; none was `Stored`. A node that holds
nothing runs a check for each forged STORE, and beyond 256 checks at once it
drops the STORE without an answer (`MAX_STORE_LOOKUPS`).

**Reading.**
- No node took a forged record, on either image, in these runs. Before ADR
  0005 a persistent attacker could still win the first-publication window: on
  2026-11-04 it put a forged record on 6 nodes in 1 round of 20, by racing the
  owner's first STOREs. With ADR 0005 that window has no prize: a forged
  version 0 does not bind to the DID, and a forged version 1 is refused (A3).
- Without an update, the restarted replica is still empty after 3 s in every
  round, on both images and at both sizes: its neighbours do not notice a node
  that comes back within about a second, so they send it nothing. The hourly
  republication, or the owner's next update or republication, fills it (L1).

## 9. A3. A forged version 1 right after version 0

**Question.** The key security case of ADR 0005: right after the owner
publishes version 0, can a forged version 1, whose `prev` is the real hash of
version 0 but signed by a key whose hash is not the `nextKeyHash` of version
0, get onto any node?

**Setup.** In `successor` mode the attacker answers each STORE of a version 0
it sees with a forged version 1 to the same node, at once. 10 nodes, `k` = 3,
WAN Europe, then 127 nodes, `k` = 20, WAN Europe.

**Procedure.** Each round: the owner publishes a new DID; 3.5 s later the
script reads how many nodes hold a forged record and what three plain reads
return. No replica restarts.

**Results.** 20 rounds each.

| Network | Forged versions 1 sent | Answered | Nodes holding a forged record | Plain reads returning it | Owner's publication |
|---|---|---|---|---|---|
| 10 nodes, `k` = 3 | 55 | all `Conflict` | 0/180 | 0/60 | complete 20/20 |
| 127 nodes, `k` = 20 | 367 | all `Conflict` | 0/2520 | 0/60 | complete 20/20 |

**Reading.** The forged version 1 was sent about 1 ms after the owner's
version 0, and no node took it: a node holding version 0 checks the forged key
against its `nextKeyHash` (R3), and an empty one hears version 0 from the
others and finds the same mismatch (R5). The owner's publication was not
disturbed.

## 10. A4. Nodes that lie in `FindHash`

**Question.** How many nodes that lie in the check of an empty replica does it
take to block a publication, or the repair of a replica restarted empty?

**Setup.** A testbed switch, compiled only with the `testbed` feature
(`ctl <node> lie on`), makes a node answer every `FindHash`, for any key, with
a version far ahead (`seq` 2^53 − 1) and a made-up hash it never serves; it
stores and serves records as usual. Each round the liars are the replicas
closest to the key, those every check asks: 0, 1, 12 (one below the quorum)
and 13 (the quorum). 127 nodes, `k` = 20, WAN Europe, the procedure of E4 with
counters.

**What ADR 0005 predicts.** A version 0 at an empty replica (R2) is refused
only when a quorum claims a later version, so that a single holder of a later
version cannot stop the owner's replay: 1 to 12 liars do not block a first
publication, 13 do. A later version at an empty replica (R5) is refused on a
single claim of a version ahead of it: one liar blocks the repair. This is the
single liar's veto the review of ADR 0005 recorded; removing it (refusals that
show their evidence) is a later ADR.

**Results.** 20 rounds each, 127 nodes, `k` = 20, WAN Europe.

| Liars | Publication of version 0 | Replicas storing it, median | Restarted replica holds the new version | Checks of the restarted replica | Reads by every other node |
|---|---|---|---|---|---|
| 0 | complete 20/20 | 20 | 20/20 | `accepted` 20 | 2520/2520 |
| 1 | complete 20/20 | 20 | **0/20** | `newer_claimed` 60 | 2520/2520 |
| 12 | complete 20/20 | 20 | **0/20** | `newer_claimed` 60 | 2520/2520 |
| 13 (quorum) | **rejected 20/20** (`NewerVersion`) | 13 (the liars), 7 refusing | no replica to restart | `newer_claimed` 396 | 2520/2520 |

With 13 liars no honest replica stored the record (132 of the 392 replica
slots stayed empty over the 20 rounds); the 13 liars, which store and serve
records as usual, held it, and every read found it there. The rotation was
`confirmed` with 0 to 13 liars: the owner and the replicas that hold the record
form its majority.

**Reading.**
- As predicted: up to 12 liars do not block a first publication, 13 do; one
  liar blocks the repair of a replica restarted empty, every time: every check
  of the restarted replica, three per round, ended `newer_claimed`.
- A liar cannot get a forged record accepted or change what readers get here;
  it keeps empty replicas empty. On `main` one node could already do so,
  by answering another hash or by not answering (section 7 of `DESIGN.md`);
  ADR 0005 keeps that veto for later versions and removes it for a version 0,
  where a quorum is needed. Here the liars claim a later version; a liar that
  claims another version 0, or stays silent, also blocks the owner's replay
  from version 0. That variant was not measured.

## 11. A5. Spoofed answers under guessed message ids

**Question.** Message ids are drawn at random for each request (ADR 0005, open
point 25). Can an attacker who does not read them get a forged `FindHash`
answer accepted by a replica, by sending it from the address of the node the
replica asked?

**Setup.** In `spoof` mode the attacker answers each `FindHash` it sees with 64
answers claiming a version far ahead, sent to the asking replica from the
address and port of the node asked (a raw socket writes the IP header), under
random message ids. As a control, the same with the ids read on the wire: it
shows the spoofed answers reach the replica, and that the id is what stops
them; an attacker who reads the traffic still sees every id, which stays a
limit. 127 nodes, `k` = 20, WAN Europe, the procedure of E4 with counters. A
check that took a spoofed answer ends `newer_claimed` where it would have
accepted.

**Results.** 20 rounds each, 64 spoofed answers for each `FindHash` the
attacker saw (about 20 per round).

| Spoofed answers under | Checks of the restarted replica | Restarted replica holds the new version | Publication of version 0 |
|---|---|---|---|
| no attacker (A4, 0 liars) | `accepted` 20 | 20/20 | complete 20/20 |
| random ids | `accepted` 20, `newer_claimed` 0 | 20/20 | complete 20/20 |
| the ids read on the wire (control) | `accepted` 5, `newer_claimed` 45 | 5/20 | complete 20/20 |

**Reading.**
- Under random ids no spoofed answer was taken: the replica's checks ended as
  without an attacker.
- The control shows the spoofed answers reach the replica and are taken when
  their id is right: they blocked the repair in 15 of 20 rounds. The ids are
  what stops an attacker that does not read the traffic; one that reads it
  answers for any node it sees asked, and has the single liar's veto of A4.
- The first publication was not blocked in the control either: a version 0 is
  refused only on a quorum of claims, which the spoofed answers did not reach.

## 12. L1. Copies over time with churn and liars

**Question.** How many replicas keep the current version over time while
nodes crash and come back empty, with 0, 1 or a quorum of liars near the key?
The review of ADR 0005 calls this the weakest property of the design; no
system it cites reports it.

**Setup.** The owner publishes a new DID and rotates once. For 10 minutes,
every 10 s one of the `k` replicas other than the owner and the liars crashes
and comes back empty; every 60 s the owner sends its current version again
with the saved bytes (`republish`, which the application does at least once
every 24 hours, ADR 0005 section 5); every 5 s the script counts what the
replicas hold. 0, 1 and 13 liars, 127 nodes, `k` = 20, WAN Europe.

**Results.** 600 s, 59 crashes of a replica and 9 republications per run, 120
samples. Copies of the current version on the replicas other than the owner
(20, or 19 when the owner is one of the `k` closest):

| Liars | Copies, median (min, max) | Samples below the quorum (13) | Republications |
|---|---|---|---|
| 0 | 18 (15, 20) | 0/120 | confirmed 9/9 |
| 1 | 15 (10, 20) | 26/120 | confirmed 9/9 |
| 13 | 13 (13, 13), all on the liars | 0/120, but no honest copy | confirmed 9/9 |

**Reading.**
- Without liars, each crash takes a copy away and nothing fills it until the
  owner's republication, which fills every empty replica at once: the copies
  go from 20 down to 15 and back every minute, never below the quorum. The
  holders' hourly republication did not run: the records were younger than
  an hour.
- With one liar the copies follow a cycle. While 13 or more replicas hold the
  record, the liar blocks every repair and crashes take copies away; once
  fewer hold it, the owner's replay starts from version 0, which one claim of
  a later version does not block, then sends the later versions by UPDATE,
  which a replica checks against the version before without asking anyone; it
  fills every empty replica at once. The record spent about a fifth of the
  time below the quorum, never below 10 copies, and the owner's republication
  is what kept it.
- With 13 liars the honest replicas refused the first publication and stayed
  empty for the whole run; the record lived only on the liars. A quorum of
  liars near a DID decides what the DID's honest replicas hold.
- The time scale is compressed: a crash every 10 s and a republication every
  60 s stand for rarer crashes and a republication at least every 24 hours.
  What the runs show is the shape: with a liar the copies depend on the
  owner's republication.

## 13. L2. Replicas lost while the owner is offline

**Question.** With ADR 0005, an empty replica accepts a later version from
the holders' republication only when a quorum of the nodes it asks hold it,
and the owner is the one who restores copies below the quorum (ADR 0005,
Consequences). How does the record recover when several replicas lose their
copy at once, for example in a power cut at one site, while the owner is
offline? `main` has no quorum: an empty replica takes a record that no node
contradicts.

**Setup.** The owner publishes a new DID and rotates once, then is frozen
(`docker pause`, so that it keeps its versions and does not answer). M of the
replicas holding the current version crash and come back empty at once, with
M = 4, 7, 8, 12 and 16. Each replica that still holds the record then sends it
to the `k` nodes closest to the key, one after the other, as the hourly
republication does (testbed command `push`), and the script counts what the
replicas hold. On the branch the owner then comes back and sends its current
version again with the saved bytes (`republish`), and the replicas are
counted once more. 5 rounds per M, a new DID each, 127 nodes, `k` = 20, WAN
Europe. The `main` image adds only the testbed's `push` command to `424b76f`
(`main-push.patch`). No host drops. Data in
`experiments/2026-11-11-owner-outage/`.

**Results.** Rounds in which every replica held the current version again,
and copies of the current version after the holders' republication (median
of 5; 20 replicas, or 19 when the owner is one of the `k` closest):

| Replicas lost | Holders left | `main`: restored by the holders | Branch: restored by the holders | Branch: after the owner's return |
|---|---|---|---|---|
| 4 | 15–16 | 5/5 (20) | 5/5 (20) | 5/5 |
| 7 | 12–13 | 5/5 (20) | 4/5 (20) | 5/5 |
| 8 | 11–12 | 5/5 (20) | 0/5 (12) | 5/5 |
| 12 | 7–8 | 5/5 (20) | 0/5 (8) | 5/5 |
| 16 | 3–4 | 5/5 (20) | 0/5 (4) | 5/5 |

**Reading.**
- On `main` the holders refill every empty replica, down to 3 holders left:
  each empty replica takes the record from the first holder that sends it.
- On the branch the threshold is exactly the quorum. With 13 holders or more
  the first STORE fills each empty replica; with 12 or fewer every STORE to an
  empty replica goes unanswered (its check finds too few votes) and the
  copies stay where the loss left them. The one round of 7 lost that was not
  restored had 19 replicas, so 12 holders.
- When the owner comes back, its republication restores every replica in
  every round, down to 3 holders left: version 0 needs no votes and each
  later version is checked against the one before.
- This is the price of the quorum: a later version cannot be checked by an
  empty replica on its own, so the branch accepts it only on the word of a
  quorum, and fewer than a quorum of colluding nodes cannot vouch for a forged
  version. `main` accepts on the absence of contradiction, which also accepts
  a forged record when no holder answers.
- The time scale is compressed. Below the quorum, the copies of a DID wait
  for the owner, who republishes at least once every 24 hours and when it
  comes back online; meanwhile the remaining holders keep the record readable
  and refresh each other's expiry. A record whose owner is offline for more
  than 14 days and that falls below the quorum cannot be restored by the
  network.

## 14. L3. What readers get in the worst case

**Question.** In the situation of L2 below the quorum, with the owner offline
and empty replicas that the holders cannot refill, and with an attacker that
keeps sending forged versions to every node: does a reader get the owner's
record, a forgery, or nothing? Two readers: a node that has been in the
network all along, and a node that joins at that moment, with an empty routing
table.

**Setup.** As L2: 127 nodes, `k` = 20, WAN Europe, the owner frozen after one
rotation, M = 8, 12, 16 or 20 replicas holding the current version restarted
empty at once, 5 rounds each, then the holders' republication. In addition:
- a persistent attacker (`attack.py start --mode persist --period 1000
  --did-ttl 60`): for 60 s after it sees a DID it sends every node, every
  second, a forged version of it, with the owner's DID and `prev` and a key of
  its own;
- after the holders' republication, with the owner still offline, every node
  but the owner reads the DID once (126 readers), and 3 nodes kept outside the
  network (130 in all) join it, bootstrap from the seeds and read it once;
- on the branch the owner then comes back and republishes, and the 126 nodes
  read again.

A read is classified by the key that signed what it got: one of the owner's
versions (signed, whether or not its rotation reached a majority), the forged
key that the attacker logged for that DID, or nothing. No read got a record
signed by any other key. The host dropped 4,089 datagrams during the `main`
run and 1,931 during the branch run: the attacker's load costs availability
on this host, which the results show; it cannot make a node accept a record.
Data in `experiments/2026-11-11-owner-outage/reads/`.

**Results.** All 20 rounds of each image; reads written owner's / forged /
nothing:

| | `main` | Branch |
|---|---|---|
| Forged STOREs the nodes stored | 29,865 | **0** |
| Reads by the nodes in the network | 1,172 / 1,228 / 120 | 1,328 / **0** / 1,192 |
| Reads by the nodes that joined | 27 / 32 / 1 | 24 / **0** / 36 |
| Reads after the owner's return | | 2,097 / 0 / 423 |
| First publications complete / degraded / failed | 11 / 4 / 5 | 10 / 6 / 4 |

The rounds whose first publication reached every replica, so that only the
loss and the attack differ:

| Replicas lost | `main`: rounds, reads in the network, reads by joiners | Branch: rounds, reads in the network, reads by joiners | Branch, after the owner's return |
|---|---|---|---|
| 8 | 3: 378 / 0 / 0, 9 / 0 / 0 | 3: 378 / 0 / 0, 9 / 0 / 0 | all replicas restored, 378 / 0 / 0 |
| 12 | 1: 126 / 0 / 0, 3 / 0 / 0 | 2: 252 / 0 / 0, 6 / 0 / 0 | all restored, 252 / 0 / 0 |
| 16 | 1: 126 / 0 / 0, 3 / 0 / 0 | 2: 252 / 0 / 0, 6 / 0 / 0 | all restored, 252 / 0 / 0 |
| 20 | 2: 0 / **252** / 0, 0 / **6** / 0 | 3: 0 / 0 / 378, 0 / 0 / 9 | all restored, 378 / 0 / 0 |

**Reading.**
- **On the branch no node stored a forged version and no reader got one**, in
  any round, in the network or just joined. A holder refuses a forged
  version as a second version with the same number, or because its key is
  not the one the version before committed to; an empty node refuses it
  because its check finds the genuine version, or too few votes.
- **Below the quorum, while one holder remains, every reader gets the owner's
  record**: with 8, 12 or 16 replicas lost, every read of the rounds whose
  publication reached every replica, also on `main`. The empty replicas that the holders cannot refill hold nothing, so
  they give a reader no wrong record, and its lookup goes on to a holder.
- **With every replica lost**, the branch's readers get nothing until the
  owner returns, and then every read gets its record. `main`'s readers get the
  attacker's forgery: an empty replica on `main` takes a record that no node
  contradicts, and with no holder left nothing does.
- **`main` is also exposed at the first publication.** In the rounds where its
  publication did not reach every replica, the forgery reached replicas and
  readers; on the branch those rounds left replicas empty, and readers got the
  owner's record or nothing.
- **The attacker costs availability on both images**: half of the first
  publications did not reach every replica, because the checks of empty
  replicas, flooded with forged STOREs, did not hear from every node they
  asked in time and refused, as they must on silence. In those rounds many
  branch readers found nothing, and the owner's return restored most reads
  (2,097 of 2,520 in all rounds), not always the replicas. The attacker can
  deny service; it cannot get a record accepted.
- **A node that joins at that moment gets the same kinds of answer** as the
  nodes in the network: the owner's record where copies remained, a forgery
  only on `main`. Where copies were scarce it found the record somewhat less
  often (branch: 24 of 60 reads, against 1,328 of 2,520).
- These readers make plain reads, which take the first record that verifies.
  This attacker does not answer reads; one that reads the traffic could answer
  a lookup for the nodes asked with a self-signed forgery, which a read would
  return. The application compares the key with the one bound in the
  credential (`DESIGN.md`, section 8).

**First run, discarded.** A first run with a heavier attacker (every 500 ms,
120 s per DID) made the host drop 12,368 datagrams during the branch run, and
counted the owner's version 1 as another record when its rotation did not
reach a majority. It is kept in `reads/discarded-first-run/` and not used. Its
attacker logs agree with the results above: on the branch no forged STORE was
stored (`Stored` 0, `AlreadyStored` 0), on `main` 322 were.

## 15. Summary

Validated on the code of ADR 0005:
- **Publication and availability.** 100 first publications in a network of 127
  nodes (`k` = 20), in LAN, WAN Europe, WAN Trans-Atlantic and WAN Europe with
  0.5% loss: all `complete`, and all 12,600 reads right after found the
  record. Latency and traffic as before ADR 0005 (on WAN 3% slower, 1.2 ms in
  LAN; about 630 KiB per publication).
- **Rotation.** A replica restarted empty gets the new version 120 times of
  120, against 86 on `main`: the known gap is closed. A rotation sends 170 KiB
  instead of 247 (an UPDATE in 5 fragments instead of 8, no read first), and
  takes about as long.
- **Forged records.** None stored in 160 rounds of race, burst and
  persistent attacks at 10 and 127 nodes (about 223,000 forged STOREs answered
  `Conflict` and 171,000 dropped unanswered, none `Stored`), nor in 40 rounds
  of a forged version 1 right after version 0.
- **Check of a later version.** At most 500 ms with its fetch across the
  Atlantic: it fits within `STORE_LOOKUP_TIMEOUT` (2 s).
- **Message ids.** No spoofed answer under a guessed id was taken; under the
  ids read on the wire they were.

Measured costs and limits:
- **One liar near a DID** keeps its empty replicas empty (0 of 20 repairs);
  with churn the copies then depend on the owner's republication, and spent a
  fifth of the time below the quorum. **A quorum of liars** blocks a first
  publication and keeps every honest replica empty.
- **An attacker that reads the traffic** can answer for other nodes, with the
  power of a liar.
- **A replica that restarts empty without an update** stays empty until a
  republication, on `main` as with ADR 0005: its neighbours do not notice a
  node that comes back within a second. Under churn the copies of a record
  younger than an hour come back only through the owner's republication (L1).
- **Replicas lost while the owner is offline.** With 13 holders or more the
  holders' republication refills the empty replicas, as on `main`; with 12 or
  fewer it refills none, where `main` refills all, and the copies wait for the
  owner, whose return restores them all (L2).
- **Readers in the worst case**, with the owner offline, replicas lost and a
  persistent attacker: on the branch no reader, in the network or just
  joined, got a forged record, and no node stored one; while a holder remains
  readers get the owner's record, with none left they get nothing until the
  owner returns. On `main`, with no holder left, every reader got the
  attacker's forgery (L3). The attacker's flood still costs availability on
  both: half of the first publications did not reach every replica.
- **Traffic of a first publication**: about 630 KiB at `k` = 20, 73% of it in
  the answers to the replicas' checks.
- **Tail under loss**: publications of 0.5 to 1.1 s under 0.5% loss.

## 16. How to reproduce

Host limits, once per boot:

```bash
sudo sysctl -w net.ipv4.neigh.default.gc_thresh1=4096 net.ipv4.neigh.default.gc_thresh2=16384 net.ipv4.neigh.default.gc_thresh3=32768
sudo sysctl -w net.core.netdev_max_backlog=16384
```

The two images: the branch from commit `f4a9a2a`, `main` from a worktree of
`424b76f`:

```bash
testbed/testbed.py build --tag auth-kademlia-testbed:adr0005-final
git worktree add ../main-424b76f 424b76f
testbed/testbed.py build --tag auth-kademlia-testbed:main-424b76f --context ../main-424b76f
```

Every experiment, one network at a time, as run on 2026-11-11:

```bash
experiments/2026-11-11-adr0005/run_experiments.sh all   # or: compare, attacks
```

L2 runs on two images with the testbed's `push` command: the branch from
commit `01451e0`, `main` from the worktree of `424b76f` with
`experiments/2026-11-11-owner-outage/main-push.patch` applied:

```bash
testbed/testbed.py build --tag auth-kademlia-testbed:adr0005-push
git -C ../main-424b76f apply "$PWD/experiments/2026-11-11-owner-outage/main-push.patch"
testbed/testbed.py build --tag auth-kademlia-testbed:main-424b76f-push --context ../main-424b76f
experiments/2026-11-11-owner-outage/run_outage.sh
```

L3 runs on the same two images, with `testbed/measure.py` as committed with
`--reads` and `--joiners`, and is analysed with the two scripts beside its
data:

```bash
experiments/2026-11-11-owner-outage/reads/run_outage_reads.sh
python3 experiments/2026-11-11-owner-outage/reads/check_forged.py <run>.json <side>-attacker-log.txt
python3 experiments/2026-11-11-owner-outage/reads/digest_reads.py <run>.json
```

One step by hand, for example E1 on WAN Europe:

```bash
testbed/testbed.py up --nodes 127 --k 20 --alpha 3 --profile wan-eu --image auth-kademlia-testbed:adr0005-final --no-build
testbed/measure.py publish --rounds 20
testbed/testbed.py down
```

Each run writes its rounds to `testbed/.generated/` (not in the repository).
