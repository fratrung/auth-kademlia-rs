# Experiments

This file collects the experiments that validate how AuthKademlia nodes and the
DHT behave, run on the Docker testbed (`testbed/`) against the current code:
how fast a record is published and read, what it costs in traffic, and what an
attacker who reads the network can achieve. The measurements that led to fixes
are in `testbed/README.md` and in the commit history; they are not repeated
here.

Each experiment states the question it answers, how it is run, what is
measured, the results and how to read them.

**The results predate ADR 0003 and ADR 0004**: they were measured with
Dilithium-2 records and 160-bit ids. E1 and E2 must be measured again with
ML-DSA-65 records and 256-bit ids (section 1).

## Contents

1. [Environment](#1-environment)
2. [What is measured](#2-what-is-measured)
3. [E1. Publication and read latency](#3-e1-publication-and-read-latency)
4. [E2. Traffic per publication and per read](#4-e2-traffic-per-publication-and-per-read)
5. [E3. The empty-replica check and resends](#5-e3-the-empty-replica-check-and-resends)
6. [A1. Race and burst attacks on a restarted replica](#6-a1-race-and-burst-attacks-on-a-restarted-replica)
7. [A2. Persistent attacker and restarts](#7-a2-persistent-attacker-and-restarts)
8. [Summary](#8-summary)
9. [How to reproduce](#9-how-to-reproduce)

## 1. Environment

**Code.** Commit `fc79016` (an empty replica asks all the nodes it knows at
once) with the counters of `src/counters.rs`, which only count. Testbed image
`auth-kademlia-testbed:o2-counters`, release build, Rust 1.98.1. For the
before/after comparisons, commit `e383d17`, the same code without `fc79016`.
All runs on 2026-11-04.

**Records since ADR 0003.** These runs used Dilithium-2 records, about 6 KB in
5 fragments. Records are now signed with ML-DSA-65 and carry no KEM key: about
6.5 KB, still 5 fragments, with a slower verification. E1 (latency) and E2
(traffic) must be measured again; A1 and A2 are not expected to change. Since
ADR 0004 ids and keys are 256 bits, 12 bytes more each in every message. Until
then the numbers below describe the Dilithium-2 code with 160-bit ids.

**Host.** AMD Ryzen 7 4800H (8 cores, 16 threads), 15 GB RAM, Linux 7.0,
Docker 29.9.2. All containers share the host's CPU and kernel; no CPU limit
per container.

**Host limits.** Raised as `testbed/README.md` requires for more than about
30 nodes: the neighbour table (`gc_thresh1..3` = 4096, 16384, 32768) and the
per-CPU receive backlog (`net.core.netdev_max_backlog` = 16384). With the
default backlog the host drops datagrams between containers without any
emulated loss; every run here was checked to have no such drop (second column
of `/proc/net/softnet_stat`, before and after each run).

**Network.** One node per container. `tc netem` delays each container's
egress, so a request and its answer cross two delays.

| Profile | RTT | Source |
|---|---|---|
| `lan` | no delay added (Docker bridge, about 0.16 ms) | |
| `wan-eu` | 13.6 ms | Verizon backbone, Europe, monthly average |
| `wan-atlantic` | 70.4 ms | Verizon backbone, Trans-Atlantic, monthly average |

Loss, when set, applies per direction. 0.5% is Verizon's delivery target (at
least 99.5% of packets).

**Nodes.** 3 seeds; every node bootstraps from them. A record is a DID
Document signed with Dilithium-2, about 6 KB, sent in 5 fragments. Node ids
are derived from container names; storage is in memory, so a restarted node is
empty.

**Sample sizes.** 20 publications per configuration, 40 with loss; attacks 20
rounds. A p95 over 20 samples is the 19th value: read it as "the slowest
publications", not as a precise percentile.

## 2. What is measured

| Metric | Definition |
|---|---|
| Publication time | `Server::set_detailed` timed inside the owner: lookup of the `k` closest nodes, then a STORE to each, including each empty replica's network check; it ends when every replica has answered or timed out |
| Outcome | `complete` (every node that answered holds the record), `degraded` (some replica unavailable), `rejected` |
| Readable by the first watcher | Three other nodes read the DID in a loop from 0.5 s before the publication; time from the start of the publication to the first successful read (containers share the host clock) |
| Reads right after | Every other node reads the DID once after the publication |
| Remote read time | `Server::get` on a node without a local copy |
| Traffic | Datagrams and bytes sent by all nodes, by message type, from the counters (`ctl <node> counters`). Bytes are UDP payloads including the 12-byte KADF header, without IP, UDP and Ethernet headers (42 bytes per datagram on Ethernet) |
| Check | For each STORE to an empty replica: outcome, rounds of its lookup, duration |
| Resends | Requests sent again, split by whether the peer's round trip was measured when the request was first sent |

Reading the counters runs `docker exec` in all 127 containers just before each
publication, which loads the host. Latency (E1) is therefore measured in
separate runs without counters; the publication times of the counter runs (E2,
E3) are not used as latency.

## 3. E1. Publication and read latency

**Question.** How long does a first publication take in a network of 127
nodes, and can every other node read the record right after?

**Setup.** 127 nodes, `k` = 20, `alpha` = 3. The owner (`node-1`) publishes a
new DID each round.

**Results.** Every publication was `complete` and every read right after found
the record.

| Profile | Publication, median (p95) | First watcher, median (p95) | Reads right after | Remote read, median (p95) |
|---|---|---|---|---|
| LAN | 7.8 ms (11.4) | 6.0 ms (7.9) | 2520/2520 | 1.8 ms (6.5) |
| WAN Europe | 84.8 ms (93.3) | 64.0 ms (69.2) | 2520/2520 | 15.6 ms (45.8) |
| WAN Trans-Atlantic | 401 ms (440) | 299 ms (309) | 2520/2520 | 72.2 ms (216) |
| WAN Europe, 0.5% loss, 40 rounds | 164 ms (591, max 1581) | 68.3 ms (115) | 5040/5040 | 15.5 ms (20.7) |

**Reading.**
- On WAN a publication takes about 6 round trips (Europe 6.2, Trans-Atlantic
  5.7): the owner's lookup, the STORE, and in between each replica's check,
  which takes one or two more (E3). In LAN, with round trips of about
  0.16 ms, the time is mostly processing, including a Dilithium verification
  at each replica (about 5 ms on x86).
- The record is readable before the owner's call returns: the first watcher
  finds it one to one and a half round trips earlier, once the first replicas
  store it.
- A remote read takes about one round trip in the median: one round of three
  requests reaches a holder. The p95 of about three round trips is a read that
  needs one or two more hops.
- Under 0.5% loss nothing failed, but the slowest publications take 0.5 to
  1.6 s. The values cluster near 0.57 s and 1.1 s, about one and two waits of
  500 ms: the wait before resending a request to a peer whose round trip has
  not been measured yet. This is consistent with the resend rules, not yet
  attributed message by message.

**Effect of asking all close nodes at once (`fc79016`).** Same session,
images alternated per profile, no host drops:

| Profile | Before (`e383d17`) | After (`fc79016`) |
|---|---|---|
| LAN, median (p95) | 8.2 ms (10.1) | 7.8 ms (11.4) |
| WAN Europe, median (p95) | 87.2 ms (123.3) | 84.8 ms (93.3) |
| WAN Europe, first watcher, median | 77.3 ms | 64.0 ms |
| WAN Trans-Atlantic, median (p95) | 504 ms (513) | 401 ms (440) |
| WAN Europe 0.5% loss, median (p95) | 183 ms (1151) | 164 ms (591) |

The gain grows with the round-trip time: about 100 ms, one and a half round
trips, across the Atlantic; little on the European median, more on its slowest
publications.

## 4. E2. Traffic per publication and per read

**Question.** What does a first publication cost the network, and what does a
remote read cost?

**Setup.** As E1, with `--watchers 0 --counters`: no node reads during the
publication, and the counters of every node are read before the publication,
0.3 s after it, and after the reads that follow.

**Results.** Medians per publication, all nodes together.

| Message | LAN | WAN Europe | WAN Europe, 0.5% loss |
|---|---|---|---|
| `Store` (owner to replicas) | 120.3 KiB, 100 | 120.3 KiB, 100 | 132.3 KiB, 110 |
| `FindHash` (check questions) | 24.4 KiB, 410 | 24.2 KiB, 406 | 24.3 KiB, 408 |
| `FindValueNodes` (answers with closer nodes) | 357.5 KiB, 409 | 373.1 KiB, 426 | 366.2 KiB, 420 |
| `FindHashHit` (answers with a hash) | 1.0 KiB, 20 | 0, 0 | 0.3 KiB, 6 |
| `FindValue` (owner's lookup) | 1.2 KiB, 20 | 1.2 KiB, 20 | 1.2 KiB, 20 |
| `Received`, `StoreResult` | 0.9 KiB, 40 | 0.9 KiB, 40 | 1.0 KiB, 42 |
| **Total** | **503 KiB, 999 datagrams** | **520 KiB, 993** | **526 KiB, 1014** |

A remote read, averaged over about 2100 reads per run (4200 with loss):

| | LAN | WAN Europe | WAN Europe, 0.5% loss |
|---|---|---|---|
| Total | 16.6 KiB, 17.2 datagrams | 15.8 KiB, 16.6 | 16.2 KiB, 16.8 |
| of which `FindValueHit` (records) | 15.8 KiB, 13.2 | 14.9 KiB, 12.4 | 15.4 KiB, 12.9 |

A read served from a local copy sends nothing.

**Reading.**
- About 70% of a first publication's bytes are the answers to the replicas'
  checks. At a first publication no node holds the record, so each node asked
  answers with its 20 closest contacts (about 900 bytes) instead of a 32-byte
  hash, and each of the 20 replicas asks about 20 nodes. The replica already
  knows most of those contacts.
- The 20 STOREs are the record itself, 6 KB to each replica: 120 KiB that no
  change to the check can remove.
- A remote read sends three requests at once (`alpha`), and two or three
  holders answer with the whole record before the reader takes the first valid one and
  cancels the rest.
- Loss adds little traffic: resends are mostly small `FindHash` questions; a
  STORE is sent again in full (10 more datagrams per publication, about two
  STOREs).

## 5. E3. The empty-replica check and resends

**Question.** How many rounds and how long does an empty replica's check take,
and how often are requests sent again?

**Setup.** The counter runs of E2.

**Results.** All checks ended `none_or_same` (no node held another record).

| | LAN | WAN Europe | WAN Europe, 0.5% loss |
|---|---|---|---|
| Checks | 395 | 395 | 795 |
| Lookup in 1 round / 2 rounds / more | 243 / 152 / 0 | 267 / 128 / 0 | 660 / 135 / 0 |
| Mean duration | 4.0 ms | 29.7 ms | 59.9 ms |
| Checks over 500 ms | 0 | 0 | 22 (17 up to 1 s, 5 up to 2 s) |
| Resends to measured / never measured peers | 0 / 0 | 30 / 0 | 417 / 24 |

**Reading.**
- No lookup needed more than two rounds: a replica asks every node it knows
  at once, and a second round only for closer nodes it learned from the
  answers.
- In WAN Europe without loss a check takes about two round trips on average.
- Without loss there are still 30 resends in 20 publications in WAN Europe:
  answers that came later than three round trips of that peer, the shortest
  wait the resend rule allows. In LAN there are none.
- With loss, few resends go to peers never measured (24 in 40 publications),
  but each costs at least 500 ms; they are the likely source of the slow
  publications in E1.

## 6. A1. Race and burst attacks on a restarted replica

**Question.** Can an attacker that reads all traffic get a forged record onto
a replica that has just restarted empty, by racing the owner's record after an
UPDATE?

**Setup.** 10 nodes, `k` = 3, `alpha` = 3. The attacker runs in the host's
network namespace: it sees every container's packets and can send its own,
but cannot change or drop the owner's. It signs a document of its own for the
DID it sees, so the forged record passes the signature check. No extra delay.

**Procedure.** Each round: the owner publishes a new DID; one of its replicas
crashes and restarts empty; the owner rotates its keys (UPDATE). The replica
without the record refuses the UPDATE, and the owner then sends it the new
record as a STORE. In `race` mode the attacker sends one forged STORE to that
replica as soon as it sees the UPDATE; in `burst` mode 64 at once from 16
ports.

**Results.** 20 rounds each.

| Network, mode | Attacker wins | Restarted replica holds the owner's record / stays empty | Owner's update | Other replicas intact | Plain reads returning a forged record | Forged STOREs answered |
|---|---|---|---|---|---|---|
| LAN, race | 0/20 | 14 / 6 | confirmed 20/20 | 36/36 | 0/60 | 56, all `Conflict` |
| WAN Europe, race | 0/20 | 9 / 11 | confirmed 20/20 | 29/29 | 0/60 | 49, all `Conflict` |
| WAN Trans-Atlantic, race | 0/20 | 13 / 7 | confirmed 20/20 | 33/33 | 0/60 | 53, all `Conflict` |
| WAN Europe, burst | 0/20 | 17 / 3 | confirmed 20/20 | 37/37 | 0/60 | 3648, all `Conflict` |

The attacker sent its forged STORE 0.3 to 0.7 ms (median) after seeing the
UPDATE, while the owner needs one more round trip to send its own.

Before and after `fc79016`, WAN Europe, race, 40 rounds each in the same
session: the restarted replica held the owner's record 27/40 before and 30/40
after, and stayed empty 13/40 and 10/40; the attacker won 0/40 in both, and
no plain read (0/120) returned a forged record. Asking all close nodes at once
does not leave the replica empty more often: the 11/20 in the table is within
the spread of 20-round runs.

**Reading.**
- No forged record was stored. The restarted replica asks the other replicas,
  which hold the owner's record, and refuses the forged one without verifying
  its signature.
- The restarted replica often stays empty. While another replica still holds
  the previous version of the record, the owner's STORE of the new one gets
  `Conflict` too (a known gap, `DESIGN.md` section 7). The replica is refilled
  by the hourly republication.

## 7. A2. Persistent attacker and restarts

**Question.** What does an attacker achieve that sends forged records for
every DID it sees, to every node, all the time?

**Setup.** 10 nodes, `k` = 3, WAN Europe. In `persist` mode the attacker learns
DIDs from the STOREs and UPDATEs it sees and, every 100 ms, sends a forged
STORE for each DID seen in the last 20 s to every node.

**Procedure.** Each round: the owner publishes a new DID; after 0.5 s one of
its replicas crashes and restarts empty; 3 s later the script reads what the
restarted replica holds, how many nodes hold a forged record of that DID, and
what three plain reads return. A control run without the attacker comes
first.

**Results.** 20 rounds each.

| | Restarted replica: owner's / forged / empty | Owner's publication | Nodes holding a forged record | Plain reads returning it |
|---|---|---|---|---|
| No attacker | 0 / 0 / 20 | complete 20/20 | 0/180 | 0/60 |
| Persistent attacker | 0 / 1 / 19 | complete 19, rejected 1 | 6/180, all in one round | 3/60, all in that round |

The attacker's STOREs over the run were answered `Conflict` 27,515 times,
`AlreadyStored` 1613, not answered 189 (most likely refused because a node did
not answer the check, or because the restarted node knew nobody yet) and
`Stored` 19. The script
counts forged copies only of the current round's DID; the stores outside the
failed round are not attributed (they may be copies of that round's DID on
nodes restarted later).

**Reading.**
- A restarted replica did not take a forged record of a DID the network
  already held: the check found the owner's record on the other replicas.
- The one failed round is the first-publication window. The attacker learned
  the DID from the owner's first STOREs and sent forged ones to the other
  nodes before any of them had stored the owner's record, so their checks found
  nothing and the first writer won. The owner saw `ReplicaConflict` and knows
  the publication failed. This is a known limit (`DESIGN.md` section 7): the
  check protects a record the network holds, not a first publication.
- Without an attacker the restarted replica is still empty after 3 s in every
  round: its neighbours do not resend records to a node that comes back within
  about a second. The hourly republication refills it.

## 8. Summary

Validated on the current code:
- **Publication and availability.** 100 first publications in a network of 127
  nodes (`k` = 20), in LAN, WAN Europe, WAN Trans-Atlantic and WAN Europe with
  0.5% loss: all `complete`, and all 12,600 reads right after found the
  record.
- **Latency.** About 6 round trips for a publication, about 1 for a remote read
  (median).
- **Forged records against a record the network holds.** No forged record
  stored in 80 rounds of race and burst attacks, or in 19 of 20 rounds of a
  persistent attacker; no plain read returned a forged record there.

Measured costs and open points:
- **Traffic.** A first publication costs about 500 KiB and 1000 datagrams at
  `k` = 20, 70% of it in the answers to the replicas' checks. A remote read
  costs about 16 KiB, mostly whole records from several holders.
- **First publication.** An attacker that sees the owner's first STOREs can
  win the race to nodes that do not hold the record yet (1 of 20 rounds).
- **Refill.** A replica that restarts empty stays empty until the hourly
  republication, and after an UPDATE in 3 to 11 of 20 rounds.
- **Tail under loss.** Publications of 0.5 to 1.6 s under 0.5% loss.

## 9. How to reproduce

Host limits, once per boot:

```bash
sudo sysctl -w net.ipv4.neigh.default.gc_thresh1=4096 net.ipv4.neigh.default.gc_thresh2=16384 net.ipv4.neigh.default.gc_thresh3=32768
sudo sysctl -w net.core.netdev_max_backlog=16384
testbed/testbed.py build
```

E1, one profile (`lan`, `wan-eu`, `wan-atlantic`; with loss add `--loss 0.5`
and use 40 rounds):

```bash
testbed/testbed.py up --nodes 127 --k 20 --alpha 3 --profile wan-eu --no-build
testbed/measure.py publish --rounds 20
testbed/testbed.py down
```

E2 and E3: the same with `testbed/measure.py publish --rounds 20 --watchers 0
--counters`.

A1 (`--mode burst` for the burst row) and A2:

```bash
testbed/testbed.py up --nodes 10 --k 3 --alpha 3 --profile wan-eu --no-build
testbed/attack.py start --mode race
testbed/attack.py race --rounds 20
testbed/testbed.py down

testbed/testbed.py up --nodes 10 --k 3 --alpha 3 --profile wan-eu --no-build
testbed/attack.py restart --rounds 20          # control, no attacker
testbed/attack.py start --mode persist
testbed/attack.py restart --rounds 20
testbed/testbed.py down
```

To check that the host dropped nothing during a run, compare the sum of the
second column of `/proc/net/softnet_stat` (hexadecimal) before and after it.
Each run writes its rounds to `testbed/.generated/` (not in the repository).
