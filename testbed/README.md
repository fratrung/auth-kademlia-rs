# Testbed

A network of DHT nodes in Docker containers, with network latency and packet
loss emulated by `tc netem`. It is meant for watching the protocol on a
network that behaves like a real one: lookups that cross several nodes, replies
that get lost, replicas that are unreachable during an update.

Modes:
- **Interactive** (`testbed.py`): start a network and drive single nodes.
- **Attack** (`attack.py`), built on the interactive network: an attacker that
  reads the traffic and sends forged versions of the DIDs it sees, or spoofed
  answers to the check of an empty replica.
- **Measurement** (`measure.py`): publication time, and when other nodes can
  read the record; rotations with replicas restarted empty and nodes that lie
  in `FindHash`; copies of a record over time while nodes crash. With
  `--counters`, also what every node sent, read from the
  library's counters (`src/counters.rs`, on in the testbed image). The traffic
  tables below were measured from the host, before the counters existed.

The testbed binaries (`testbed_node`, `testbed_attacker`) are built only with
`--features testbed`, which the image enables; a normal build of the library
does not include them.

## Requirements

- Docker with Compose v2 (`docker compose`).
- A Linux kernel with `sch_netem`. Containers get `NET_ADMIN` only to run `tc`
  on their own interface.
- Python 3, standard library only.
- Beyond about 30 nodes, a larger neighbour table and a longer receive backlog
  on the host (see below).

### More than about 30 nodes on one machine

Raise the host's neighbour table limits and its per-CPU receive backlog
before `up`:

```
sudo sysctl -w net.ipv4.neigh.default.gc_thresh1=4096 net.ipv4.neigh.default.gc_thresh2=16384 net.ipv4.neigh.default.gc_thresh3=32768
sudo sysctl -w net.core.netdev_max_backlog=16384
```

The values last until the next reboot. Why: to send a datagram to another
container, a node's kernel needs that container's MAC address, which it learns
with ARP and keeps in the neighbour table. Fixed IP addresses do not avoid
this. The containers share the host's kernel, and the table's limit counts the
entries of every container together: by default at most 1024
(`gc_thresh3`). A node talks to the nodes it meets in its lookups, so N nodes
need up to N × (N − 1) entries: 870 for 30 nodes, about 16,000 for 127. Beyond
the limit the kernel refuses to send to addresses it cannot record. In a real
deployment each node has its own kernel and needs at most N − 1 entries.

How it showed up: with 127 nodes, k=20 and the default limit, 14 nodes still
had no contact 120 s after start, and one reached the seeds only after about 3
minutes. Their sends failed inside the kernel (`SndbufErrors` in
`/proc/net/snmp` in the container), and the host's kernel log said
`neighbour: arp_cache: neighbor table overflow!`. With the limits above, all
127 nodes had contacts 1 s after start and no send failed.

**The receive backlog.** A datagram from one container to another crosses two
`veth` pairs and the bridge, all in the host's kernel. Each `veth` hands it to
a per-CPU queue of at most `netdev_max_backlog` packets (1000 by default), and
a packet arriving at a full queue is dropped. A broadcast, such as an ARP
request, is copied to every port of the bridge, 127 packets at once. The drop
is silent for the testbed: `tc` shows none, the containers' `RcvbufErrors`
stay at 0; it shows in the second column of `/proc/net/softnet_stat` and as
`tx_dropped` on the host side of the `veth`s (`ip -s link`). On 2026-11-04,
127 nodes, WAN Europe without emulated loss: in 10 publications 34 of about
27,000 datagrams sent never arrived, and the nodes sent requests again (59
times); in 40 publications 99 of 792 STORE checks lasted 1 to 2 s. With
16384, 10 publications lost none (27,987 sent, 27,987 received), no check
lasted more than 200 ms, and no request to a peer never measured was sent
again. A
real deployment does not have this queue shared by every node. Runs before
that date may contain such drops.

## Quick start

```bash
testbed/testbed.py up --nodes 10 --k 3 --alpha 3 --profile wan-eu
testbed/testbed.py status                 # contacts and records per node
testbed/testbed.py ctl node-3 publish     # node-3 creates and publishes its DID
testbed/testbed.py get node-3 --from node-5
testbed/testbed.py ctl node-3 update      # key rotation
testbed/testbed.py logs -f                # every node, follow
testbed/testbed.py down
```

`up` builds the image first (under a minute with a warm cache); pass
`--no-build` to reuse it.

## The network

`up` writes `testbed/.generated/compose.yaml` and starts it:

| Option | Default | Meaning |
|---|---|---|
| `--nodes` | 10 | Number of nodes, `node-1` .. `node-N` |
| `--k`, `--alpha` | 20, 3 | Kademlia parameters, the same on every node |
| `--seeds` | 3 | `node-1` .. `node-S` are the bootstrap nodes |
| `--profile` | `lan` | Network profile, see below |
| `--delay` | from the profile | One-way delay in ms, overrides the profile |
| `--jitter` | 0 | Jitter in ms, normal distribution |
| `--loss` | 0 | Loss in %, per direction |
| `--cpus` | none | CPU limit per container, e.g. `0.5` |
| `--log` | `warn,testbed_node=info` | `RUST_LOG` of every node |
| `--subnet` | `10.213` | First two octets of the /16 the nodes live in |

**Bootstrap.** Every node receives the addresses of all the seeds and
bootstraps from them, seeds included (without themselves). A node that starts
before its seeds keeps retrying them, as the library does on its own (P1).
`up` returns when every node has at least one live contact, and stops at once
if a container exits.

**Identity.** A node's id is derived from its name, and storage lives in
memory. A node stopped or killed and started again comes back with the same id
and no records, as after a crash.

## Network profiles

`tc netem` runs on each container's egress, so a request and its reply cross
two delays: each container gets half the round-trip time. Loss also applies
once per direction.

| Profile | RTT | Source |
|---|---|---|
| `lan` | no delay added | Switch hops take microseconds. The Docker bridge alone measured 0.16 ms on the development machine; `rtt` shows it. |
| `wan-eu` | 13.6 ms | Verizon, Europe, September 2026 average |
| `wan-eu-target` | 30 ms | Verizon, Europe, target |
| `wan-atlantic` | 70.4 ms | Verizon, Trans-Atlantic, September 2026 average |
| `wan-atlantic-target` | 90 ms | Verizon, Trans-Atlantic, target |

Verizon measures with ICMP pings every 5 minutes between backbone routers and
publishes the monthly average
([IP latency statistics](https://www.verizon.com/business/terms/latency/)). The
RTT between two real devices is higher, because the access networks add to it:
the `-target` profiles are the pessimistic variants.

For loss, realistic values are small. Verizon's target is at least 99.5% of
packets delivered, that is up to 0.5% loss. ITU-T Y.1541 sets an IP packet loss
ratio of 10⁻³ (0.1%) for its classes 0 to 4; this figure comes from
reproductions of the table, not from the ITU text in force. Values such as 1%
or 5% are stress tests. Verizon publishes only averages, so jitter is off by
default; Y.1541 bounds delay variation at 50 ms for classes 0 and 1.

## Commands

| Command | What it does |
|---|---|
| `status` | Live contacts, contacts and records of every node |
| `ctl NODE info` | Name, address, node id, DID, current version and signing key |
| `ctl NODE new` | Create a new DID (version 0) without publishing it |
| `ctl NODE publish` | Create the node's DID on first use and publish version 0; again, it sends the same record |
| `ctl NODE update` | Rotate the ML-DSA-65 key: the next version, signed by the key the current one committed to and committing to a new one, sent with the earlier versions (ADR 0005) |
| `ctl NODE republish` | Send the current version again with the saved bytes, as the owner does at least every 24 hours |
| `ctl NODE discard` | Drop a rotation that was not confirmed; the next `update` signs another version with the same key, which replicas that took the first refuse |
| `ctl NODE lie on` / `lie off` | Answer every `FindHash` with a made-up version far ahead, or stop (testbed builds only) |
| `ctl NODE get DID` | Read a DID; `get TARGET --from NODE` also takes a node name |
| `ctl NODE storage` | Records this node holds, with their signing key |
| `ctl NODE routing` | This node's closest contacts |
| `netem NODE` | Change one node's emulation live: `--profile`, `--delay`, `--jitter`, `--loss` |
| `rtt A B` | Ping from A to B |
| `pause` / `unpause NODES` | Freeze nodes, as if hung: they stop answering |
| `stop` / `start NODES` | Stop nodes (they send `Leave`) and start them again, empty |
| `kill NODES` | Crash nodes: no `Leave`. `start` brings them back with the same id and no records |
| `logs [NODE] [-f]` | Logs of one node or of all |

Signing keys are shown as the first 6 bytes of their SHA-256, so versions can be
told apart. An update that is not confirmed stays pending: `update` again
retries the same record, as a retry must.

**Logs.** Each node logs one line per command it runs (outcome, replicas,
time), its contacts every 30 s, and the library's warnings, such as peers that
did not answer and records refused. Pass `--log info` or `--log debug` to `up`
for the library's own logs.

## Example: a replica that misses an update

```bash
testbed/testbed.py up --nodes 10 --k 3 --profile wan-eu --no-build
testbed/testbed.py ctl node-3 publish
for n in $(seq 1 10); do testbed/testbed.py ctl node-$n storage; done   # find the 3 replicas
testbed/testbed.py pause node-10          # one of them
testbed/testbed.py ctl node-3 update      # confirmed after one RPC timeout
testbed/testbed.py unpause node-10
testbed/testbed.py ctl node-10 storage    # still the old version
testbed/testbed.py ctl node-3 republish   # the owner sends the current version again
testbed/testbed.py ctl node-10 storage    # the current version
```

Since ADR 0005 node-10, which holds the version before the current one, takes
the owner's next `update` or `republish` directly: it checks the new version
against the one it holds. A replica further behind answers `MissingPrevious`,
and the owner replays the versions it missed. Before ADR 0005 nothing repaired
it, and on 2026-11-03 this run also showed the owner locked out: while node-10 was
frozen, node-3 entered the k closest and took a copy; once node-10 came back,
node-3 left them, its copy stayed behind, and its next rotation was refused.
Both are P3 defects in `dht_robustness_issues.md`.

## Attack mode

`testbed/attack.py` adds an attacker to a running network. It runs in the host
network namespace, where it sees every container's traffic, as on a shared
medium or a mirror port. It can read and send, but not change or drop packets:
changing the owner's record would break its self-signature anyway.

It takes the DID from the requests it sees and forges a version of it (ADR
0005): the `seq` and `prev` of the version it saw, or a version 1 after a
version 0, self-signed with a key of its own, which no version committed to. A
forged version passes the signature check; a replica holding the version
before refuses it, and an empty replica refuses it unless its check of the
network lets it through. The attacker sits next to every node: netem delays
only the containers' egress. `--delay` moves it farther away. Modes (`start
--mode`):

| Mode | What it does |
|---|---|
| `race` (default) | For each UPDATE, one forged STORE to the same replica, racing the owner's STORE to a replica that refused the UPDATE |
| `burst` | For each UPDATE, `--burst` (64) forged STOREs at once from `--ports` (16) ports. Many lookups at once can make the replica drop answers: it tests what the replica does then |
| `successor` | For each STORE of a version 0, a forged version 1 after it to the same replica, at once: the key security case of ADR 0005 |
| `spoof` | For each `FindHash` it sees, `--burst` (64) answers claiming a version far ahead, sent to the asking replica from the address and port of the node asked (a raw socket writes the IP header), under random message ids. `--spoof-ids observed` uses the ids read on the wire instead: the control, which shows the answers reach the replica and that the id is what stops them |
| `persist` | Learns DIDs from the STOREs and UPDATEs it sees and, every `--period` ms (100), sends a forged STORE for each DID seen in the last `--did-ttl` s (20) to every node. It covers every moment a node lacks the record |

```bash
testbed/testbed.py up --nodes 10 --k 3 --profile wan-eu --no-build
testbed/attack.py start [--mode race|burst|successor|spoof|persist] [--delay MS]
testbed/attack.py race --rounds 20 [--owner node-1]      # with race or burst
testbed/attack.py restart --rounds 20 [--owner node-1]   # with persist, or none
testbed/attack.py restart --rounds 20 --no-crash         # with successor
testbed/attack.py logs
testbed/attack.py stop                    # `testbed.py down` removes it too
```

`restart` repeats a round without an update: the owner publishes a new DID, one
of its replicas crashes and restarts empty, and after `--wait` seconds (3) it
reports what the replica holds, how many nodes hold a forged record, and how
many plain reads return it. With `--no-crash` nothing restarts: only
publication under attack, for example to compare traffic. `start --image TAG`
runs the attacker from another image than the network's, so that the same
attacker can be used against different builds.

`race` repeats a round: the owner publishes a new DID, one of its replicas
crashes and restarts empty, the owner rotates its keys. It reports what the
restarted replica holds afterwards (the owner's record, the attacker's, the old
one, nothing), the owner's outcome, the other replicas, how many plain reads
from other nodes return the forged record, and the answers the attacker got.
The state "before" is read about 0.1 s before the update, so a replica can be
refilled in between. `testbed.py up --image TAG` runs another build, for
example one without a fix, built with `testbed.py build --tag TAG --context DIR`.

Results on 2026-11-03, 10 nodes, k=3, alpha=3, attacker without extra delay:

| Network | Code | Attacker wins | Owner's outcome | Plain reads returning the forged record |
|---|---|---|---|---|
| LAN | before P3 point b | 0/20, 0/10 (every forged STORE got `Conflict`) | confirmed | 0 |
| LAN | with point b | 1/20 | confirmed 20/20 | 0/60 |
| WAN Europe | before point b | 20/20 | confirmed 20/20 | 14/60 |
| WAN Europe | with point b | 17/20 | confirmed 20/20 | 15/60 |
| WAN Trans-Atlantic | with point b | 16/20 | confirmed 20/20 | 15/60 |

- In LAN, in these first runs, the neighbours refilled a restarted replica
  within about 0.1 s, so the update rarely found it empty. Later runs, in LAN
  and WAN, found it still empty: see below.
- In WAN the refill is slower. When the replica is still empty, the attacker
  wins every time: it sends 0.3-0.7 ms after seeing the UPDATE, while the owner
  needs one more round trip to send its own STORE (P3 point b).
- The owner always sees "confirmed": the majority of the other replicas is
  enough, so it does not learn that one replica holds a forged record.
- The forged record stays: the owner's next update cannot verify against it.
  Readers that check the key against the VC skip it; plain reads get it about
  one time in four.

### With the STORE check

An empty replica now asks the nodes closest to the DID for the hash of their
record before storing, and refuses when one holds another record, when one
does not answer, or when it knows nobody to ask (`DESIGN.md`, section 7).
Same network, 2026-11-03.

`race` attacker:

| Network | Attacker wins | Plain reads returning the forged record | Restarted replica empty after the update |
|---|---|---|---|
| LAN | 0/20 | 0/60 | 12/20 |
| WAN Europe | 0/20 | 0/60 | 6/20 |
| WAN Trans-Atlantic | 0/20 | 0/60 | 6/20 |

`burst` attacker, WAN Europe:

| Check | Forged records stored | Restarted replica empty after the update |
|---|---|---|
| accepts on silence, whole records as answers | 1, in 53 bursts | 4/20 |
| refuses on silence, whole records | 0, in 48 | 12/20 |
| refuses on silence, hashes | 0, in 53 | 7/20 |

`persist` attacker with `restart`, WAN Europe:

| Check | Restarted replica with the forged record | Nodes holding a forged record | Plain reads returning it |
|---|---|---|---|
| none | 19/20 | 141/180 | 58/60 |
| accepts on silence and with nobody to ask | 6/20 | 7/180 | 3/60 |
| refuses on silence, accepts with nobody to ask | 6/20 | 6/180 | 10/60 |
| refuses on silence and with nobody to ask, hashes | 0/20 | 6/180, all in one round | 3/60 |

Traffic, `persist` with `restart --no-crash`, 10 rounds in 43 s: the nodes sent
92,492 KiB when the check received whole records, 4,675 KiB with hashes.

- No forged record reached a replica through a race or a burst. The bursts'
  unanswered STOREs were refused or dropped without being stored.
- The restarted replica often stays empty after the update. While another
  replica still holds the old version, the owner's STORE of the new one is
  refused (a known gap of the check). With whole records as answers, a burst
  also made the replica lose answers and refuse; with hashes it does so less.
- Without the check, a persistent attacker poisons most of the network: every
  node that lacks the record takes the forged one, and plain reads find it.
  With nobody to ask counted as "nobody holds it", a node that had just
  restarted accepted the forged record before it knew any contact.
- With the final check, the forged records of the last row all came from one
  round: the attacker learned the DID from the owner's first STOREs and sent
  forged ones to the other nodes before any replica had stored the owner's
  record, so their checks found nothing. A first publication stays open to an
  attacker that sees it, in a window of a few tens of milliseconds.
- In the runs without an attacker, a replica that crashed and was back within
  about a second was still empty 3 s later in 9 rounds out of 10 without the
  check, and 10 out of 10 with it: its neighbours see it neither as new nor as
  returning. The hourly republication refills it.

## Measurement mode

`measure.py publish` measures how long a publication takes and when other
nodes can read the record. Each round the owner creates a new DID without
publishing it (`ctl <node> new`), three other nodes start reading it in a loop
(`ctl <node> watch <did> <ms>`), the owner publishes it, and then every other
node reads it once.

```
testbed/testbed.py up --nodes 30 --k 5 --profile wan-eu --loss 0.5
testbed/measure.py publish --rounds 40
```

It prints the publication time, the time until the first watcher reads the
record (counted from the start of the publication; containers share the host
clock), the reads that found it right after, and the remote read time. The
rounds are saved in `.generated/publish-*.json`.

```
testbed/measure.py publish --rounds 20 --watchers 0 --counters
```

`--counters` reads every node's counters (`ctl <node> counters`) right before
the publication, 0.3 s after it (`--settle`), and after the reads that follow.
It prints, as medians per publication, the datagrams and bytes all nodes sent
by message type; over all rounds, the resends to peers whose round trip was
measured or not, and the STORE checks by outcome, lookup rounds and duration;
and the mean traffic of a remote read (a node with a local copy sends
nothing). Reading the counters runs `docker exec` in every container, which
loads the host: time publications without `--counters`. Bytes are UDP payloads,
KADF header included, without IP, UDP and Ethernet headers. Watchers' reads are
counted too, so `--watchers 0` counts the publication alone.

```
testbed/measure.py update --rounds 20 --restart 1 [--liars N] [--counters]
```

`measure.py update` measures rotations: each round the owner publishes a new
DID, rotates `--rotations` times (1), and `--restart M` replicas holding the
current version crash and come back empty just before the last rotation. It
prints the rotation time, what the replicas, the restarted ones and every
other node hold or read (current, older, other, none), and with `--counters`
the traffic of the last rotation, the checks by outcome and the checks that
fetched the version before, with their duration. `--liars N` makes the `N`
replicas closest to the key lie in `FindHash` (`ctl <node> lie on`) for the
round. The key rule covers both UUID and ADR 0005 DIDs, so the same mode
measures images from before and after ADR 0005.

```
testbed/measure.py churn --duration 600 --liars 1
```

`measure.py churn` counts the copies of one record over time while nodes
crash: the owner publishes a new DID and rotates once; every `--churn-every`
seconds (10) one of the `k` replicas (or any node, `--churn-among all`) other
than the owner and the liars crashes and comes back empty; every
`--republish-every` seconds (60) the owner sends its current version again;
every `--sample-every` seconds (5) it prints what the replicas hold, and at the
end how often fewer than the quorum held the current version.

The results below come before two changes to the check: the DID binding is
checked before asking the network (`e383d17`), and a replica asks all the
nodes it knows at once instead of three at a time (`fc79016`). They have not
been measured again yet.

Results on 2026-11-03, 30 nodes, k=5, alpha=3:

| Network | No check | Hash check | Hash check with resends |
|---|---|---|---|
| LAN, publication median | 1.2 ms | 1.6 ms | 1.8 ms |
| WAN Europe, publication median (p95) | 43 ms (43) | 75 ms (86) | 72 ms (86) |
| WAN Trans-Atlantic, publication median (p95) | 215 ms (216) | 359 ms (430) | 359 ms (430) |
| WAN Europe, 0.5% loss: publications missing a replica | 7/40 | 26/80 | 0/80 |
| WAN Europe, 0.5% loss: publications over 1 s | 8/40 | 26/80 | 0/80 |
| WAN Europe, 0.5% loss: publication p95 | 2557 ms | 2544-2559 ms | 143-148 ms |

- Without loss every read right after a publication found the record (580/580
  per run) in every version.
- The check adds about two round trips: the replica's own lookup of the hash
  takes two rounds, sometimes three.
- Before the resends, a single lost datagram cost the whole 2.5 s RPC timeout,
  and in the check it also made the replica refuse. With them it costs a few
  round trips. Reads that start before the record exists benefit too: the
  watchers' 2 s stalls under loss are gone.
- With k=3 on 10 nodes the same comparison gave 5/60 publications missing a
  replica without the check and 14/60 with the hash check alone.

Results on 2026-11-04, 127 nodes, k=20, alpha=3. All three builds have the
futurelock fix; the last two are the current code with one part switched off.

| Network | No check | Check without resends | Check with resends (current) |
|---|---|---|---|
| LAN, publication median | 3.7 ms | 8.3 ms | 8.9 ms |
| WAN Europe, publication median | 46 ms | 103 ms | 102 ms |
| WAN Trans-Atlantic, publication median | 218 ms | 471 ms | 504 ms |
| WAN Europe, no loss: publications missing a replica | 0/20 | 2/20 | 0/20 |
| WAN Europe, 0.5% loss: publications missing a replica | 0/40 | 40/40 | 0/40 |
| WAN Europe, 0.5% loss: replicas stored | 798/800 | 581/799 | 800/800 |
| WAN Europe, 0.5% loss: publication median (p95) | 88 ms (148) | 2.5 s (5.0) | 179 ms (1.17 s) |

- Every read right after a publication found the record in every run
  (2520/2520, 5040/5040 with loss). Reads do not use the check.
- At k=20 an empty replica must hear from about twenty nodes, so without
  resends one lost datagram among hundreds is enough to refuse. With loss, the
  p95 of 1.17 s is not explained yet; peers never measured get a 500 ms wait
  before the first resend.
- Before the futurelock fix, one of the 127 nodes stopped answering two
  seconds after the first publication, also with the build before the check.

Traffic per operation, counted on the host side of each container's veth
(what the container sent, with IP, UDP and Ethernet headers), 20 first
publications and about 80 remote reads per run, medians:

| | Current, LAN | Current, WAN Europe | No check, LAN | No check, WAN Europe |
|---|---|---|---|---|
| First publication, sent by the owner | 126 KiB, 120 datagrams | 126 KiB, 123 | 126 KiB, 120 | 126 KiB, 120 |
| First publication, sent by all other nodes | 406 KiB, 916 | 404 KiB, 885 | 21 KiB, 60 | 21 KiB, 61 |
| First publication, total | 533 KiB, ~1040 | 535 KiB, ~1000 | 147 KiB, 180 | 147 KiB, 182 |
| Remote read | 18.8 KiB, 18 | 18.8 KiB, 20 | 18.8 KiB, 18 | 19.1 KiB, 24 |

- The owner sends the same in both: its lookup and twenty 6 KB STOREs. The
  check adds about 19 KiB and 42 datagrams per empty replica: at a first
  publication nobody holds the record, so the nodes asked answer with their
  closest contacts (about 850 bytes), not with a 32-byte hash.
- A remote read is one round of three requests (alpha), each holder answering
  with the whole record. A read with a local copy sends nothing. With the
  network idle, nodes sent nothing.

## Limits

- All containers share the host CPU, and ML-DSA verification competes
  between them. `--cpus` gets closer to an ARM board but stays an
  approximation.
- A desktop with 16 cores and 15 GB ran 127 nodes (about 5 GB used), once
  the neighbour table limit was raised (see Requirements).
- Emulation acts on each container's egress only.
