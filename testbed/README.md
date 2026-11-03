# Testbed

A network of DHT nodes in Docker containers, with network latency and packet
loss emulated by `tc netem`. It is meant for watching the protocol on a
network that behaves like a real one: lookups that cross several nodes, replies
that get lost, replicas that are unreachable during an update.

The testbed has two planned modes. The **interactive** mode, described here, is
available. The **measurement** mode (latency percentiles, hops per lookup,
bytes per operation, success rate under loss) is not built yet: it needs
counters in the library, behind a Cargo feature that is off by default.

## Requirements

- Docker with Compose v2 (`docker compose`).
- A Linux kernel with `sch_netem`. Containers get `NET_ADMIN` only to run `tc`
  on their own interface.
- Python 3, standard library only.

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

**Identity.** Node ids are random, and storage lives in memory. A node stopped
and started again joins with a new id and no records.

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
| `ctl NODE info` | Name, address, node id, DID, current signing key |
| `ctl NODE publish` | Create the node's DID on first use and publish it; again, it republishes the same record |
| `ctl NODE update` | Rotate Dilithium and Kyber keys together; the old key authorizes the new record |
| `ctl NODE discard` | Drop a rotation that was not confirmed |
| `ctl NODE get DID` | Read a DID; `get TARGET --from NODE` also takes a node name |
| `ctl NODE storage` | Records this node holds, with their signing key |
| `ctl NODE routing` | This node's closest contacts |
| `netem NODE` | Change one node's emulation live: `--profile`, `--delay`, `--jitter`, `--loss` |
| `rtt A B` | Ping from A to B |
| `pause` / `unpause NODES` | Freeze nodes, as if hung: they stop answering |
| `stop` / `start NODES` | Stop nodes (they send `Leave`) and start them again, empty |
| `logs [NODE] [-f]` | Logs of one node or of all |

Signing keys are shown as the first 6 bytes of their SHA-256, so versions can be
told apart. An update that is not confirmed stays pending: `update` again
retries the same record and authorization, as a retry must.

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
testbed/testbed.py ctl node-10 storage    # still the old key: nothing repairs it
```

On 2026-11-03 this run also showed the owner locked out: while node-10 was
frozen, node-3 entered the k closest and took a copy; once node-10 came back,
node-3 left them, its copy stayed behind, and its next rotation was refused.
Both are P3 defects in `dht_robustness_issues.md`.

## Limits

- All containers share the host CPU, and Dilithium verification competes
  between them. `--cpus` gets closer to an ARM board but stays an
  approximation.
- A desktop runs a few tens of nodes, perhaps 100.
- Emulation acts on each container's egress only.
