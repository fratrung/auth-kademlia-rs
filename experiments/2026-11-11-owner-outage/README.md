# Measurements of 2026-11-11: replicas lost while the owner is offline

The raw data behind L2 and L3 in `EXPERIMENTS.md`. L2: the owner of a DID
goes offline, several replicas lose their copy at once, and the remaining
holders republish it. L3, in `reads/`: the same with a persistent attacker,
and what readers get then. Run once by `run_outage.sh`, on `main` and then on the branch
of ADR 0005, one network at a time, on the Docker testbed (`testbed/`).

## Images

| Tag | Code |
|---|---|
| `auth-kademlia-testbed:main-424b76f-push` | `main` at `424b76f`, before ADR 0005, with `main-push.patch` applied: the testbed's `push` command only |
| `auth-kademlia-testbed:adr0005-push` | branch `feat/self-certifying-did-and-pre-rotation`, ADR 0005 implemented, with the `push` command: commit `01451e0` |

`push <did>` makes a node send the record it holds for that DID to the `k`
nodes closest to its key, as the hourly republication does for every record
older than an hour (`src/network/maintenance.rs`), and reports the answers.
The patch adds nothing else to `main`; the library is unchanged.

Host limits raised as `testbed/README.md` requires (neighbour table
4096/16384/32768, receive backlog 16384).

## Files

- `run_outage.sh`: the script that ran the steps; it writes to
  `testbed/.generated/outage-runs/`.
- `runner.log`: the steps in order, with the time each started and ended,
  its exit code, and the datagrams the host dropped during it (second column
  of `/proc/net/softnet_stat`, summed over the CPUs, after minus before).
- `<side>-up.txt`, `<side>-down.txt`: starting and stopping each network of
  127 nodes, `k` = 20, `alpha` = 3, WAN Europe.
- `<side>-outage.txt`: what `testbed/measure.py outage` printed, one line per
  round and a summary.
- `<side>-outage.json`: the data of every round: the DID, the replicas, the
  victims, the signing key of each version, the counts before the loss, after
  the loss, after the holders' republication and, on the branch, after the
  owner's return, and the answers to the holders' STOREs.

Counts are written `current/older/none` over the replicas, the owner left
out: 20, or 19 when the owner is one of the `k` closest.

## Reproduce

From the repository root, with the two images built (the `main` one from a
worktree of `424b76f` with `main-push.patch` applied):

```bash
experiments/2026-11-11-owner-outage/run_outage.sh
```

## L3: reads in the worst case (`reads/`)

`run_outage_reads.sh` ran, on the same two images, a network of 130 nodes
(127, and 3 kept outside to join at the worst moment of each round), a
persistent attacker (`attack.py start --mode persist --period 1000 --did-ttl
60`), and `testbed/measure.py outage --lost 8 12 16 20 --rounds 5 --reads
--joiners 3`, with `--owner-returns` on the branch.

- `runner.log`, `<side>-*.txt`, `<side>-outage-reads.json`: as above. Each
  round also holds the outcome of the publication and of the rotation, and
  for each set of reads the counts by version and the signing keys read
  (`keys`).
- `<side>-attacker-log.txt`: the attacker's log. For each DID it names the
  forged key it uses (`learned ... forged key`), and every 5 s it totals the
  answers to its forged STOREs (`Stored` means a node stored a forgery). The
  warning it logs for each unanswered STORE is removed, and counted at the end
  of the file.
- `check_forged.py RUN.json ATTACKER-LOG`: matches every key read with the
  owner's versions and the attacker's forged keys.
- `digest_reads.py RUN.json`: the rounds split by whether the first
  publication reached every replica.
- `discarded-first-run/`: a first run with a heavier attacker (every 500 ms,
  120 s per DID), not used: the host dropped 12,368 datagrams during the
  branch run, and the owner's version 1 was counted as another record when its
  rotation did not reach a majority (`EXPERIMENTS.md`, L3).

Reproduce from the repository root:

```bash
experiments/2026-11-11-owner-outage/reads/run_outage_reads.sh
```
