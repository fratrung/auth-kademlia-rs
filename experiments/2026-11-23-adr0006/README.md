# Measurements of 2026-11-23: ADR 0006

The raw data behind `EXPERIMENTS.md` for ADR 0006 (a DID that commits the
root of a Merkle tree of 64 rotation keys): every step of
`run_experiments.sh` and of `run_data_dir.sh`, run once, one network at a
time, on the Docker testbed (`testbed/`). The results to compare with, for
ADR 0005 and for `main` before it, are in `experiments/2026-11-11-adr0005/`
and `experiments/2026-11-11-owner-outage/`.

## Images

| Tag | Code | Steps |
|---|---|---|
| `auth-kademlia-testbed:adr0006` | branch `feat/merkle-committed-rotation-keys` at `b4b8ef0` | this folder, `run_experiments.sh` |
| `auth-kademlia-testbed:adr0006-data` | `9e9b72e`: `b4b8ef0` and the testbed's `DATA_DIR` | `data-dir/before-fix/` |
| `auth-kademlia-testbed:adr0006-data` | `03336ab`: a node that starts with records sends them to nobody until it has joined | `data-dir/` |

The first image was built from `b4b8ef0` and run with the drivers of the
working tree (`testbed/*.py`), which differ from it in labels and in the
`--data-dir` option of `9e9b72e` only. The two `adr0006-data` images
were built from the working tree before those commits, with the same code.

All sign records with ML-DSA-65 and use 256-bit ids. Host limits raised as
`testbed/README.md` requires (neighbour table 4096/16384/32768, receive
backlog 16384).

## Files

For each step named `<step>`:

- `<step>.txt`: what the step printed, rounds and summary;
- `<step>.json`: the data of every round, as `testbed/measure.py` or
  `testbed/attack.py` wrote it (only for steps that measure).

`runner.log` lists the steps in order, with the time each started and ended,
its exit code, and the datagrams the host dropped during it (the second column
of `/proc/net/softnet_stat`, summed over the CPUs, after minus before): a step
with drops measured the host, not the protocol. Two steps had drops:
`adr0006-wan-eu-loss0.5-e2` (508) and `data-dir/before-fix/data-wan-eu-outage`
(398).

Step names:

| Prefix | Network |
|---|---|
| `adr0006-<profile>` | 127 nodes, `k` = 20, `alpha` = 3, profiles `lan`, `wan-eu`, `wan-atlantic`, and `wan-eu-loss0.5` (WAN Europe with 0.5% loss each way) |
| `k3-<profile>` | 10 nodes, `k` = 3, `alpha` = 3 |
| `k20-wan-eu` | 127 nodes, `k` = 20, `alpha` = 3, WAN Europe |
| `outage-wan-eu` | 127 nodes, `k` = 20, WAN Europe: L2 |
| `reads-wan-eu` | 130 nodes, `k` = 20, WAN Europe, a persistent attacker: L3 |
| `data-wan-eu` (in `data-dir/`) | 127 nodes, `k` = 20, WAN Europe, every node with its records on disk (`up --data-dir`): D1 |

| Suffix | Step |
|---|---|
| `e1` | publication and read latency (`measure.py publish`) |
| `e2` | the same publications with every node's counters: traffic and the checks of empty replicas (`--watchers 0 --counters`) |
| `update` | rotation with a replica restarted empty just before it (`measure.py update --restart 1`) |
| `update-counters` | the same with counters: the STORE of the new position, checks and fetches |
| `race`, `burst` | attacker racing the owner to a restarted replica (`attack.py race`) |
| `restart-control`, `persist` | restarts without and with a persistent attacker (`attack.py restart`) |
| `successor` | forged position 1 right after each position 0 (`attack.py restart --no-crash`) |
| `liars<N>` | `N` replicas closest to the key lie in `FindHash` (`measure.py update --liars N`) |
| `spoof-guessed`, `spoof-observed` | spoofed `FindHash` answers under random ids, and the control under the ids read on the wire |
| `churn`, `churn-liars<N>` | copies of a record over 10 minutes of crashes, with `N` liars (`measure.py churn`) |
| `outage` | the owner offline while replicas crash at once, the holders' republication and the owner's return (`measure.py outage`) |
| `outage-reads` | the same with reads by every node and by 3 nodes that join at that moment (`--reads --joiners 3`) |
| `attacker-log` | the attacker's log during `outage-reads` |
| `up`, `down`, `*-start`, `*-stop` | starting and stopping networks and attackers |

`reads-wan-eu-attacker-log.txt` names, for each DID, the forged key the
attacker uses (`learned ... forged key`), and every 5 s totals the answers to
its forged STOREs (`Stored` would mean a node stored a forgery). The warning
it logs for each unanswered STORE is removed, and counted at the end of the
file. `experiments/2026-11-11-owner-outage/reads/check_forged.py` matches
every key read with the owner's positions and the attacker's forged keys:

```bash
python3 experiments/2026-11-11-owner-outage/reads/check_forged.py \
    experiments/2026-11-23-adr0006/reads-wan-eu-outage-reads.json \
    experiments/2026-11-23-adr0006/reads-wan-eu-attacker-log.txt
```

### `data-dir/` and `data-dir/before-fix/`

The same steps of `run_data_dir.sh`, twice. In `before-fix/`, a node
restarted from its directory sent its records to the nodes it met during its
bootstrap lookup, with an almost empty routing table: in
`data-wan-eu-update` 461 of 2520 reads after a rotation returned the
position before, from nodes outside the `k` closest that had taken it. The
steps in `data-dir/` ran on the code that holds those records until the
node's lookup of its own id is over.

## Reproduce

From the repository root, with the images built
(`testbed/testbed.py build --tag auth-kademlia-testbed:adr0006` from
`b4b8ef0`, `--tag auth-kademlia-testbed:adr0006-data` from the commit to
measure):

```bash
experiments/2026-11-23-adr0006/run_experiments.sh all   # or: compare, attacks, outage
experiments/2026-11-23-adr0006/run_data_dir.sh
```

They write to `testbed/.generated/adr0006-runs/` and
`testbed/.generated/adr0006-data-runs/`.
