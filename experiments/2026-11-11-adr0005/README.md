# Measurements of 2026-11-11: ADR 0005

The raw data behind `EXPERIMENTS.md` for ADR 0005 (self-certifying DIDs and a
pre-rotated chain of versions): every step of `run_experiments.sh`, run once,
one network at a time, on the Docker testbed (`testbed/`).

## Images

| Tag | Code |
|---|---|
| `auth-kademlia-testbed:main-424b76f` | `main` at `424b76f`, before ADR 0005: UUID DIDs, `auth_signature` on updates |
| `auth-kademlia-testbed:adr0005-final` | branch `feat/self-certifying-did-and-pre-rotation`, ADR 0005 implemented |

Both sign records with ML-DSA-65 and use 256-bit ids. Host limits raised as
`testbed/README.md` requires (neighbour table 4096/16384/32768, receive backlog
16384).

## Files

For each step named `<step>`:

- `<step>.txt`: what the step printed, rounds and summary;
- `<step>.json`: the data of every round, as `testbed/measure.py` or
  `testbed/attack.py` wrote it (only for steps that measure).

`runner.log` lists the steps in order, with the time each started and ended,
its exit code, and the datagrams the host dropped during it (the second column
of `/proc/net/softnet_stat`, summed over the CPUs, after minus before): a step
with drops measured the host, not the protocol.

Step names:

| Prefix | Network |
|---|---|
| `main-<profile>`, `branch-<profile>` | 127 nodes, `k` = 20, `alpha` = 3, on the `main` or the branch image |
| `k3-<profile>` | 10 nodes, `k` = 3, `alpha` = 3, branch image |
| `k20-wan-eu` | 127 nodes, `k` = 20, `alpha` = 3, WAN Europe, branch image |

| Suffix | Step |
|---|---|
| `e1` | publication and read latency (`measure.py publish`) |
| `e2` | the same publications with every node's counters: traffic and the checks of empty replicas (`--watchers 0 --counters`) |
| `update` | rotation with a replica restarted empty just before it (`measure.py update --restart 1`) |
| `update-counters` | the same with counters: UPDATE fragments, checks and fetches |
| `race`, `burst` | attacker racing the owner after an UPDATE (`attack.py race`) |
| `restart-control`, `persist` | restarts without and with a persistent attacker (`attack.py restart`) |
| `successor` | forged version 1 right after each version 0 (`attack.py restart --no-crash`) |
| `liars<N>` | `N` replicas closest to the key lie in `FindHash` (`measure.py update --liars N`) |
| `spoof-guessed`, `spoof-observed` | spoofed `FindHash` answers under random ids, and the control under the ids read on the wire |
| `churn-liars<N>` | copies of a record over 10 minutes of crashes, with `N` liars (`measure.py churn`) |
| `up`, `down`, `*-start`, `*-stop` | starting and stopping networks and attackers |

### Baseline attacks on `main`

`main-k3-wan-eu-race.json`, `-burst.json`, `-restart-control.json` and
`-persist.json` are A1 and A2 on the `main` image (10 nodes, `k` = 3, WAN
Europe), run in that order on 2026-11-11 between 00:31 and 00:36, before
`run_experiments.sh`, with the same driver. Only their data was kept: the text
they printed was lost with a temporary folder at a reboot. The attacker's mode
is not in the data; the order of the runs gives it.

## Reproduce

From the repository root, with the two images built:

```bash
experiments/2026-11-11-adr0005/run_experiments.sh all   # or: compare, attacks
```

It writes to `testbed/.generated/adr0005-runs/`.
