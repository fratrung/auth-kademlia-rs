# Measurements of 2026-11-03 and 2026-11-04: the check of empty replicas

The raw data of the measurements reported in `testbed/README.md` ("Attack
mode", "With the STORE check" and "Measurement mode", results of 2026-11-03
and 2026-11-04). They were taken while the network check of empty replicas,
the resends of lost requests and the fix of a futurelock were developed
(commits `7c252f7` to `71e4392`), before ML-DSA-65 (ADR 0003), 256-bit ids
(ADR 0004) and self-certifying DIDs (ADR 0005). They describe those builds,
not the current code; `EXPERIMENTS.md` holds the measurements of the current
code.

Each file is what `testbed/measure.py publish` or `testbed/attack.py race` or
`restart` wrote: `config` (network size, `k`, emulation, image) and one entry
per round. The runs were made by hand, one at a time. No script and no log of
host drops were kept: that the host can drop datagrams between containers
unless its receive backlog is raised was documented afterwards, on 2026-11-05
(`71e4392`). The traffic tables of 2026-11-04 were read from the host's
interface counters, which these files do not hold.

## Builds

The image tag in each file's `config` names the build:

| Tag | Build |
|---|---|
| `before-check` | Before the network check of empty replicas |
| `before-p3b` | Before the owner sends the record by STORE to replicas that refused an UPDATE (`7c252f7`) |
| `hash-check` | The check with hash answers (`FindHash`), without resends |
| `resend` | The check with hash answers and resends of lost requests |
| `futurelock` | The check with resends and the futurelock fix (`82885fa`) |
| `k20-nocheck`, `k20-noresend` | The `futurelock` build with the check, or the resends, switched off |
| `o1-e383d17`, `o2-fc79016` | The commits `e383d17` (binding checked before the lookup) and `fc79016` (all close nodes asked at once) |
| `o2-counters` | `fc79016` with the counters of `src/counters.rs` |
| `latest`, `welcome`, `check-open` | Builds of 2026-11-03 tagged at the time without a commit; `latest` was reused for successive builds of that day |

Which file gives which row of the tables in `testbed/README.md` was not
recorded, apart from what the tag, the time and the settings show.

## Files

| File | Started | Mode | Image | Nodes | `k` | Profile | Loss | Rounds |
|---|---|---|---|---|---|---|---|---|
| `race-lan-20261103-143920.json` | 2026-11-03 14:39 | race | `latest` | 10 | 3 | lan | 0.0% | 5 |
| `race-lan-20261103-143958.json` | 2026-11-03 14:39 | race | `latest` | 10 | 3 | lan | 0.0% | 20 |
| `race-wan-eu-20261103-144059.json` | 2026-11-03 14:40 | race | `latest` | 10 | 3 | wan-eu | 0.0% | 20 |
| `race-wan-atlantic-20261103-144200.json` | 2026-11-03 14:42 | race | `latest` | 10 | 3 | wan-atlantic | 0.0% | 20 |
| `race-lan-20261103-144236.json` | 2026-11-03 14:42 | race | `before-p3b` | 10 | 3 | lan | 0.0% | 10 |
| `race-lan-20261103-144314.json` | 2026-11-03 14:43 | race | `before-p3b` | 10 | 3 | lan | 0.0% | 20 |
| `race-wan-eu-20261103-144403.json` | 2026-11-03 14:44 | race | `before-p3b` | 10 | 3 | wan-eu | 0.0% | 20 |
| `race-lan-20261103-144507.json` | 2026-11-03 14:45 | race | `before-p3b` | 10 | 3 | lan | 0.0% | 10 |
| `race-wan-eu-20261103-162129.json` | 2026-11-03 16:21 | race | `latest` | 10 | 3 | wan-eu | 0.0% | 2 |
| `restart-wan-eu-20261103-162145.json` | 2026-11-03 16:21 | restart | `latest` | 10 | 3 | wan-eu | 0.0% | 2 |
| `race-lan-20261103-162422.json` | 2026-11-03 16:24 | race | `latest` | 10 | 3 | lan | 0.0% | 20 |
| `race-wan-eu-20261103-162513.json` | 2026-11-03 16:25 | race | `latest` | 10 | 3 | wan-eu | 0.0% | 20 |
| `race-wan-atlantic-20261103-162619.json` | 2026-11-03 16:26 | race | `latest` | 10 | 3 | wan-atlantic | 0.0% | 20 |
| `race-wan-eu-20261103-162713.json` | 2026-11-03 16:27 | race | `check-open` | 10 | 3 | wan-eu | 0.0% | 20 |
| `race-wan-eu-20261103-162806.json` | 2026-11-03 16:28 | race | `latest` | 10 | 3 | wan-eu | 0.0% | 20 |
| `restart-wan-eu-20261103-162856.json` | 2026-11-03 16:28 | restart | `before-check` | 10 | 3 | wan-eu | 0.0% | 10 |
| `restart-wan-eu-20261103-162946.json` | 2026-11-03 16:29 | restart | `latest` | 10 | 3 | wan-eu | 0.0% | 10 |
| `restart-wan-eu-20261103-163121.json` | 2026-11-03 16:31 | restart | `before-check` | 10 | 3 | wan-eu | 0.0% | 20 |
| `restart-wan-eu-20261103-163256.json` | 2026-11-03 16:32 | restart | `latest` | 10 | 3 | wan-eu | 0.0% | 20 |
| `race-lan-20261103-165121.json` | 2026-11-03 16:51 | race | `latest` | 10 | 3 | lan | 0.0% | 20 |
| `race-wan-eu-20261103-165220.json` | 2026-11-03 16:52 | race | `latest` | 10 | 3 | wan-eu | 0.0% | 20 |
| `race-wan-atlantic-20261103-165339.json` | 2026-11-03 16:53 | race | `latest` | 10 | 3 | wan-atlantic | 0.0% | 20 |
| `race-wan-eu-20261103-165443.json` | 2026-11-03 16:54 | race | `latest` | 10 | 3 | wan-eu | 0.0% | 20 |
| `restart-wan-eu-20261103-165539.json` | 2026-11-03 16:55 | restart | `latest` | 10 | 3 | wan-eu | 0.0% | 10 |
| `restart-wan-eu-20261103-165723.json` | 2026-11-03 16:57 | restart | `latest` | 10 | 3 | wan-eu | 0.0% | 20 |
| `restart-wan-eu-20261103-165915.json` | 2026-11-03 16:59 | restart | `check-open` | 10 | 3 | wan-eu | 0.0% | 20 |
| `restart-wan-eu-20261103-170007.json` | 2026-11-03 17:00 | restart | `latest` | 10 | 3 | wan-eu | 0.0% | 10 |
| `restart-wan-eu-20261103-170059.json` | 2026-11-03 17:00 | restart | `check-open` | 10 | 3 | wan-eu | 0.0% | 10 |
| `publish-wan-eu-20261103-180236.json` | 2026-11-03 18:02 | publish | `latest` | 10 | 3 | wan-eu | 0.0% | 3 |
| `publish-lan-20261103-180318.json` | 2026-11-03 18:03 | publish | `before-check` | 10 | 3 | lan | 0.0% | 20 |
| `publish-wan-eu-20261103-180342.json` | 2026-11-03 18:03 | publish | `before-check` | 10 | 3 | wan-eu | 0.0% | 20 |
| `publish-wan-atlantic-20261103-180411.json` | 2026-11-03 18:04 | publish | `before-check` | 10 | 3 | wan-atlantic | 0.0% | 20 |
| `publish-wan-eu-20261103-180521.json` | 2026-11-03 18:05 | publish | `before-check` | 10 | 3 | wan-eu | 0.5% | 20 |
| `publish-lan-20261103-180544.json` | 2026-11-03 18:05 | publish | `latest` | 10 | 3 | lan | 0.0% | 20 |
| `publish-wan-eu-20261103-180608.json` | 2026-11-03 18:06 | publish | `latest` | 10 | 3 | wan-eu | 0.0% | 20 |
| `publish-wan-atlantic-20261103-180637.json` | 2026-11-03 18:06 | publish | `latest` | 10 | 3 | wan-atlantic | 0.0% | 20 |
| `publish-wan-eu-20261103-180755.json` | 2026-11-03 18:07 | publish | `latest` | 10 | 3 | wan-eu | 0.5% | 20 |
| `publish-wan-eu-20261103-181407.json` | 2026-11-03 18:14 | publish | `latest` | 10 | 3 | wan-eu | 0.5% | 40 |
| `publish-wan-eu-20261103-181608.json` | 2026-11-03 18:16 | publish | `before-check` | 10 | 3 | wan-eu | 0.5% | 40 |
| `publish-lan-20261103-182238.json` | 2026-11-03 18:22 | publish | `before-check` | 30 | 5 | lan | 0.0% | 20 |
| `publish-wan-eu-20261103-182304.json` | 2026-11-03 18:23 | publish | `before-check` | 30 | 5 | wan-eu | 0.0% | 20 |
| `publish-wan-atlantic-20261103-182338.json` | 2026-11-03 18:23 | publish | `before-check` | 30 | 5 | wan-atlantic | 0.0% | 20 |
| `publish-wan-eu-20261103-182603.json` | 2026-11-03 18:26 | publish | `before-check` | 30 | 5 | wan-eu | 0.5% | 40 |
| `publish-lan-20261103-182628.json` | 2026-11-03 18:26 | publish | `latest` | 30 | 5 | lan | 0.0% | 20 |
| `publish-wan-eu-20261103-182655.json` | 2026-11-03 18:26 | publish | `latest` | 30 | 5 | wan-eu | 0.0% | 20 |
| `publish-wan-atlantic-20261103-182732.json` | 2026-11-03 18:27 | publish | `latest` | 30 | 5 | wan-atlantic | 0.0% | 20 |
| `publish-wan-eu-20261103-183006.json` | 2026-11-03 18:30 | publish | `latest` | 30 | 5 | wan-eu | 0.5% | 40 |
| `publish-lan-20261103-191329.json` | 2026-11-03 19:13 | publish | `resend` | 30 | 5 | lan | 0.0% | 20 |
| `publish-wan-eu-20261103-191357.json` | 2026-11-03 19:13 | publish | `resend` | 30 | 5 | wan-eu | 0.0% | 20 |
| `publish-wan-atlantic-20261103-191434.json` | 2026-11-03 19:14 | publish | `resend` | 30 | 5 | wan-atlantic | 0.0% | 20 |
| `publish-wan-eu-20261103-191523.json` | 2026-11-03 19:15 | publish | `resend` | 30 | 5 | wan-eu | 0.5% | 40 |
| `publish-wan-eu-20261103-191749.json` | 2026-11-03 19:17 | publish | `hash-check` | 30 | 5 | wan-eu | 0.5% | 40 |
| `publish-wan-eu-20261103-191839.json` | 2026-11-03 19:18 | publish | `resend` | 30 | 5 | wan-eu | 0.5% | 40 |
| `publish-lan-20261103-205326.json` | 2026-11-03 20:53 | publish | `welcome` | 30 | 5 | lan | 0.0% | 20 |
| `publish-wan-eu-20261103-205353.json` | 2026-11-03 20:53 | publish | `welcome` | 30 | 5 | wan-eu | 0.0% | 20 |
| `publish-wan-atlantic-20261103-205432.json` | 2026-11-03 20:54 | publish | `welcome` | 30 | 5 | wan-atlantic | 0.0% | 20 |
| `publish-wan-eu-20261103-205525.json` | 2026-11-03 20:55 | publish | `welcome` | 30 | 5 | wan-eu | 0.5% | 40 |
| `publish-wan-eu-20261103-205617.json` | 2026-11-03 20:56 | publish | `welcome` | 30 | 5 | wan-eu | 0.5% | 40 |
| `publish-lan-20261104-030826.json` | 2026-11-04 03:08 | publish | `welcome` | 30 | 5 | lan | 0.0% | 20 |
| `publish-wan-eu-20261104-030916.json` | 2026-11-04 03:09 | publish | `welcome` | 30 | 5 | wan-eu | 0.0% | 20 |
| `publish-lan-20261104-040610.json` | 2026-11-04 04:06 | publish | `futurelock` | 127 | 20 | lan | 0.0% | 20 |
| `publish-wan-eu-20261104-040733.json` | 2026-11-04 04:07 | publish | `futurelock` | 127 | 20 | wan-eu | 0.0% | 20 |
| `publish-wan-atlantic-20261104-040902.json` | 2026-11-04 04:09 | publish | `futurelock` | 127 | 20 | wan-atlantic | 0.0% | 20 |
| `publish-wan-eu-20261104-041117.json` | 2026-11-04 04:11 | publish | `futurelock` | 127 | 20 | wan-eu | 0.5% | 40 |
| `publish-lan-20261104-043502.json` | 2026-11-04 04:35 | publish | `k20-nocheck` | 127 | 20 | lan | 0.0% | 20 |
| `publish-wan-eu-20261104-043622.json` | 2026-11-04 04:36 | publish | `k20-nocheck` | 127 | 20 | wan-eu | 0.0% | 20 |
| `publish-wan-atlantic-20261104-043751.json` | 2026-11-04 04:37 | publish | `k20-nocheck` | 127 | 20 | wan-atlantic | 0.0% | 20 |
| `publish-wan-eu-20261104-044000.json` | 2026-11-04 04:40 | publish | `k20-nocheck` | 127 | 20 | wan-eu | 0.5% | 40 |
| `publish-lan-20261104-044108.json` | 2026-11-04 04:41 | publish | `k20-noresend` | 127 | 20 | lan | 0.0% | 20 |
| `publish-wan-eu-20261104-044235.json` | 2026-11-04 04:42 | publish | `k20-noresend` | 127 | 20 | wan-eu | 0.0% | 20 |
| `publish-wan-atlantic-20261104-044404.json` | 2026-11-04 04:44 | publish | `k20-noresend` | 127 | 20 | wan-atlantic | 0.0% | 20 |
| `publish-wan-eu-20261104-044832.json` | 2026-11-04 04:48 | publish | `k20-noresend` | 127 | 20 | wan-eu | 0.5% | 40 |
| `publish-wan-eu-20261104-223805.json` | 2026-11-04 22:38 | publish | `o2-fc79016` | 127 | 20 | wan-eu | 0.0% | 20 |
| `publish-wan-atlantic-20261104-223933.json` | 2026-11-04 22:39 | publish | `o2-fc79016` | 127 | 20 | wan-atlantic | 0.0% | 20 |
| `publish-lan-20261104-224038.json` | 2026-11-04 22:40 | publish | `o2-fc79016` | 127 | 20 | lan | 0.0% | 20 |
| `publish-wan-eu-20261104-224251.json` | 2026-11-04 22:42 | publish | `o2-fc79016` | 127 | 20 | wan-eu | 0.5% | 40 |
| `publish-wan-eu-20261104-224730.json` | 2026-11-04 22:47 | publish | `futurelock` | 127 | 20 | wan-eu | 0.0% | 20 |
| `publish-wan-eu-20261104-225121.json` | 2026-11-04 22:51 | publish | `o2-counters` | 127 | 20 | wan-eu | 0.0% | 40 |
| `publish-wan-atlantic-20261104-225338.json` | 2026-11-04 22:53 | publish | `o2-counters` | 127 | 20 | wan-atlantic | 0.0% | 20 |
| `publish-wan-eu-20261104-225557.json` | 2026-11-04 22:55 | publish | `o2-counters` | 127 | 20 | wan-eu | 0.0% | 10 |
| `publish-wan-eu-20261104-225822.json` | 2026-11-04 22:58 | publish | `o2-counters` | 127 | 20 | wan-eu | 0.0% | 10 |
| `publish-lan-20261104-230108.json` | 2026-11-04 23:01 | publish | `o1-e383d17` | 127 | 20 | lan | 0.0% | 20 |
| `publish-lan-20261104-230212.json` | 2026-11-04 23:02 | publish | `o2-counters` | 127 | 20 | lan | 0.0% | 20 |
| `publish-wan-eu-20261104-230319.json` | 2026-11-04 23:03 | publish | `o1-e383d17` | 127 | 20 | wan-eu | 0.0% | 20 |
| `publish-wan-eu-20261104-230425.json` | 2026-11-04 23:04 | publish | `o2-counters` | 127 | 20 | wan-eu | 0.0% | 20 |
| `publish-wan-atlantic-20261104-230541.json` | 2026-11-04 23:05 | publish | `o1-e383d17` | 127 | 20 | wan-atlantic | 0.0% | 20 |
| `publish-wan-atlantic-20261104-230659.json` | 2026-11-04 23:06 | publish | `o2-counters` | 127 | 20 | wan-atlantic | 0.0% | 20 |
| `publish-wan-eu-20261104-230901.json` | 2026-11-04 23:09 | publish | `o1-e383d17` | 127 | 20 | wan-eu | 0.5% | 40 |
| `publish-wan-eu-20261104-231102.json` | 2026-11-04 23:11 | publish | `o2-counters` | 127 | 20 | wan-eu | 0.5% | 40 |
| `publish-lan-20261104-231344.json` | 2026-11-04 23:13 | publish | `o2-counters` | 127 | 20 | lan | 0.0% | 20 |
| `publish-wan-eu-20261104-231610.json` | 2026-11-04 23:16 | publish | `o2-counters` | 127 | 20 | wan-eu | 0.0% | 20 |
| `publish-wan-eu-20261104-232049.json` | 2026-11-04 23:20 | publish | `o2-counters` | 127 | 20 | wan-eu | 0.5% | 40 |
| `race-lan-20261104-232138.json` | 2026-11-04 23:21 | race | `o2-counters` | 10 | 3 | lan | 0.0% | 20 |
| `race-wan-eu-20261104-232227.json` | 2026-11-04 23:22 | race | `o2-counters` | 10 | 3 | wan-eu | 0.0% | 20 |
| `race-wan-atlantic-20261104-232332.json` | 2026-11-04 23:23 | race | `o2-counters` | 10 | 3 | wan-atlantic | 0.0% | 20 |
| `race-wan-eu-20261104-232420.json` | 2026-11-04 23:24 | race | `o2-counters` | 10 | 3 | wan-eu | 0.0% | 20 |
| `restart-wan-eu-20261104-232552.json` | 2026-11-04 23:25 | restart | `o2-counters` | 10 | 3 | wan-eu | 0.0% | 20 |
| `restart-wan-eu-20261104-232724.json` | 2026-11-04 23:27 | restart | `o2-counters` | 10 | 3 | wan-eu | 0.0% | 20 |
| `race-wan-eu-20261104-232942.json` | 2026-11-04 23:29 | race | `o1-e383d17` | 10 | 3 | wan-eu | 0.0% | 40 |
| `race-wan-eu-20261104-233114.json` | 2026-11-04 23:31 | race | `o2-counters` | 10 | 3 | wan-eu | 0.0% | 40 |
