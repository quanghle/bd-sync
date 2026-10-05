# Benchmarks

`bd bench` seeds a random dependency graph on a scratch database, drains it
with N workers (claim → work → close), and verifies from the event log that
every issue was claimed and closed exactly once, and never before its
blockers closed.

| mode | workers are | measures |
|---|---|---|
| `threads` (default) | threads in this process, one connection each | the embedded library |
| `processes` | long-lived worker processes | cross-process locking |
| `cli` | a fresh `bd` process per operation | what CLI agents experience |
| `remote` | like `cli`, through a scratch `bd serve` on loopback (HTTP, access token, one sub-actor per worker) | what clients of a bd server experience |

| flag | default | meaning |
|---|---|---|
| `-w, --workers N` | 8 | concurrent workers |
| `--mode` | `threads` | above |
| `-n, --issues N` | 2000 | issues to seed |
| `--deps F` | 1.0 | average blocking dependencies per issue |
| `--work-ms MS` | 0 | simulated work per claim |
| `--heartbeat` | off | heartbeat once per claim before closing |
| `--durability` | `normal` | `off`, `normal` or `full` |
| `--keep PATH` | temporary | keep the scratch database at this path |
| `--seed N` | 42 | random seed |

## Results

A WSL2 laptop, release build, `durability=normal`, 3,000 issues with about
one blocking edge each:

| mode | workers | claims/s | write tx/s | claim p50 | claim p99 |
|---|---|---|---|---|---|
| threads | 1 | 3,600 | 7,100 | 63 µs | 0.2 ms |
| threads | 4 | 4,500 | 9,000 | 87 µs | 10 ms |
| processes | 8 | 4,700 | 9,300 | 85 µs | 11 ms |
| cli | 1 | 235 | 470 | 2.0 ms | 2.6 ms |
| cli | 8 | 920 | 1,800 | 2.7 ms | 22 ms |
| remote | 1 | 180 | 370 | 2.6 ms | 3.5 ms |
| remote | 8 | 1,030 | 2,060 | 3.1 ms | 15 ms |

- SQLite has one writer, so throughput plateaus around the single-writer
  rate.
- Tail latency comes from contention and WAL-checkpoint fsyncs: with
  `--durability off`, p99 drops below 0.4 ms. `durability=full` fsyncs
  every commit and is bounded by the disk's fsync latency.
- Through a server, one worker pays about 0.4 ms per command for HTTP, but
  8 remote workers outran 8 `cli` workers: the server keeps its database
  connections open, while each `cli` process opens the database again.
