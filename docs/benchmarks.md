# Benchmarks

`bd bench` seeds a random DAG on a scratch database, drains it with N
workers (claim → work → close), and verifies from the event log that every
issue was claimed and closed exactly once and never before its blockers
closed. It has four modes:

- `threads`: an embedded library, one connection per thread
- `processes`: long-lived worker processes
- `cli`: a fresh `bd` process per operation, which is what agents experience
- `remote`: like `cli`, but through a scratch `bd serve` on loopback (HTTP,
  access token, one sub-actor per worker), which is what clients of a bd
  server experience

Results on a WSL2 laptop (release build, `durability=normal`, 3,000 issues, about one blocking edge each):

| mode | workers | claims/s | write tx/s | claim p50 | claim p99 |
|---|---|---|---|---|---|
| threads | 1 | 3,600 | 7,100 | 63 µs | 0.2 ms |
| threads | 4 | 4,500 | 9,000 | 87 µs | 10 ms |
| processes | 8 | 4,700 | 9,300 | 85 µs | 11 ms |
| cli | 1 | 235 | 470 | 2.0 ms | 2.6 ms |
| cli | 8 | 920 | 1,800 | 2.7 ms | 22 ms |
| remote | 1 | 180 | 370 | 2.6 ms | 3.5 ms |
| remote | 8 | 1,030 | 2,060 | 3.1 ms | 15 ms |

SQLite has one writer, so throughput plateaus around the single-writer rate.
Tail latency comes from contention and WAL-checkpoint fsyncs: with
`--durability off`, p99 drops below 0.4 ms. `durability=full` fsyncs every
commit and is bounded by the disk's fsync latency. Through a server, one
worker pays about 0.4 ms per command for HTTP, but 8 workers outran `cli`
(1,030 against 810 claims/s in the same run): the server keeps its database
connections open, while each `cli` process opens the database again.
