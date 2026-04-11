# TODO

## TDX measurement tracking
Build-time: capture MRTD + RTMR values for each release. Registration-time: verify agent quotes against expected measurements. Sealing: encrypt secrets to measured state.

## Interactive terminal via socket
Add `{"method":"attach","id":"..."}` for bidirectional stdin/stdout streaming over the unix socket. Currently dd-client's terminal proxies through `exec` polling which is not truly interactive.

## Workload restart policy
libcontainer doesn't auto-restart crashed containers, and process workloads don't either. Add a configurable restart policy (always, on-failure, never) in `workload.rs` that supervises both container and process workloads.

## Health check for workloads
Per-workload health check config (cmd, interval, retries). Mark workload unhealthy/restart on failure. Currently only tracks running/stopped/failed.
