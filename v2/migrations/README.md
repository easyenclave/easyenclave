# v2 Migrations

`v2/migrations` is reserved for the Go rewrite schema only.

Rules:
- No dependency on legacy Python migration history.
- Keep runtime liveness independent from DB completeness.
- Persist only state that cannot be reconstructed from live agents + bootstrap config.

Required recovery posture:
- If the runtime DB is lost, CP can restart, agents reconnect, and runtime state is rehydrated from agent snapshots and bootstrap state.
