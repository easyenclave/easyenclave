# GPU evidence on easyenclave

EasyEnclave produces TDX evidence by default. On confidential-GPU hosts
(NVIDIA H100 / H200 in CC mode), the `attest` socket method can also
fold raw NVIDIA GPU evidence into its response so a relying party can
hand the bundle to Intel Trust Authority (ITA) v2's combined-appraisal
endpoint.

The runtime stays an evidence *producer*, not a verifier — same
invariant as the TDX path. PID 1 does not run nv-ppcie-verifier, does
not call NRAS, and does not gate on partial evidence.

## Wire shape

`attest` response — TDX-only (default, unchanged):

```json
{
  "ok": true,
  "attestation_type": "tdx",
  "quote_format": "tdx",
  "quote_b64": "<TDX quote>",
  "report_data_b64": "<input>",
  "report_data_len": 32
}
```

`attest` response — GPU helper present, success:

```json
{
  "ok": true,
  "attestation_type": "tdx",
  "quote_format": "tdx",
  "quote_b64": "<TDX quote>",
  "report_data_b64": "<input>",
  "report_data_len": 32,
  "evidence": {
    "nvgpu": {
      "gpu_attestation_report_b64": "<raw GPU report>",
      "switch_attestation_report_b64": "<raw NVSwitch report — omitted on single-GPU>",
      "collected_at": 1745889600,
      "helper": "nvidia-cc"
    }
  }
}
```

`attest` response — GPU helper configured but failed:

```json
{
  "ok": true,
  "attestation_type": "tdx",
  "quote_format": "tdx",
  "quote_b64": "<TDX quote>",
  "report_data_b64": "<input>",
  "report_data_len": 32,
  "evidence": {
    "nvgpu_error": "helper exited 1: GPU not in CC mode"
  }
}
```

The TDX quote is always returned when TDX is healthy. A GPU helper
failure surfaces as `evidence.nvgpu_error` and never escalates to a
top-level `"ok": false`.

`health` response surfaces the helper identifier when configured, so
clients can detect capability without an `attest` round-trip:

```json
{
  "ok": true,
  "attestation_type": "tdx",
  "gpu_evidence_type": "nvidia-cc",
  "workloads": 3,
  "uptime_secs": 120
}
```

## Helper protocol

The GPU helper is a separate executable owned by the image, not by the
runtime. PID 1 launches it on each `attest` call (gated by an in-process
TTL cache). The contract:

| Channel | Direction | Today | Reserved for |
|---------|-----------|-------|--------------|
| stdin | runtime → helper | nothing written | verifier nonce, when binding protocol pins down |
| stdout | helper → runtime | length-prefixed evidence | (same) |
| stderr | helper → runtime | diagnostics | (same) — captured into `evidence.nvgpu_error` on failure |
| exit code | helper → runtime | `0` = success, anything else = error | (same) |

Stdout wire format:

```
gpu_report_len  : u32 big-endian
gpu_report      : <gpu_report_len> raw bytes
switch_report_len : u32 big-endian
switch_report   : <switch_report_len> raw bytes (may be 0 on single-GPU)
```

A helper that has nothing to report **must** still emit the four-byte
zero length prefix for both fields. The parser uses framing, not EOF.
Length must not exceed 64 MiB per field.

Configuration (in `/etc/easyenclave/config.json`, all overridable via
the corresponding `EE_*` env vars):

```json
"gpu_attestation": {
  "enabled": true,
  "helper_path": "/usr/local/bin/ee-gpu-evidence",
  "timeout_secs": 15,
  "cache_ttl_secs": 60
}
```

If `gpu_attestation` is absent, `enabled` is `false`, or `helper_path`
doesn't exist on disk, the runtime stays TDX-only — booting on a
non-GPU host with the llm-cuda config still works.

## Assembling an ITA v2 combined appraisal request

The runtime emits raw evidence bytes; the relying party (a private-claude
analogue or a small verifier sidecar — explicitly *not* PID 1) assembles
the ITA appraisal payload:

1. Get a verifier nonce: `GET https://api.trustauthority.intel.com/appraisal/v2/nonce`.
2. Compute the 64-byte TDX `report_data` per Intel's client-adapter
   guidance. Today the runtime treats `report_data_b64` as opaque and
   passes it through untouched, so the binding protocol lives at the
   relying party.
3. Send `{"method": "attest", "report_data_b64": "<...>"}` over the
   easyenclave socket. (When the GPU-binding protocol pins down nonce-based
   combined evidence, the runtime will write the verifier nonce on the
   helper's stdin — currently `Stdio::null()` in `src/attestation/nvgpu.rs`.)
4. POST to ITA `appraisal/v2/attest`:

   ```json
   {
     "tdx": {
       "quote": "<from response.quote_b64>",
       "verifier_nonce": {"val": "...", "iat": "...", "signature": "..."}
     },
     "nvgpu": {
       "gpu_attestation_report": "<from response.evidence.nvgpu.gpu_attestation_report_b64>",
       "switch_attestation_report": "<from response.evidence.nvgpu.switch_attestation_report_b64, if present>"
     },
     "policy_ids": ["<policy-id>"],
     "policy_must_match": true
   }
   ```

ITA returns a signed token whose `tdx` and `nvgpu` claims attest the
combined platform. The claims include the GPU UUID, driver/firmware
versions, GPU mode bits, and (if a switch report was supplied) the
fabric configuration — same surface confer-image's local
`ppcie.verifier` was producing internally, but verified by ITA so the
relying party can trust it without trusting the enclave to verify
itself.

## Open spec questions (current state)

- **Binding protocol — nonce-based vs hash-based.** The runtime stays
  neutral: `report_data_b64` is passed through unchanged, the helper
  reads stdin (today `Stdio::null()`) when nonce-binding pins down. Any
  change to the binding lives at the verifier-side adapter, not in PID 1.
- **Fabric Manager presence.** Single-GPU hosts don't run
  `nv-fabricmanager`; the helper protocol allows `switch_report_len = 0`
  to omit. The real Python helper (when the deferred bake lands) must
  not fail in that case.

## Reference points

- Code surface: `src/attestation/mod.rs` (`GpuEvidenceBackend` trait,
  `detect_gpu_evidence`), `src/attestation/nvgpu.rs` (helper-script
  backend + parser tests), `src/socket.rs` (`handle_attest`,
  `handle_health`), `src/config.rs` (`GpuAttestationConfig`).
- Image scaffolding: `image/mkosi.profiles/llm-cuda/mkosi.extra/usr/local/bin/ee-gpu-evidence`
  (stub today; real Python helper deferred), `image/mkosi.profiles/llm-cuda/mkosi.conf`
  (deferred-bake comment block enumerating `nv-attestation-sdk` pins).
- Upstream: confer-image's
  [`nvidia-cc-attestation.service`](https://github.com/ConferLabs/confer-image/blob/master/mkosi.skeleton/etc/systemd/system/nvidia-cc-attestation.service)
  and
  [NVIDIA nvtrust](https://github.com/NVIDIA/nvtrust).
- Adjacent: `docs/private-claude.md` (the existing TDX-attested workload
  pattern that this evidence channel slots into).
