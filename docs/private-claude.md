# private-claude on easyenclave

`private-claude` is a TDX-attested Noise-tunnel proxy for any frontier
LLM, distributed as a static `private-claude-proxy` binary in a GitHub
release. It runs as a regular easyenclave workload — no image-level
changes — and uses easyenclave's existing release-fetch + cloud-config
plumbing for delivery and key management.

Repo: `<org>/private-claude` (Rust). Wire-protocol-compatible with
[ConferLabs/confer-proxy](https://github.com/ConferLabs/confer-proxy).

## What it gives you

- **Provider-side ZDR** via OpenRouter routing (`provider.data_collection
  = "deny"` enforced server-side on every outbound request, plus the
  account-level "ZDR routing" toggle on the OpenRouter API key).
  Self-serve across Claude / GPT / Gemini / Mistral / etc. — you pick
  the model per request.
- **Enclave-side privacy** for chat history. Plaintext lives only in
  the proxy's TDX-private memory; per-VM-lifetime, no on-disk
  persistence, no S3 export.
- **Attestation-bound channel.** Clients open a Noise XX websocket
  (`Noise_XX_25519_AESGCM_SHA256`); during the handshake the proxy
  sends an Intel-Trust-Authority-signed v2 JWT whose `tdx.runtime_data`
  claim cryptographically binds the Noise static public key *and* the
  proxy binary hash. A client that doesn't pin the right release
  manifest can't establish a session.

## Threat model

- **TDX protects:** chat plaintext, the Noise static private key, the
  OpenRouter API key, and the ITA API key — all live only in TDX-private
  memory and are inaccessible to the host/cloud operator.
- **TDX does not protect:** the provider side (handled by OpenRouter
  ZDR routing) or the client (not in scope — install only trusted
  clients).
- **ZDR is delegated to OpenRouter.** The proxy enforces the routing
  flag on every outbound; OpenRouter enforces it across providers.
  Strictly stronger than default behavior, weaker than a direct
  Anthropic enterprise ZDR contract — the trade-off you make for
  self-serve multi-provider.

## Required env (set on the easyenclave VM via customData / IMDS / agent.env)

| Var | Purpose |
|---|---|
| `OPENROUTER_API_KEY` | Bearer token. The account should have "ZDR routing" turned on too. |
| `ITA_API_KEY` | Intel Trust Authority key — the proxy uses this to fetch a freshness nonce and submit the TDX quote for signing. |
| `ITA_URL` | Default `https://api.trustauthority.intel.com`. |
| `PRIVATE_CLAUDE_AUTH_KEY` | 32-byte hex; PASETO v4.local key for inside-tunnel session auth. |
| `PRIVATE_CLAUDE_DEFAULT_MODEL` | Optional default, e.g. `anthropic/claude-3-5-sonnet`. |

## Sample `/etc/easyenclave/config.json`

```json
{
  "boot_workloads": [
    {
      "app_name": "private-claude",
      "github_release": {
        "repo": "<org>/private-claude",
        "asset": "private-claude-proxy-x86_64-musl.tar.gz",
        "rename": "private-claude-proxy"
      },
      "cmd": ["private-claude-proxy"],
      "env": ["RUST_LOG=info"]
    },
    {
      "app_name": "cloudflared",
      "github_release": {
        "repo": "cloudflare/cloudflared",
        "asset": "cloudflared-linux-amd64",
        "rename": "cloudflared"
      },
      "cmd": ["cloudflared", "tunnel", "--url", "http://127.0.0.1:8080", "run"]
    }
  ]
}
```

The proxy binds `0.0.0.0:8080` for plain `ws://` (TLS termination is
cloudflared's job, exactly as in the rest of the easyenclave deployment
shape; the confidentiality story is the Noise tunnel, not transport TLS).

## Compatible clients

Any Noise XX client that can verify an ITA v2 JWT and pin a
release-published `MEASUREMENTS.md` can talk to this proxy. The
intended deliverable for end users is a small Tauri desktop app
(`private-claude-app`, post-v1) that bundles the verifier + a built-in
chat UI **and** exposes a localhost OpenAI-compatible HTTPS endpoint —
so power users can also point Open WebUI / LobeChat / LibreChat /
Continue.dev / aider at it without losing the attestation guarantee.

## Choosing a target image

Reuse any existing easyenclave image — `gcp`, `azure`, `local-tdx-qcow2`
all work. Per-target MRTD/RTMR values are different (see the
"Attestation across targets" section above), so the release manifest
embedded in the proxy binary is keyed by target name; clients pin the
entry that matches the image they're connecting to.
