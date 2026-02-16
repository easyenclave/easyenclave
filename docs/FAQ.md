# EasyEnclave FAQ

Frequently asked questions about EasyEnclave, remote attestation, TEEs, and privacy-preserving applications.

## Table of Contents

- [General](#general)
- [Remote Attestation](#remote-attestation)
- [TEE Technologies](#tee-technologies)
- [Security & Threats](#security--threats)
- [Deployment](#deployment)

---

## General

### What is EasyEnclave?

EasyEnclave is a confidential discovery service for applications running in Trusted Execution Environments (TEEs) like Intel TDX. It provides:
- **Service registration** - Register attested services with metadata
- **Service discovery** - Find services with verified attestation
- **Attestation verification** - Verify TDX attestations via Intel Trust Authority
- **Python SDK** - Simple client library for accessing attested services

### Who is EasyEnclave for?

EasyEnclave is for developers building privacy-preserving applications:
- **Privacy-critical services** (contact discovery, private AI, confidential databases)
- **Multi-party computation** (collaborative analytics without data sharing)
- **Confidential AI** (LLMs that don't leak prompts or training data)
- **Defense-in-depth security** (protection even against physical attacks)

### How is EasyEnclave different from other TEE platforms?

**EasyEnclave focuses on simplicity:**
- 3-line SDK to connect to attested services
- GitHub Actions for one-click deployment
- Automatic attestation verification
- No complex cryptographic setup

**Other platforms require:**
- Manual attestation verification
- Complex cryptographic protocols
- Custom infrastructure setup
- Deep TEE expertise

---

## Remote Attestation

### What is remote attestation?

**Remote attestation** is a cryptographic proof that:
1. **Code is running in a real TEE** (not emulated)
2. **Code matches expected measurement** (MRTD hash)
3. **TEE is genuine and up-to-date** (signed by vendor)

**How it works:**
```
┌──────────────────────┐
│  TDX Virtual Machine │
│  ┌────────────────┐  │
│  │  Your App      │  │
│  │  (code + data) │  │
│  └────────────────┘  │
│         ↓            │
│  Measured by TDX     │
│  (MRTD = SHA384)     │
└──────────┬───────────┘
           │
           ↓
    ┌─────────────────┐
    │ Intel Hardware  │
    │ Signs Quote     │
    │ (private key)   │
    └─────────┬───────┘
              │
              ↓
      ┌────────────────┐
      │ Intel Trust    │
      │ Authority      │
      │ Verifies Quote │
      └────────────────┘
              │
              ↓
        ✅ Attestation Valid
```

**Key concepts:**
- **MRTD (Measurement)** - Hash of VM image (kernel, app, config)
- **Quote** - Signed attestation from TEE hardware
- **Trust Authority** - Vendor service that verifies quotes (Intel ITA, Azure MAA, etc.)

### Why is remote attestation important?

**Without attestation:**
- ❌ You don't know what code is running
- ❌ Server could be compromised
- ❌ Data could be logged or stolen
- ❌ No proof of privacy protection

**With attestation:**
- ✅ Cryptographic proof of exact code
- ✅ Verify before sending sensitive data
- ✅ TEE protects against OS/hypervisor attacks
- ✅ Build zero-trust applications

### What TEE vendors support remote attestation?

| Vendor | Technology | Attestation Service | Status |
|--------|------------|---------------------|--------|
| **Intel** | TDX (Trust Domain Extensions) | Intel Trust Authority | ✅ Production |
| **AMD** | SEV-SNP (Secure Encrypted Virtualization) | AMD ASP | ✅ Production |
| **ARM** | CCA (Confidential Compute Architecture) | ARM CCA Services | 🚧 Preview |
| **Intel** | SGX (Software Guard Extensions) | Intel Attestation Service | ⚠️ Legacy |
| **IBM** | PEF (Protected Execution Facility) | IBM Crypto | ✅ Production |
| **NVIDIA** | H100 Confidential Computing | NVIDIA RAS | 🚧 Preview |

**EasyEnclave currently supports:**
- ✅ Intel TDX (primary focus)
- 🔜 AMD SEV-SNP (planned)
- 🔜 ARM CCA (planned)

### How does EasyEnclave verify attestations?

```python
# Simplified flow in EasyEnclave SDK

# 1. Client requests service
client = EasyEnclaveClient("https://app.easyenclave.com")
service = client.service("my-app")

# 2. SDK fetches expected MRTD from control plane
expected_mrtd = control_plane.get_app_mrtd("my-app", "v1.0.0")

# 3. SDK requests attestation quote from service
quote = service.get_attestation_quote()

# 4. SDK sends quote to Intel Trust Authority
ita_response = intel_trust_authority.verify(quote)

# 5. SDK checks MRTD matches
assert ita_response.mrtd == expected_mrtd  # ✅

# 6. Only then allow access to service
response = service.post("/api/endpoint", json={...})
```

**Security properties:**
- Client never trusts unattested services
- MRTD is pinned to specific app version
- Intel verifies hardware signature
- Replay attacks prevented (nonces)

### Can I trust the attestation service?

**Trust model:**

**You trust:**
- ✅ Intel/AMD/ARM hardware (root of trust)
- ✅ Vendor attestation service (Intel ITA, etc.)
- ✅ Your own MRTD (you built the image)

**You DON'T trust:**
- ❌ Cloud provider (they can't read TEE memory)
- ❌ EasyEnclave control plane (only stores metadata)
- ❌ Network (attestation is cryptographically verified)

**Intel Trust Authority:**
- Operated by Intel (hardware vendor)
- Verifies quotes signed by Intel CPUs
- Cannot fake attestations (requires private key in CPU)
- Industry standard for TDX attestation

**Alternative:** Self-host attestation service (advanced)

---

## TEE Technologies

### What is Intel TDX?

**Intel Trust Domain Extensions (TDX)** is a hardware-based TEE technology.

**How it works:**
- **Hardware isolation** - CPU enforces memory encryption
- **Encrypted memory** - All RAM encrypted with per-VM keys
- **Integrity protection** - Detects memory tampering
- **Attestation** - Cryptographic proof of running code

**Protection boundaries:**
```
┌─────────────────────────────────────────┐
│  Untrusted: Cloud Provider              │
│  ┌───────────────────────────────────┐  │
│  │ Hypervisor (VMware, KVM, Hyper-V) │  │
│  │ ❌ Cannot read TDX memory          │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │ Operating System (Linux, etc.)    │  │
│  │ ❌ Cannot read TDX memory          │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
           ↓ Encrypted boundary
┌─────────────────────────────────────────┐
│  Trusted: TDX Virtual Machine           │
│  ┌───────────────────────────────────┐  │
│  │ Your Application + Data           │  │
│  │ ✅ Protected by hardware          │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**Requirements:**
- 4th Gen Intel Xeon Scalable or newer (Sapphire Rapids+)
- TDX-enabled BIOS
- TDX-aware hypervisor (KVM, VMware ESXi)

### What's the difference between TDX and SGX?

| Feature | Intel TDX | Intel SGX |
|---------|-----------|-----------|
| **Isolation** | Full VM | Enclave (process) |
| **Memory** | Gigabytes | Megabytes |
| **Performance** | Near-native | 10-50% overhead |
| **OS Support** | Any OS | Modified app |
| **Use Case** | Large apps | Small modules |
| **Status** | ✅ Production | ⚠️ Deprecated on client CPUs |

**TDX advantages:**
- Run entire VMs (no app changes)
- More memory (scale to hundreds of GBs)
- Better performance
- Easier to use

**SGX advantages:**
- Smaller TCB (fewer trusted components)
- Works on older hardware
- More mature ecosystem

**EasyEnclave focuses on TDX** because it's easier for developers and supports larger applications (like LLMs).

### How does TDX compare to AMD SEV-SNP?

| Feature | Intel TDX | AMD SEV-SNP |
|---------|-----------|-------------|
| **Encryption** | AES-GCM per-VM | AES per-VM |
| **Integrity** | Hardware checks | Hardware checks |
| **Attestation** | Intel Trust Authority | AMD ASP |
| **Availability** | 4th Gen Xeon+ | EPYC Milan+ |
| **Maturity** | Production (2023+) | Production (2021+) |

**Both provide:**
- ✅ Memory encryption
- ✅ Remote attestation
- ✅ VM-level isolation
- ✅ Protection from cloud provider

**Key difference:** Vendor ecosystem (Intel vs AMD)

---

## Security & Threats

### What attacks does TDX protect against?

| Attack Type | TDX Protection | Notes |
|-------------|----------------|-------|
| **Remote attacker** | ✅ Full | Encrypted memory, network isolation |
| **Malicious hypervisor** | ✅ Full | Hardware-enforced memory encryption |
| **Malicious OS** | ✅ Full | TEE isolated from OS |
| **Physical memory dump** | ✅ Partial | Memory encrypted, but keys could be extracted |
| **Side channels (cache)** | ⚠️ Partial | Some mitigations, not perfect |
| **Voltage glitching** | ⚠️ Limited | Hardware defenses, but attackable |

### What is tee.fail about?

**[tee.fail](https://tee.fail)** documents physical attacks on TEEs, showing that:

1. **TEE encryption can be broken** with physical access
   - Voltage glitching
   - Laser fault injection
   - Memory bus sniffing

2. **Side channels leak information**
   - Cache timing attacks
   - Page fault patterns
   - Memory access patterns

3. **Supply chain attacks** possible
   - Compromised firmware
   - Modified hardware

**Does this mean TEEs are useless?**

**No!** TEEs still provide strong protection:

✅ **Against remote attackers** - TDX is excellent
✅ **Against cloud providers** - Strong protection
✅ **Against malicious OS** - Full protection
⚠️ **Against nation-states with physical access** - Limited

**Defense-in-depth approach:**
- **Use TEEs** for cloud/OS protection
- **Add encrypted storage** for data-at-rest protection
- **Use MPC** for multi-party scenarios
- **Add protocol-level encryption** for data in transit

### Should I worry about physical attacks?

**It depends on your threat model:**

**Low risk scenarios:**
- Running on your own hardware
- Trusted cloud provider
- Non-critical data

**High risk scenarios:**
- Nation-state adversaries
- High-value data (medical, financial)
- Regulated industries (HIPAA, GDPR)

**Recommendations:**

| Threat Level | Protection Strategy |
|--------------|---------------------|
| **Basic** | TDX + attestation |
| **Moderate** | TDX + attestation + encrypted storage |
| **High** | TDX + encrypted storage + MPC + defense-in-depth |
| **Maximum** | Air-gapped + HSMs + formal verification |

**For most use cases:** TDX attestation is sufficient.

---

## Deployment

### How do I deploy my app on EasyEnclave?

**Step 1: Containerize your app**
```dockerfile
FROM python:3.11
COPY . /app
RUN pip install -r requirements.txt
CMD ["uvicorn", "app:app", "--host", "0.0.0.0"]
```

**Step 2: Push to registry**
```bash
docker build -t ghcr.io/you/myapp:v1.0.0 .
docker push ghcr.io/you/myapp:v1.0.0
```

**Step 3: Register with EasyEnclave**
```bash
curl -X POST https://app.easyenclave.com/api/v1/apps \
  -H "Content-Type: application/json" \
  -d '{"name": "myapp", "description": "My app"}'
```

**Step 4: Publish version**
```bash
COMPOSE_B64=$(base64 -w 0 docker-compose.yml)
curl -X POST https://app.easyenclave.com/api/v1/apps/myapp/versions \
  -d "{\"version\": \"v1.0.0\", \"compose\": \"$COMPOSE_B64\"}"
```

**Step 5: Deploy to verified TDX capacity**
```bash
curl -X POST https://app.easyenclave.com/api/v1/apps/myapp/versions/v1.0.0/deploy \
  -d '{
    "node_size": "tiny",
    "allowed_datacenters": ["gcp:us-central1-a"]
  }'
```

The control plane selects the agent automatically from verified healthy capacity. Use `agent_id` only for controlled upgrade or recovery workflows.

**See full guide:** main README deployment examples and `.github/workflows/deploy-examples.yml`.

### How does the measuring enclave work?

**Problem:** Docker image tags are mutable (`:latest` changes)

**Solution:** Measurer apps resolve tags to immutable digests and return per-size measurements

```
1. You publish: myapp:v1.0.0 (with optional `node_size`)
   ↓
2. Control plane routes to measurer app:
   measuring-enclave or measuring-enclave-<node_size>
   ↓
3. Measurer resolves:
   myapp:v1.0.0 → sha256:abc123... (immutable)
   ↓
4. Compute trusted values for that size
   ↓
5. Store measurement on app version (scoped by node_size)
   ↓
6. Scheduler only deploys to agents with matching node_size + measurement
```

**Security benefits:**
- ✅ Tag updates don't break attestation
- ✅ Workers verify exact image + size profile
- ✅ Measurer runs as an attested app on verified tiny TDX agents (bare metal or GCP)
- ✅ Unmeasured versions are blocked from deployment

**See:** `apps/measuring-enclave/` for implementation

### Can I run EasyEnclave on non-TDX hardware?

**Yes, but without attestation.**

**Development mode:**
```bash
docker compose up  # Runs locally without TDX
```

**Production (requires TDX):**
- Intel 4th Gen Xeon Scalable or newer
- TDX-enabled BIOS
- TDX-aware hypervisor

**Cloud providers with TDX:**
- ✅ Azure (DCasv5, ECasv5 series)
- ✅ Google Cloud (C3 series)
- ✅ AWS (planned)
- ✅ IBM Cloud (select regions)

### How much does it cost to run TDX VMs?

**Cloud pricing (as of 2024):**

| Provider | Instance Type | vCPUs | RAM | Price/hour |
|----------|---------------|-------|-----|------------|
| **Azure** | DCasv5-4 | 4 | 16 GB | ~$0.50 |
| **Azure** | DCasv5-8 | 8 | 32 GB | ~$1.00 |
| **Google Cloud** | c3-standard-4 | 4 | 16 GB | ~$0.45 |
| **Google Cloud** | c3-standard-8 | 8 | 32 GB | ~$0.90 |

**Note:** Prices vary by region. TDX VMs cost ~10-20% more than regular VMs.

### Can I self-host the control plane?

**Yes!** EasyEnclave is open source.

```bash
git clone https://github.com/easyenclave/easyenclave
cd easyenclave
docker compose up
```

**Requirements:**
- Docker + Docker Compose
- PostgreSQL (or SQLite for dev)
- Intel Trust Authority API key

**See:** Main README for configuration

---

## Contributing

Found a bug or have a question? [Open an issue](https://github.com/easyenclave/easyenclave/issues).

Want to contribute? See [CONTRIBUTING.md](../CONTRIBUTING.md).

**Example apps welcome!** Check out `examples/hello-tdx/` and `examples/private-llm/` for inspiration.
