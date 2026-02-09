# EasyEnclave FAQ

Frequently asked questions about EasyEnclave, remote attestation, TEEs, and privacy-preserving applications.

## Table of Contents

- [General](#general)
- [Remote Attestation](#remote-attestation)
- [TEE Technologies](#tee-technologies)
- [Security & Threats](#security--threats)
- [ORAM & Privacy](#oram--privacy)
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
- **Add ORAM** for access pattern protection
- **Use MPC** for multi-party scenarios
- **Use encryption** for data at rest

### How does ORAM help with tee.fail attacks?

**ORAM (Oblivious RAM)** protects access patterns even if TEE is compromised.

**Scenario: Contact discovery**

**Without ORAM (TDX only):**
```
Attacker with physical access:
1. Extracts TDX encryption keys (voltage glitching)
2. Dumps database
3. Monitors database accesses
4. Sees: "User X queried contacts A, B, C"
❌ Privacy leaked!
```

**With ORAM (TDX + ORAM):**
```
Attacker with physical access:
1. Extracts TDX encryption keys (voltage glitching)
2. Dumps database → sees encrypted blocks (gibberish)
3. Monitors database accesses → sees random bucket reads
4. Cannot determine which contacts were queried
✅ Access patterns protected!
```

**Why ORAM matters:**

| Protection Level | Defends Against | Use When |
|------------------|-----------------|----------|
| **TDX alone** | Cloud provider, malicious OS | General applications |
| **TDX + ORAM** | Physical attacks, side channels | High-security use cases |
| **TDX + ORAM + MPC** | Insider threats, collusion | Maximum security |

**See:** `apps/oram-contacts/` for a working example

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
| **High** | TDX + ORAM + MPC + defense-in-depth |
| **Maximum** | Air-gapped + HSMs + formal verification |

**For most use cases:** TDX attestation is sufficient.

**For privacy-critical apps:** Add ORAM (see `apps/oram-contacts/`).

---

## ORAM & Privacy

### What is ORAM?

**Oblivious RAM (ORAM)** hides which data you access.

**Traditional database:**
```sql
SELECT * FROM users WHERE id = 42;
-- Reads row 42 from disk
-- ❌ Attacker sees: "User accessed row 42"
```

**ORAM database:**
```
Read blocks [7, 12, 15, 23, 31, ...] (10 random blocks)
Write blocks [3, 18, 29, 45, ...] (8 random blocks)
-- ✅ Attacker sees: "Random block accesses"
-- Cannot tell which user was queried
```

**Key property:** All queries look identical (same # of accesses).

### How does ORAM work?

**Cuckoo Hash ORAM (used in EasyEnclave example):**

```
Data Storage:
┌──────────┬──────────┬──────────┐
│ Bucket 0 │ Bucket 1 │ Bucket 2 │ ... (1024 buckets)
├──────────┼──────────┼──────────┤
│ Block A  │ Block E  │ Block C  │
│ Block B  │ Block F  │ Block D  │
│ Dummy    │ Dummy    │ Block G  │
│ Dummy    │ Dummy    │ Dummy    │
└──────────┴──────────┴──────────┘

Position Map (in memory):
Contact "Alice" → Bucket 7, Slot 2
Contact "Bob"   → Bucket 15, Slot 1
...
```

**Read operation:**
1. Check position map → Contact is in bucket 7
2. Read bucket 7 (4 blocks)
3. Read alternative bucket 12 (4 blocks) - even if not there!
4. Read stash (overflow storage)
5. **Total: Always read ~10 blocks regardless of result**

**Write operation:**
1. Remove old block (if exists)
2. Add to stash
3. Evict from stash to random buckets (cuckoo hashing)
4. **Total: Always write ~8 blocks**

**Security: Attacker sees same pattern for all queries!**

### What's the performance overhead of ORAM?

**Typical overhead: 20-100x slower than regular database**

| Operation | Traditional DB | ORAM | Overhead |
|-----------|----------------|------|----------|
| Single read | 0.1ms (1 page) | 2-10ms (10 pages) | 20-100x |
| Batch read | 1ms (10 pages) | 50-100ms (100 pages) | 50x |
| Write | 0.1ms | 5-15ms | 50-150x |

**When is this acceptable?**
- ✅ Infrequent queries (contact discovery)
- ✅ High-value privacy (medical records)
- ✅ Small datasets (<100K records)
- ❌ High-throughput databases
- ❌ Real-time analytics
- ❌ Large-scale data warehouses

**Example: Contact discovery**
- User checks 10 contacts per day
- 10ms per query = 100ms total
- Privacy benefit >> 100ms overhead

### When should I use ORAM?

**Use ORAM when:**
1. **Access patterns reveal sensitive info**
   - Contact discovery (who you know)
   - Medical records (which diseases queried)
   - Search queries (what you're interested in)

2. **Attacker has physical access**
   - Nation-state adversaries
   - Compromised hardware
   - Side-channel attacks

3. **Compliance requires it**
   - GDPR (access pattern = personal data)
   - HIPAA (medical query patterns)
   - Zero-knowledge requirements

**Don't use ORAM when:**
- Access patterns aren't sensitive
- Performance is critical
- Dataset is too large (>1M records)
- TEE protection is sufficient

### How do I add ORAM to my app?

**EasyEnclave provides a working example:** `apps/oram-contacts/`

**Quick start:**
```python
from oram_store import ORAMContactStore

# Initialize ORAM
store = ORAMContactStore(
    db_path="/data/contacts.db",
    num_buckets=1024,  # Adjust for dataset size
)

# Register contact (oblivious write)
store.register_contact(phone_hash, user_id)

# Lookup contacts (oblivious read)
results = store.lookup_contacts([phone_hash1, phone_hash2])
# All queries access same # of buckets!
```

**See full example:**
- Code: `apps/oram-contacts/oram_store.py`
- Docs: `apps/oram-contacts/README.md`
- Examples: `examples/oram-contacts/client.py`

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

**Step 5: Deploy to TDX worker**
```bash
curl -X POST https://app.easyenclave.com/api/v1/apps/myapp/versions/v1.0.0/deploy \
  -d '{"agent_id": "agent-123"}'
```

**See full guide:** `apps/oram-contacts/DEPLOYMENT.md`

### How does the measuring enclave work?

**Problem:** Docker image tags are mutable (`:latest` changes)

**Solution:** Measuring enclave resolves tags to immutable digests

```
1. You publish: myapp:v1.0.0
   ↓
2. Measuring enclave resolves:
   myapp:v1.0.0 → sha256:abc123... (immutable)
   ↓
3. Compute MRTD from digest
   ↓
4. Store MRTD in control plane
   ↓
5. Workers verify: running image matches MRTD
```

**Security benefits:**
- ✅ Tag updates don't break attestation
- ✅ Workers verify exact image
- ✅ Measuring enclave is itself attested

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

**Example apps welcome!** Check out `apps/oram-contacts/` for inspiration.
