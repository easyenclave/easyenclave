# ORAM Contact Discovery

Privacy-preserving contact discovery service using **Oblivious RAM (ORAM)** with defense-in-depth security.

## What is ORAM?

Oblivious RAM (ORAM) is a cryptographic technique that hides **access patterns** to data. Even if an attacker:
- Has physical access to the server
- Breaks TEE encryption (TDX, SGX)
- Dumps all memory and database contents

They **cannot** determine:
- Which contacts you looked up
- How often you queried specific contacts
- Correlations between queries

## Why This Matters

Traditional databases (even encrypted ones) leak access patterns:
```
Query Alice   → Read row 42      ❌ Pattern reveals query
Query Bob     → Read row 51      ❌ Pattern reveals query
Query Alice   → Read row 42      ❌ Reveals repeated access
```

With ORAM, all queries look identical:
```
Query Alice   → Read 8-10 random buckets, Write 8-10 buckets  ✅
Query Bob     → Read 8-10 random buckets, Write 8-10 buckets  ✅
Query Charlie → Read 8-10 random buckets, Write 8-10 buckets  ✅
```

An observer (even with full database access) cannot distinguish between these queries.

## Threat Model

| Attack Vector | Traditional DB | TDX Only | TDX + ORAM |
|---------------|----------------|----------|------------|
| Remote attacker | ❌ Exposed | ✅ Protected | ✅ Protected |
| Malicious OS | ❌ Exposed | ✅ Protected | ✅ Protected |
| Cache timing | ❌ Leaks | ❌ Leaks | ✅ Protected |
| Physical access | ❌ Game over | ❌ Keys extracted | ✅ Patterns hidden |
| Page faults | ❌ Leaks | ❌ Leaks | ✅ Protected |

**Reference:** [tee.fail](https://tee.fail) - Physical attacks on TEEs

## Architecture

```
┌──────────────────────┐
│  Client Application  │
└──────────┬───────────┘
           │ EasyEnclave SDK
           ↓
┌──────────────────────┐
│  EasyEnclave CP      │
│  (attestation +      │
│   proxy routing)     │
└──────────┬───────────┘
           │ Verified tunnel
           ↓
┌──────────────────────────────────┐
│  TDX Worker                       │
│  ┌────────────────────────────┐  │
│  │ ORAM Contacts App          │  │
│  │ ├── FastAPI endpoints      │  │
│  │ ├── ORAM store (cuckoo)    │  │
│  │ └── SQLite backend         │  │
│  └────────────────────────────┘  │
│  MRTD: <measured hash>           │
└──────────────────────────────────┘
```

### ORAM Implementation

**Cuckoo Hash Bucketing:**
- Two hash functions for each logical address
- Multiple blocks per bucket (4 blocks/bucket)
- Stash for overflow handling
- Every query accesses same number of buckets

**Encryption:**
- AES-GCM for all stored blocks
- Unique nonce per block
- No plaintext in database

**Storage:**
- SQLite backend for persistence
- Encrypted buckets table
- Stash table for overflow
- Position map (kept in memory)

## API Reference

### POST `/register`

Register a contact.

**Request:**
```json
{
  "phone_number": "+1-555-0100",
  "user_id": "alice"
}
```

**Response:**
```json
{
  "registered": true,
  "user_id": "alice"
}
```

**Security:** Phone number is hashed (SHA-256) and stored obliviously in ORAM.

---

### POST `/lookup`

Lookup contacts by phone hash.

**Request:**
```json
{
  "phone_hashes": [
    "a3c1f...",  // hex-encoded SHA-256
    "b7d9e..."
  ]
}
```

**Response:**
```json
{
  "results": ["alice", null]  // null if not found
}
```

**Security:** All queries access same number of buckets (oblivious).

---

### GET `/health`

Health check with ORAM statistics.

**Response:**
```json
{
  "status": "healthy",
  "oram_stats": {
    "total_capacity": 4096,
    "num_contacts": 150,
    "stash_size": 5,
    "occupancy": 0.0366
  }
}
```

---

### GET `/stats`

Detailed ORAM statistics (admin).

**Response:**
```json
{
  "total_capacity": 4096,
  "num_contacts": 150,
  "stash_size": 5,
  "occupancy": 0.0366
}
```

## Deployment

### 1. Build Docker Image

```bash
cd apps/oram-contacts
docker build -t ghcr.io/easyenclave/oram-contacts:v1.0.0 .
docker push ghcr.io/easyenclave/oram-contacts:v1.0.0
```

### 2. Register with EasyEnclave

```bash
# Register app
curl -X POST https://app.easyenclave.com/api/v1/apps \
  -H "Content-Type: application/json" \
  -d '{
    "name": "oram-contacts",
    "description": "Privacy-preserving contact discovery with ORAM",
    "tags": ["privacy", "oram", "contacts"]
  }'

# Publish version
COMPOSE_B64=$(base64 -w 0 docker-compose.yml)
curl -X POST https://app.easyenclave.com/api/v1/apps/oram-contacts/versions \
  -H "Content-Type: application/json" \
  -d "{
    \"version\": \"v1.0.0\",
    \"compose\": \"$COMPOSE_B64\"
  }"
```

### 3. Deploy to TDX Worker

```bash
# Wait for measuring enclave to attest image
# Then deploy
curl -X POST https://app.easyenclave.com/api/v1/apps/oram-contacts/versions/v1.0.0/deploy \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "<agent-id>",
    "config": {
      "service_name": "oram-contacts"
    }
  }'
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ORAM_DB_PATH` | `/data/contacts.db` | SQLite database path |
| `ORAM_BUCKETS` | `1024` | Number of cuckoo hash buckets |
| `ORAM_STASH_SIZE` | `100` | Maximum stash capacity |

**Performance tuning:**
- Increase `ORAM_BUCKETS` for more contacts (reduces collisions)
- Increase `ORAM_STASH_SIZE` if getting overflow errors
- Trade-off: Larger buckets = better performance, more storage

## Performance

**Overhead:**
- Traditional indexed lookup: ~0.1ms (1 page read)
- ORAM lookup: ~2-5ms (10 page reads + 8 writes)
- **20-50x slower**, but acceptable for contact discovery

**Expected performance:**
- 100-200 queries/sec
- 10,000+ contacts supported
- <10ms per query (batch)

**Optimizations:**
- Batch queries (amortizes overhead)
- In-memory position map (reduces DB reads)
- Larger buckets (fewer evictions)

## Security Properties

### What ORAM Protects

**Even if attacker:**
- ✅ Has physical access to server
- ✅ Breaks TDX and extracts keys
- ✅ Dumps entire SQLite database
- ✅ Reads all memory
- ✅ Monitors page faults

**They cannot:**
- ❌ Tell which contacts you looked up
- ❌ Distinguish real queries from dummy accesses
- ❌ Correlate bucket accesses to phone numbers
- ❌ Reconstruct query history
- ❌ Determine access frequency

### Access Pattern Example

```
Without ORAM:
  Query Alice   → Read row 42
  Query Bob     → Read row 51
  Query Charlie → Read row 63
  ❌ Patterns reveal what you queried

With ORAM:
  Query Alice   → Read buckets [7, 12, stash], Write buckets [7, 12, 3, 18]
  Query Bob     → Read buckets [2, 15, stash], Write buckets [2, 15, 8, 19]
  Query Charlie → Read buckets [1, 13, stash], Write buckets [1, 13, 7, 20]
  ✅ All queries touch ~same number of buckets (8-10)
  ✅ No correlation between query and buckets
```

### Encryption at Rest

All blocks stored in SQLite are encrypted with AES-GCM:

```sql
-- Raw database view (attacker perspective)
SELECT * FROM oram_buckets LIMIT 1;
-- Returns: (0, 0, 0x7a3f9e...) -- gibberish ciphertext
```

Even with database dump, attacker only sees:
- Encrypted blocks (AES-GCM ciphertext)
- No plaintext phone numbers or user IDs
- No access pattern information

## Example Usage

See `examples/oram-contacts/` for:
- `client.py` - Simple SDK usage
- `benchmark.py` - Performance testing
- Full end-to-end examples

## References

- **Path ORAM:** [Stefanov et al., 2013](https://eprint.iacr.org/2013/280)
- **Cuckoo Hashing:** [Pagh and Rodler, 2004](https://en.wikipedia.org/wiki/Cuckoo_hashing)
- **TEE Attacks:** [tee.fail](https://tee.fail)
- **EasyEnclave:** [github.com/easyenclave/easyenclave](https://github.com/easyenclave/easyenclave)

## License

Same as EasyEnclave parent project.
