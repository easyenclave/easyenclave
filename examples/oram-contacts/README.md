# ORAM Contact Discovery - Examples

This directory contains example scripts for using the ORAM contact discovery service.

## Prerequisites

1. **Deploy the service** (see `apps/oram-contacts/README.md`)
2. **Install EasyEnclave SDK:**
   ```bash
   cd sdk/python
   pip install -e .
   ```

## Quick Start

### Local Testing

Run the service locally with Docker:

```bash
cd apps/oram-contacts
docker-compose up
```

Then run the example:

```bash
cd examples/oram-contacts
python3 client.py
```

### Production Usage

Update the client URL in scripts:

```python
# Change from:
client = EasyEnclaveClient("https://app.easyenclave.com")

# To your deployment:
client = EasyEnclaveClient("https://your-deployment.com")
```

## Examples

### `client.py` - Basic Usage

Demonstrates:
- Registering contacts
- Looking up contacts by phone hash
- Oblivious query patterns
- Security guarantees

**Run:**
```bash
python3 client.py
```

**Expected output:**
```
==============================================================
ORAM Contact Discovery Example
==============================================================

1. Connecting to ORAM service...
   ✓ Service status: healthy
   ✓ ORAM stats: {'total_capacity': 4096, 'num_contacts': 0, ...}

2. Registering users...
   ✓ Registered alice (+1-555-0100)
   ✓ Registered bob (+1-555-0101)
   ...

3. Looking up contacts (oblivious)...
   Lookup results:
   ✅ +1-555-0100 → alice
   ❌ +1-555-0199 not registered
   ✅ +1-555-0102 → charlie
   ...

🔒 Security Guarantees:
==============================================================
✅ Server never learned which numbers you checked
   All queries looked identical (ORAM access pattern hiding)
...
```

### `benchmark.py` - Performance Testing

Measures:
- Registration throughput (contacts/sec)
- Lookup latency (ms per query)
- ORAM overhead vs traditional DB
- Batch query optimization

**Run:**
```bash
python3 benchmark.py
```

**Expected output:**
```
======================================================================
ORAM Contact Discovery - Performance Benchmark
======================================================================

📝 Registering 1000 contacts...
   Progress: 100/1000 (42.3 contacts/sec)
   Progress: 200/1000 (45.1 contacts/sec)
   ...
   ✓ Registration complete:
     Total time: 23.45s
     Rate: 42.6 contacts/sec
     Per contact: 23.5ms

🔍 Looking up 500 contacts (batch size: 10)...
   ✓ Lookup complete:
     Total time: 4.56s
     Rate: 109.6 queries/sec
     Per query: 9.1ms
     Per batch: 91.2ms

📊 ORAM Overhead:
  Traditional DB lookup: ~0.1ms (1 page read)
  ORAM lookup: 9.1ms (oblivious access)
  Overhead factor: ~91x

  ✅ Acceptable for contact discovery use case
  ✅ Privacy protection worth the performance cost
```

## Modifying for Your Use Case

### 1. Different Data Types

The ORAM store can be adapted for any key-value lookups:

```python
# Instead of phone numbers:
# - Email addresses
# - User IDs
# - IP addresses
# - Any identifier that needs privacy

# Change registration:
response = service.post("/register", json={
    "phone_number": "email@example.com",  # Your key
    "user_id": "metadata"                  # Your value
})
```

### 2. Client-Side Hashing

For better privacy, hash on client side:

```python
import hashlib

# Hash locally (server never sees plaintext)
phone_hash = hashlib.sha256(phone.encode()).hexdigest()

# Send only hash
response = service.post("/lookup", json={
    "phone_hashes": [phone_hash]
})
```

### 3. Batch Optimization

Query multiple contacts at once:

```python
# Less efficient:
for phone in contacts:
    lookup_one(phone)  # N round trips

# More efficient:
lookup_batch(contacts)  # 1 round trip
```

### 4. Error Handling

```python
try:
    response = service.post("/lookup", json={...})
    response.raise_for_status()
    results = response.json()
except requests.HTTPError as e:
    if e.response.status_code == 507:
        print("ORAM capacity exceeded")
    elif e.response.status_code == 503:
        print("Service unavailable")
    else:
        print(f"HTTP error: {e}")
```

## Performance Tuning

### ORAM Configuration

Adjust in `docker-compose.yml`:

```yaml
environment:
  - ORAM_BUCKETS=2048      # More buckets = higher capacity
  - ORAM_STASH_SIZE=200    # Larger stash = fewer failures
```

**Trade-offs:**
- More buckets → Higher capacity, slower initialization
- Larger stash → Fewer overflows, more memory usage

### Expected Performance

| Dataset Size | Registration Rate | Lookup Rate | Latency |
|--------------|-------------------|-------------|---------|
| 1,000 contacts | ~50/sec | ~100/sec | ~10ms |
| 10,000 contacts | ~40/sec | ~80/sec | ~12ms |
| 100,000 contacts | ~30/sec | ~60/sec | ~15ms |

*Note: Actual performance depends on hardware and ORAM configuration.*

## Security Testing

### Verify Oblivious Access

```python
# All queries should take ~same time
times = []
for phone in test_contacts:
    start = time.time()
    lookup([phone])
    times.append(time.time() - start)

# Standard deviation should be low
std_dev = statistics.stdev(times)
print(f"Timing variation: {std_dev:.2f}ms")
# Should be <1ms (oblivious timing)
```

### Verify Encryption at Rest

```bash
# Dump database
sqlite3 /data/contacts.db "SELECT * FROM oram_buckets LIMIT 5;"

# Should see only encrypted blobs (hex gibberish)
# If you see plaintext, encryption is broken!
```

## Troubleshooting

### Service Unavailable (503)

```bash
# Check if service is running
docker ps | grep oram-contacts

# Check logs
docker logs oram-contacts
```

### ORAM Capacity Exceeded (507)

```bash
# Increase buckets or clear database
docker exec oram-contacts rm /data/contacts.db
docker restart oram-contacts
```

### Slow Performance

- Increase `ORAM_BUCKETS` (reduces collisions)
- Use batch queries (amortizes overhead)
- Check stash size (if > 50, need more buckets)

## Next Steps

1. **Integrate with your app** - Use SDK to call ORAM service
2. **Deploy to TDX** - Get full attestation guarantees
3. **Customize data model** - Adapt for your privacy use case
4. **Monitor performance** - Track latency and capacity

## References

- [App Documentation](../../apps/oram-contacts/README.md)
- [ORAM Paper](https://eprint.iacr.org/2013/280) (Path ORAM)
- [EasyEnclave Docs](https://docs.easyenclave.com)
