# ORAM Contacts - Deployment Guide

Step-by-step guide to deploy the ORAM contact discovery service on EasyEnclave.

## Prerequisites

1. **EasyEnclave account** - Sign up at https://app.easyenclave.com
2. **Docker** - For building container images
3. **GitHub Container Registry access** - Or any Docker registry
4. **TDX worker** - Registered with EasyEnclave

## Step 1: Build and Push Docker Image

```bash
cd apps/oram-contacts

# Build image
docker build -t ghcr.io/YOUR_USERNAME/oram-contacts:v1.0.0 .

# Login to GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# Push image
docker push ghcr.io/YOUR_USERNAME/oram-contacts:v1.0.0
```

**Alternative registries:**
- Docker Hub: `docker.io/YOUR_USERNAME/oram-contacts:v1.0.0`
- AWS ECR: `123456789.dkr.ecr.us-east-1.amazonaws.com/oram-contacts:v1.0.0`

## Step 2: Register App with EasyEnclave

### Using API

```bash
# Get admin token (from EasyEnclave UI or password login)
ADMIN_TOKEN="your-admin-token"
CP_URL="https://app.easyenclave.com"

# Register app
curl -X POST "$CP_URL/api/v1/apps" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "oram-contacts",
    "description": "Privacy-preserving contact discovery with ORAM",
    "tags": ["privacy", "oram", "contacts", "example"]
  }'
```

### Using Admin UI

1. Go to https://app.easyenclave.com/admin
2. Navigate to **Apps** tab
3. Click **Create App**
4. Fill in:
   - Name: `oram-contacts`
   - Description: `Privacy-preserving contact discovery with ORAM`
   - Tags: `privacy, oram, contacts`

## Step 3: Publish App Version

```bash
# Base64 encode docker-compose.yml
COMPOSE_B64=$(base64 -w 0 docker-compose.yml)

# Publish version
curl -X POST "$CP_URL/api/v1/apps/oram-contacts/versions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"version\": \"v1.0.0\",
    \"compose\": \"$COMPOSE_B64\"
  }"
```

**Response:**
```json
{
  "name": "oram-contacts",
  "version": "v1.0.0",
  "status": "pending",
  "published_at": "2024-01-01T00:00:00Z"
}
```

## Step 4: Wait for Attestation

The measuring enclave will:
1. Resolve Docker image digests
2. Compute MRTD (measurement)
3. Call back to attest the version

**Monitor status:**
```bash
# Poll for attestation
while true; do
  STATUS=$(curl -s "$CP_URL/api/v1/apps/oram-contacts/versions/v1.0.0" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.status')
  echo "Status: $STATUS"

  if [ "$STATUS" = "attested" ]; then
    echo "✓ Version attested!"
    break
  elif [ "$STATUS" = "failed" ]; then
    echo "✗ Attestation failed!"
    exit 1
  fi

  sleep 10
done
```

**Typical attestation time:** 30-60 seconds

## Step 5: Deploy to TDX Worker

### Get Agent ID

```bash
# List agents
curl -s "$CP_URL/api/v1/agents" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.[] | {id, hostname, status}'
```

### Deploy

```bash
# Deploy to agent
AGENT_ID="your-agent-id"

curl -X POST "$CP_URL/api/v1/apps/oram-contacts/versions/v1.0.0/deploy" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"config\": {
      \"service_name\": \"oram-contacts\"
    }
  }"
```

**Response:**
```json
{
  "deployment_id": "dep_abc123",
  "app_name": "oram-contacts",
  "version": "v1.0.0",
  "agent_id": "agent_xyz789",
  "status": "deploying",
  "created_at": "2024-01-01T00:00:00Z"
}
```

### Monitor Deployment

```bash
# Check deployment status
DEPLOYMENT_ID="dep_abc123"

curl -s "$CP_URL/api/v1/deployments/$DEPLOYMENT_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.status'
```

**Typical deployment time:** 1-3 minutes (includes image pull)

## Step 6: Verify Deployment

### Health Check

```bash
# Get service URL
SERVICE_URL=$(curl -s "$CP_URL/api/v1/deployments/$DEPLOYMENT_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.service_url')

echo "Service URL: $SERVICE_URL"

# Health check
curl -s "$SERVICE_URL/health" | jq '.'
```

**Expected output:**
```json
{
  "status": "healthy",
  "oram_stats": {
    "total_capacity": 4096,
    "num_contacts": 0,
    "stash_size": 0,
    "occupancy": 0.0
  }
}
```

### Test Registration

```bash
# Register a test contact
curl -X POST "$SERVICE_URL/register" \
  -H "Content-Type: application/json" \
  -d '{
    "phone_number": "+1-555-TEST",
    "user_id": "test-user"
  }'
```

### Verify Attestation

The EasyEnclave SDK automatically verifies TDX attestation. You can manually check:

```bash
# Get deployment MRTD
MRTD=$(curl -s "$CP_URL/api/v1/deployments/$DEPLOYMENT_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.mrtd')

echo "Deployment MRTD: $MRTD"

# Compare with app version MRTD
VERSION_MRTD=$(curl -s "$CP_URL/api/v1/apps/oram-contacts/versions/v1.0.0" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.mrtd')

echo "Version MRTD: $VERSION_MRTD"

# Should match!
if [ "$MRTD" = "$VERSION_MRTD" ]; then
  echo "✓ Attestation verified!"
else
  echo "✗ Attestation mismatch!"
  exit 1
fi
```

## Configuration

### Environment Variables

Adjust in `docker-compose.yml` before publishing:

```yaml
environment:
  - ORAM_DB_PATH=/data/contacts.db      # Database path
  - ORAM_BUCKETS=1024                   # Number of buckets
  - ORAM_STASH_SIZE=100                 # Stash capacity
```

**Performance tuning:**

| Contacts | ORAM_BUCKETS | ORAM_STASH_SIZE | Memory Usage |
|----------|--------------|-----------------|--------------|
| <1,000   | 512          | 50              | ~32 MB       |
| 1,000-10,000 | 1024     | 100             | ~64 MB       |
| 10,000-50,000 | 2048    | 200             | ~128 MB      |
| 50,000+ | 4096          | 400             | ~256 MB      |

### Persistent Storage

Data is stored in Docker volume `oram-data`. To clear:

```bash
# Stop deployment
curl -X DELETE "$CP_URL/api/v1/deployments/$DEPLOYMENT_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# SSH to agent and remove volume
docker volume rm oram-contacts_oram-data

# Redeploy
curl -X POST "$CP_URL/api/v1/apps/oram-contacts/versions/v1.0.0/deploy" ...
```

## Troubleshooting

### Image Pull Failed

**Error:** `Failed to pull image: unauthorized`

**Fix:** Ensure image is public or agent has registry credentials:

```bash
# Make GitHub Container Registry image public:
# 1. Go to https://github.com/YOUR_USERNAME?tab=packages
# 2. Click on oram-contacts package
# 3. Package settings → Change visibility → Public
```

### Stash Overflow

**Error:** `507 Storage capacity exceeded`

**Fix:** Increase `ORAM_STASH_SIZE` or `ORAM_BUCKETS`:

1. Update `docker-compose.yml`
2. Publish new version
3. Redeploy

### Slow Performance

**Issue:** Queries taking >20ms

**Fixes:**
- Increase `ORAM_BUCKETS` (reduces collisions)
- Use batch queries (amortize overhead)
- Check stash size (if >50, need more buckets)

### Service Not Starting

**Check logs:**

```bash
# Via EasyEnclave API
curl -s "$CP_URL/api/v1/deployments/$DEPLOYMENT_ID/logs" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Or SSH to agent
ssh agent-hostname
docker logs oram-contacts
```

## Updating the App

### Publish New Version

```bash
# Build new image
docker build -t ghcr.io/YOUR_USERNAME/oram-contacts:v1.1.0 .
docker push ghcr.io/YOUR_USERNAME/oram-contacts:v1.1.0

# Update docker-compose.yml with new tag
sed -i 's/:v1.0.0/:v1.1.0/g' docker-compose.yml

# Publish new version
COMPOSE_B64=$(base64 -w 0 docker-compose.yml)
curl -X POST "$CP_URL/api/v1/apps/oram-contacts/versions" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"version\": \"v1.1.0\",
    \"compose\": \"$COMPOSE_B64\"
  }"
```

### Rolling Update

```bash
# Deploy new version (creates new deployment)
curl -X POST "$CP_URL/api/v1/apps/oram-contacts/versions/v1.1.0/deploy" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"config\": {
      \"service_name\": \"oram-contacts\"
    }
  }"

# Stop old deployment
curl -X DELETE "$CP_URL/api/v1/deployments/$OLD_DEPLOYMENT_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Security Considerations

### 1. Attestation Verification

Always verify MRTD before trusting deployment:

```python
from easyenclave import EasyEnclaveClient

client = EasyEnclaveClient("https://app.easyenclave.com")
service = client.service("oram-contacts")

# SDK automatically verifies TDX attestation
# If attestation fails, connection is refused
```

### 2. Data Encryption

All blocks are encrypted with AES-GCM. Verify:

```bash
# SSH to agent
docker exec oram-contacts sqlite3 /data/contacts.db "SELECT * FROM oram_buckets LIMIT 1;"

# Should see hex blob (encrypted), not plaintext
```

### 3. Access Control

Restrict API access:

```yaml
# Add authentication middleware
environment:
  - API_KEY=your-secret-key

# In app.py:
# @app.middleware("http")
# async def verify_api_key(request, call_next):
#     ...
```

### 4. Rate Limiting

Prevent abuse:

```yaml
environment:
  - RATE_LIMIT=100  # queries per minute
```

## Monitoring

### Metrics to Track

- **Stash size** - Should stay <50% of capacity
- **Occupancy** - Should stay <80% for good performance
- **Query latency** - Should be <20ms
- **Error rate** - Should be <1%

### Example Monitoring Script

```bash
#!/bin/bash
# monitor.sh - Check ORAM service health

while true; do
  STATS=$(curl -s "$SERVICE_URL/stats")

  STASH=$(echo $STATS | jq -r '.stash_size')
  OCCUPANCY=$(echo $STATS | jq -r '.occupancy')

  echo "$(date): Stash=$STASH, Occupancy=$(echo "$OCCUPANCY * 100" | bc)%"

  if (( $(echo "$OCCUPANCY > 0.8" | bc -l) )); then
    echo "⚠ Warning: High occupancy!"
  fi

  sleep 60
done
```

## Next Steps

1. **Integrate with your app** - Use EasyEnclave SDK
2. **Customize for your use case** - Modify data model
3. **Set up monitoring** - Track metrics
4. **Scale horizontally** - Deploy multiple instances
5. **Add authentication** - Protect API endpoints

## Support

- **Documentation:** `apps/oram-contacts/README.md`
- **Examples:** `examples/oram-contacts/`
- **Issues:** https://github.com/easyenclave/easyenclave/issues
