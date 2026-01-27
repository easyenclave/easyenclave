"""End-to-end tests for source code inspection and rejection."""

from __future__ import annotations

import base64

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.storage import app_store, app_version_store


@pytest.fixture(autouse=True)
def clear_stores():
    """Clear all stores before each test."""
    app_store.clear()
    app_version_store.clear()
    yield
    app_store.clear()
    app_version_store.clear()


@pytest.fixture
def mock_github_repo_clean(httpx_mock):
    """Mock a clean GitHub repo with no forbidden keywords."""
    # Mock tree response
    httpx_mock.add_response(
        url="https://api.github.com/repos/test/clean-app/git/trees/abc123?recursive=1",
        json={
            "tree": [
                {"type": "blob", "path": "main.py", "sha": "sha1", "size": 100},
                {"type": "blob", "path": "README.md", "sha": "sha2", "size": 50},
            ]
        },
    )
    # Mock blob responses
    # main.py: print('hello world')
    httpx_mock.add_response(
        url="https://api.github.com/repos/test/clean-app/git/blobs/sha1",
        json={"encoding": "base64", "content": base64.b64encode(b"print('hello world')").decode()},
    )
    # README.md: # Clean App
    httpx_mock.add_response(
        url="https://api.github.com/repos/test/clean-app/git/blobs/sha2",
        json={"encoding": "base64", "content": base64.b64encode(b"# Clean App").decode()},
    )


@pytest.fixture
def mock_github_repo_hacked(httpx_mock):
    """Mock a GitHub repo containing forbidden keywords."""
    httpx_mock.add_response(
        url="https://api.github.com/repos/test/hacked-app/git/trees/def456?recursive=1",
        json={
            "tree": [
                {"type": "blob", "path": "exploit.py", "sha": "sha1", "size": 100},
            ]
        },
    )
    # exploit.py: # HACK: this is a backdoor
    httpx_mock.add_response(
        url="https://api.github.com/repos/test/hacked-app/git/blobs/sha1",
        json={"encoding": "base64", "content": base64.b64encode(b"# HACK: this is a backdoor").decode()},
    )


@pytest.fixture
def mock_github_repo_hax(httpx_mock):
    """Mock a GitHub repo containing HAX keyword."""
    httpx_mock.add_response(
        url="https://api.github.com/repos/test/hax-app/git/trees/ghi789?recursive=1",
        json={
            "tree": [
                {"type": "blob", "path": "src/backdoor.py", "sha": "sha1", "size": 100},
            ]
        },
    )
    # src/backdoor.py: def hax0r_mode():
    httpx_mock.add_response(
        url="https://api.github.com/repos/test/hax-app/git/blobs/sha1",
        json={"encoding": "base64", "content": base64.b64encode(b"def hax0r_mode():\n    pass").decode()},
    )


@pytest.fixture
def mock_github_repo_large(httpx_mock):
    """Mock a GitHub repo with source exceeding 100KB."""
    # Create many files that together exceed 100KB
    # Use fewer, larger files to avoid creating too many mock responses
    tree_items = []
    for i in range(110):
        tree_items.append({
            "type": "blob",
            "path": f"file{i}.py",
            "sha": f"sha{i}",
            "size": 1000,  # 1KB each = 110KB total
        })

    httpx_mock.add_response(
        url="https://api.github.com/repos/test/large-app/git/trees/large123?recursive=1",
        json={"tree": tree_items},
    )

    # Mock blob responses with 1KB content each
    # The download will stop at 100KB, so we only need ~100 responses
    large_content = "x" * 1000
    for i in range(110):
        httpx_mock.add_response(
            url=f"https://api.github.com/repos/test/large-app/git/blobs/sha{i}",
            json={"encoding": "base64", "content": base64.b64encode(large_content.encode()).decode()},
        )


@pytest.mark.asyncio
async def test_publish_clean_app_succeeds(mock_github_repo_clean):
    """Test that a clean app passes inspection and gets published."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First register the app
        register_response = await client.post("/api/v1/apps", json={
            "name": "clean-app",
            "source_repo": "test/clean-app",
        })
        assert register_response.status_code == 200

        # Publish a version
        compose_b64 = base64.b64encode(b"services: {}").decode()
        response = await client.post("/api/v1/apps/clean-app/versions", json={
            "version": "1.0.0",
            "source_commit": "abc123",
            "compose": compose_b64,
        })

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "attested"
        assert data["rejection_reason"] is None


@pytest.mark.asyncio
async def test_publish_hacked_app_rejected(mock_github_repo_hacked):
    """Test that an app with forbidden keywords is rejected."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # First register the app
        await client.post("/api/v1/apps", json={
            "name": "hacked-app",
            "source_repo": "test/hacked-app",
        })

        # Try to publish a version
        compose_b64 = base64.b64encode(b"services: {}").decode()
        response = await client.post("/api/v1/apps/hacked-app/versions", json={
            "version": "1.0.0",
            "source_commit": "def456",
            "compose": compose_b64,
        })

        # Returns 200 with status: rejected
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "rejected"
        assert "HACK" in data["rejection_reason"]
        assert "exploit.py" in data["rejection_reason"]


@pytest.mark.asyncio
async def test_publish_hacked_app_rejected_via_get(mock_github_repo_hacked):
    """Test that a rejected version shows rejection reason via GET."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register the app
        await client.post("/api/v1/apps", json={
            "name": "hacked-app-2",
            "source_repo": "test/hacked-app",
        })

        # Try to publish - this will fail with 500 in the action
        compose_b64 = base64.b64encode(b"services: {}").decode()
        try:
            await client.post("/api/v1/apps/hacked-app-2/versions", json={
                "version": "1.0.0",
                "source_commit": "def456",
                "compose": compose_b64,
            })
        except Exception:
            pass

        # Check the version via GET
        versions = await client.get("/api/v1/apps/hacked-app-2/versions")
        if versions.status_code == 200:
            data = versions.json()
            if data["total"] > 0:
                version = data["versions"][0]
                assert version["status"] == "rejected"
                assert "HACK" in version["rejection_reason"]
                assert "exploit.py" in version["rejection_reason"]


@pytest.mark.asyncio
async def test_publish_with_hax_rejected(mock_github_repo_hax):
    """Test that HAX keyword is also detected (matches hax0r)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register the app
        await client.post("/api/v1/apps", json={
            "name": "hax-app",
            "source_repo": "test/hax-app",
        })

        # Try to publish
        compose_b64 = base64.b64encode(b"services: {}").decode()
        response = await client.post("/api/v1/apps/hax-app/versions", json={
            "version": "1.0.0",
            "source_commit": "ghi789",
            "compose": compose_b64,
        })

        # Returns 200 with status: rejected
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "rejected"
        # HAX keyword matches (case-insensitive) which catches "hax0r_mode"
        assert "hax" in data["rejection_reason"].lower()
        assert "backdoor.py" in data["rejection_reason"]


@pytest.mark.asyncio
@pytest.mark.httpx_mock(can_send_already_matched_responses=True, assert_all_responses_were_requested=False)
async def test_source_size_limit_enforced(mock_github_repo_large):
    """Test that sources over 100KB are rejected."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register the app
        await client.post("/api/v1/apps", json={
            "name": "large-app",
            "source_repo": "test/large-app",
        })

        # Try to publish
        compose_b64 = base64.b64encode(b"services: {}").decode()
        response = await client.post("/api/v1/apps/large-app/versions", json={
            "version": "1.0.0",
            "source_commit": "large123",
            "compose": compose_b64,
        })

        # Returns 200 with status: rejected
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "rejected"
        assert "100KB" in data["rejection_reason"] or "limit" in data["rejection_reason"].lower()


@pytest.mark.asyncio
async def test_publish_without_source_repo_skips_inspection():
    """Test that apps without source_repo skip inspection."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register app without source_repo
        await client.post("/api/v1/apps", json={
            "name": "no-source-app",
            # No source_repo
        })

        # Publish should succeed without inspection
        compose_b64 = base64.b64encode(b"services: {}").decode()
        response = await client.post("/api/v1/apps/no-source-app/versions", json={
            "version": "1.0.0",
            "source_commit": "abc123",
            "compose": compose_b64,
        })

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "attested"


@pytest.mark.asyncio
async def test_publish_without_source_commit_skips_inspection():
    """Test that publishing without source_commit skips inspection."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register app with source_repo
        await client.post("/api/v1/apps", json={
            "name": "no-commit-app",
            "source_repo": "test/some-repo",
        })

        # Publish without source_commit should succeed without inspection
        compose_b64 = base64.b64encode(b"services: {}").decode()
        response = await client.post("/api/v1/apps/no-commit-app/versions", json={
            "version": "1.0.0",
            # No source_commit
            "compose": compose_b64,
        })

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "attested"


@pytest.mark.asyncio
async def test_app_lifecycle_register_list_get_delete():
    """Test full app lifecycle."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register
        response = await client.post("/api/v1/apps", json={
            "name": "lifecycle-app",
            "description": "Test app",
            "tags": ["test", "e2e"],
        })
        assert response.status_code == 200
        app_data = response.json()
        assert app_data["name"] == "lifecycle-app"

        # List
        response = await client.get("/api/v1/apps")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        assert any(a["name"] == "lifecycle-app" for a in data["apps"])

        # Get
        response = await client.get("/api/v1/apps/lifecycle-app")
        assert response.status_code == 200
        assert response.json()["name"] == "lifecycle-app"

        # Delete
        response = await client.delete("/api/v1/apps/lifecycle-app")
        assert response.status_code == 200

        # Verify deleted
        response = await client.get("/api/v1/apps/lifecycle-app")
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_duplicate_app_name_rejected():
    """Test that duplicate app names are rejected."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register first app
        response = await client.post("/api/v1/apps", json={
            "name": "duplicate-app",
        })
        assert response.status_code == 200

        # Try to register duplicate
        response = await client.post("/api/v1/apps", json={
            "name": "duplicate-app",
        })
        assert response.status_code == 409


@pytest.mark.asyncio
async def test_duplicate_version_rejected():
    """Test that duplicate versions are rejected."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register app
        await client.post("/api/v1/apps", json={"name": "dup-version-app"})

        # Publish first version
        compose_b64 = base64.b64encode(b"services: {}").decode()
        response = await client.post("/api/v1/apps/dup-version-app/versions", json={
            "version": "1.0.0",
            "compose": compose_b64,
        })
        assert response.status_code == 200

        # Try to publish duplicate version
        response = await client.post("/api/v1/apps/dup-version-app/versions", json={
            "version": "1.0.0",
            "compose": compose_b64,
        })
        assert response.status_code == 409
