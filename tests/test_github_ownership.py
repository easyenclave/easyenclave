"""Tests for GitHub ownership feature — owner-scoped agent access."""

import os

import pytest

from app.auth import (
    get_owner_identities,
    is_admin_session,
    require_owner_or_admin,
)
from app.db_models import AdminSession, Agent
from app.storage import admin_session_store, agent_store

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agent(vm_name: str, github_owner: str | None = None) -> Agent:
    """Create and register a minimal agent."""
    agent = Agent(
        vm_name=vm_name,
        attestation={"test": True},
        mrtd="test-mrtd",
        verified=True,
        github_owner=github_owner,
    )
    agent_store.register(agent)
    return agent


def _make_session(
    auth_method: str = "password",
    github_login: str | None = None,
    github_orgs: list[str] | None = None,
) -> AdminSession:
    """Create a session in the store and return it."""
    from app.auth import (
        create_session_expiry,
        generate_session_token,
        get_token_prefix,
        hash_api_key,
    )

    token = generate_session_token()
    session = AdminSession(
        token_hash=hash_api_key(token),
        token_prefix=get_token_prefix(token),
        expires_at=create_session_expiry(hours=24),
        auth_method=auth_method,
        github_login=github_login,
        github_orgs=github_orgs,
    )
    admin_session_store.create(session)
    return session, token


@pytest.fixture(autouse=True)
def reset_admin_logins():
    """Clear and restore ADMIN_GITHUB_LOGINS env var around each test."""
    orig = os.environ.get("ADMIN_GITHUB_LOGINS")
    os.environ.pop("ADMIN_GITHUB_LOGINS", None)
    yield
    if orig is None:
        os.environ.pop("ADMIN_GITHUB_LOGINS", None)
    else:
        os.environ["ADMIN_GITHUB_LOGINS"] = orig


# ---------------------------------------------------------------------------
# Unit tests for auth helpers
# ---------------------------------------------------------------------------


class TestIsAdminSession:
    def test_password_auth_is_admin(self):
        session, _ = _make_session(auth_method="password")
        assert is_admin_session(session) is True

    def test_github_in_admin_list(self):
        os.environ["ADMIN_GITHUB_LOGINS"] = "alice,bob"
        session, _ = _make_session(auth_method="github_oauth", github_login="alice")
        assert is_admin_session(session) is True

    def test_github_not_in_admin_list(self):
        os.environ["ADMIN_GITHUB_LOGINS"] = "alice,bob"
        session, _ = _make_session(auth_method="github_oauth", github_login="charlie")
        assert is_admin_session(session) is False

    def test_github_no_admin_list(self):
        session, _ = _make_session(auth_method="github_oauth", github_login="alice")
        assert is_admin_session(session) is False


class TestGetOwnerIdentities:
    def test_login_only(self):
        session, _ = _make_session(auth_method="github_oauth", github_login="alice")
        ids = get_owner_identities(session)
        assert ids == ["alice"]

    def test_login_and_orgs(self):
        session, _ = _make_session(
            auth_method="github_oauth",
            github_login="alice",
            github_orgs=["myorg", "otherorg"],
        )
        ids = get_owner_identities(session)
        assert ids == ["alice", "myorg", "otherorg"]

    def test_password_session(self):
        session, _ = _make_session(auth_method="password")
        ids = get_owner_identities(session)
        assert ids == []


class TestRequireOwnerOrAdmin:
    def test_admin_always_passes(self):
        session, _ = _make_session(auth_method="password")
        agent = _make_agent("vm-1", github_owner="someone-else")
        # Should not raise
        require_owner_or_admin(session, agent)

    def test_owner_matches_login(self):
        os.environ["ADMIN_GITHUB_LOGINS"] = ""
        session, _ = _make_session(auth_method="github_oauth", github_login="alice")
        agent = _make_agent("vm-2", github_owner="alice")
        require_owner_or_admin(session, agent)

    def test_owner_matches_org(self):
        os.environ["ADMIN_GITHUB_LOGINS"] = ""
        session, _ = _make_session(
            auth_method="github_oauth",
            github_login="alice",
            github_orgs=["myorg"],
        )
        agent = _make_agent("vm-3", github_owner="myorg")
        require_owner_or_admin(session, agent)

    def test_non_owner_raises_403(self):
        os.environ["ADMIN_GITHUB_LOGINS"] = ""
        session, _ = _make_session(auth_method="github_oauth", github_login="alice")
        agent = _make_agent("vm-4", github_owner="bob")
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            require_owner_or_admin(session, agent)
        assert exc_info.value.status_code == 403

    def test_no_owner_raises_403(self):
        """Agent without github_owner is inaccessible to non-admin."""
        os.environ["ADMIN_GITHUB_LOGINS"] = ""
        session, _ = _make_session(auth_method="github_oauth", github_login="alice")
        agent = _make_agent("vm-5", github_owner=None)
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            require_owner_or_admin(session, agent)
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# Storage tests
# ---------------------------------------------------------------------------


class TestAgentStoreOwnership:
    def test_list_by_owners(self):
        _make_agent("vm-a", github_owner="alice")
        _make_agent("vm-b", github_owner="bob")
        _make_agent("vm-c", github_owner="myorg")
        _make_agent("vm-d", github_owner=None)

        result = agent_store.list_by_owners(["alice", "myorg"])
        names = {a.vm_name for a in result}
        assert names == {"vm-a", "vm-c"}

    def test_list_by_owners_empty(self):
        _make_agent("vm-e", github_owner="alice")
        assert agent_store.list_by_owners([]) == []

    def test_set_github_owner(self):
        agent = _make_agent("vm-f")
        assert agent.github_owner is None

        agent_store.set_github_owner(agent.agent_id, "newowner")
        updated = agent_store.get(agent.agent_id)
        assert updated.github_owner == "newowner"

    def test_set_github_owner_clear(self):
        agent = _make_agent("vm-g", github_owner="old")
        agent_store.set_github_owner(agent.agent_id, None)
        updated = agent_store.get(agent.agent_id)
        assert updated.github_owner is None


# ---------------------------------------------------------------------------
# API route tests
# ---------------------------------------------------------------------------


class TestOwnerRoutes:
    """Test /api/v1/me/* endpoints."""

    def test_my_agents_returns_owned(self, client):
        _make_agent("vm-owned", github_owner="alice")
        _make_agent("vm-other", github_owner="bob")
        _, token = _make_session(
            auth_method="github_oauth",
            github_login="alice",
            github_orgs=["myorg"],
        )

        resp = client.get(
            "/api/v1/me/agents",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["agents"][0]["vm_name"] == "vm-owned"

    def test_my_agents_matches_org(self, client):
        _make_agent("vm-org", github_owner="myorg")
        _, token = _make_session(
            auth_method="github_oauth",
            github_login="alice",
            github_orgs=["myorg"],
        )

        resp = client.get(
            "/api/v1/me/agents",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_my_agent_detail_403(self, client):
        agent = _make_agent("vm-notmine", github_owner="bob")
        os.environ["ADMIN_GITHUB_LOGINS"] = ""
        _, token = _make_session(
            auth_method="github_oauth",
            github_login="alice",
        )

        resp = client.get(
            f"/api/v1/me/agents/{agent.agent_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_my_agent_detail_success(self, client):
        agent = _make_agent("vm-mine", github_owner="alice")
        os.environ["ADMIN_GITHUB_LOGINS"] = ""
        _, token = _make_session(
            auth_method="github_oauth",
            github_login="alice",
        )

        resp = client.get(
            f"/api/v1/me/agents/{agent.agent_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["vm_name"] == "vm-mine"

    def test_my_agent_reset_success(self, client):
        agent = _make_agent("vm-reset", github_owner="alice")
        os.environ["ADMIN_GITHUB_LOGINS"] = ""
        _, token = _make_session(
            auth_method="github_oauth",
            github_login="alice",
        )

        resp = client.post(
            f"/api/v1/me/agents/{agent.agent_id}/reset",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_my_agent_reset_403(self, client):
        agent = _make_agent("vm-notmine2", github_owner="bob")
        os.environ["ADMIN_GITHUB_LOGINS"] = ""
        _, token = _make_session(
            auth_method="github_oauth",
            github_login="alice",
        )

        resp = client.post(
            f"/api/v1/me/agents/{agent.agent_id}/reset",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403


class TestPatchOwnerRoute:
    def test_admin_can_set_owner(self, client):
        agent = _make_agent("vm-patch", github_owner=None)
        _, token = _make_session(auth_method="password")

        resp = client.patch(
            f"/api/v1/agents/{agent.agent_id}/owner",
            json={"github_owner": "newuser"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["github_owner"] == "newuser"

        updated = agent_store.get(agent.agent_id)
        assert updated.github_owner == "newuser"

    def test_non_admin_403(self, client):
        agent = _make_agent("vm-patch2", github_owner=None)
        os.environ["ADMIN_GITHUB_LOGINS"] = ""
        _, token = _make_session(
            auth_method="github_oauth",
            github_login="charlie",
        )

        resp = client.patch(
            f"/api/v1/agents/{agent.agent_id}/owner",
            json={"github_owner": "charlie"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403


class TestAuthMeRoute:
    def test_includes_is_admin_and_orgs(self, client):
        os.environ["ADMIN_GITHUB_LOGINS"] = "alice"
        _, token = _make_session(
            auth_method="github_oauth",
            github_login="alice",
            github_orgs=["myorg", "other"],
        )

        resp = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_admin"] is True
        assert data["github_orgs"] == ["myorg", "other"]

    def test_password_is_admin(self, client):
        _, token = _make_session(auth_method="password")

        resp = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_admin"] is True
        assert data["github_orgs"] == []
