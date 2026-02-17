"""End-to-end tests for real agent registration and deploy readiness."""

from __future__ import annotations

from datetime import datetime, timezone

from app.db_models import App, AppVersion
from app.storage import (
    agent_store,
    app_store,
    app_version_store,
    capacity_launch_order_store,
    trusted_mrtd_store,
)


def _make_attestation(token: str, mrtd: str) -> dict:
    return {
        "tdx": {
            "intel_ta_token": token,
            "measurements": {
                "mrtd": mrtd,
                "rtmr0": "0" * 96,
                "rtmr1": "1" * 96,
                "rtmr2": "2" * 96,
                "rtmr3": "3" * 96,
            },
        }
    }


def _mock_verify_by_token(token_to_mrtd: dict[str, str]):
    async def _verify(token: str):
        mrtd = token_to_mrtd.get(token)
        if not mrtd:
            return {
                "verified": False,
                "verification_time": datetime.now(timezone.utc),
                "details": None,
                "error": "unknown token",
            }
        return {
            "verified": True,
            "verification_time": datetime.now(timezone.utc),
            "details": {
                "tdx_mrtd": mrtd,
                "attester_tcb_status": "UpToDate",
            },
            "error": None,
        }

    return _verify


def test_registration_requires_valid_node_size_and_datacenter(client, monkeypatch):
    mrtd = "a" * 96
    monkeypatch.setattr("app.attestation.verify_attestation_token", _mock_verify_by_token({}))

    # Missing node_size
    resp = client.post(
        "/api/v1/agents/register",
        json={
            "attestation": _make_attestation("token-a", mrtd),
            "vm_name": "vm-missing-size",
            "datacenter": "gcp:us-central1-a",
        },
    )
    assert resp.status_code == 400
    assert "node_size" in resp.json()["detail"].lower()

    # Missing datacenter
    resp = client.post(
        "/api/v1/agents/register",
        json={
            "attestation": _make_attestation("token-a", mrtd),
            "vm_name": "vm-missing-dc",
            "node_size": "tiny",
            "datacenter": "",
        },
    )
    assert resp.status_code == 400
    assert "datacenter" in resp.json()["detail"].lower()

    # Invalid datacenter format
    resp = client.post(
        "/api/v1/agents/register",
        json={
            "attestation": _make_attestation("token-a", mrtd),
            "vm_name": "vm-bad-dc",
            "node_size": "tiny",
            "datacenter": "bad dc label",
        },
    )
    assert resp.status_code == 400
    assert "invalid datacenter" in resp.json()["detail"].lower()


def test_registration_can_use_cp_mint_flow_with_bootstrap_token(client, monkeypatch):
    mrtd = "a" * 96
    trusted_mrtd_store.upsert(mrtd, mrtd_type="agent", note="bootstrap baseline")

    # Minting is mocked; verification is still done via verify_attestation_token().
    async def _mock_mint(*, quote_b64: str, timeout_seconds: int = 30) -> str:
        assert quote_b64 == "quote-b64"
        return "minted-token"

    monkeypatch.setattr("app.ita_mint.mint_intel_ta_token", _mock_mint)
    monkeypatch.setattr(
        "app.attestation.verify_attestation_token",
        _mock_verify_by_token({"minted-token": mrtd}),
    )

    # Create a launch order and claim it to mint a bootstrap token (as a launcher would).
    launcher = client.post(
        "/api/v1/accounts", json={"name": "launcher", "account_type": "launcher"}
    )
    assert launcher.status_code == 200
    launcher_key = launcher.json()["api_key"]
    order = capacity_launch_order_store.create_open(
        datacenter="gcp:us-central1-a",
        node_size="tiny",
        reason="test",
    )
    claim = client.post(
        "/api/v1/launchers/capacity/orders/claim",
        headers={"Authorization": f"Bearer {launcher_key}"},
        json={"datacenter": "gcp:us-central1-a", "node_size": "tiny"},
    )
    assert claim.status_code == 200
    bootstrap_token = claim.json()["bootstrap_token"]

    resp = client.post(
        "/api/v1/agents/register",
        json={
            "attestation": {"tdx": {"quote_b64": "quote-b64", "measurements": {"mrtd": mrtd}}},
            "vm_name": "vm-cp-mint",
            "node_size": "tiny",
            "datacenter": "gcp:us-central1-a",
            "bootstrap_order_id": order.order_id,
            "bootstrap_token": bootstrap_token,
        },
    )
    assert resp.status_code == 200


def test_reregistration_requires_attestation_reverification(client, monkeypatch):
    mrtd = "b" * 96
    trusted_mrtd_store.upsert(mrtd, mrtd_type="agent", note="test baseline")
    monkeypatch.setattr(
        "app.attestation.verify_attestation_token",
        _mock_verify_by_token({"token-good": mrtd}),
    )

    payload = {
        "attestation": _make_attestation("token-good", mrtd),
        "vm_name": "vm-reverify",
        "node_size": "tiny",
        "datacenter": "gcp:us-central1-a",
    }

    first = client.post("/api/v1/agents/register", json=payload)
    assert first.status_code == 200

    async def _always_fail_verify(_token: str):
        return {
            "verified": False,
            "verification_time": datetime.now(timezone.utc),
            "details": None,
            "error": "forced test failure",
        }

    monkeypatch.setattr("app.attestation.verify_attestation_token", _always_fail_verify)
    second = client.post("/api/v1/agents/register", json=payload)
    assert second.status_code == 403
    assert "intel ta verification failed" in second.json()["detail"].lower()


def test_registration_untrusted_then_trusted_reuses_agent_identity(client, monkeypatch):
    mrtd = "c" * 96
    monkeypatch.setattr(
        "app.attestation.verify_attestation_token",
        _mock_verify_by_token({"token-c": mrtd}),
    )

    payload = {
        "attestation": _make_attestation("token-c", mrtd),
        "vm_name": "vm-untrusted-then-trusted",
        "node_size": "tiny",
        "datacenter": "gcp:us-central1-a",
    }

    first = client.post("/api/v1/agents/register", json=payload)
    assert first.status_code == 403
    assert "mrtd not in trusted list" in first.json()["detail"].lower()

    untrusted_agent = agent_store.get_by_vm_name("vm-untrusted-then-trusted")
    assert untrusted_agent is not None
    assert untrusted_agent.verified is False
    assert untrusted_agent.status == "unverified"
    first_agent_id = untrusted_agent.agent_id

    trusted_mrtd_store.upsert(mrtd, mrtd_type="agent", note="new trusted baseline")
    second = client.post("/api/v1/agents/register", json=payload)
    assert second.status_code == 200
    assert second.json()["agent_id"] == first_agent_id

    trusted_agent = agent_store.get_by_vm_name("vm-untrusted-then-trusted")
    assert trusted_agent is not None
    assert trusted_agent.agent_id == first_agent_id
    assert trusted_agent.verified is True
    assert trusted_agent.status == "undeployed"


def test_deploy_preflight_transitions_from_unverified_to_eligible_after_trust(client, monkeypatch):
    mrtd = "d" * 96
    monkeypatch.setattr(
        "app.attestation.verify_attestation_token",
        _mock_verify_by_token({"token-d": mrtd}),
    )

    app_store.register(App(name="hello-tdx"))
    app_version_store.create(
        AppVersion(
            app_name="hello-tdx",
            version="1.0.0",
            node_size="tiny",
            compose="services:\n  app:\n    image: hello:latest\n",
            status="attested",
            mrtd=mrtd,
            attestation={
                "measurement_type": "agent_reference",
                "node_size": "tiny",
                "mrtd": mrtd,
                "rtmrs": {f"rtmr{i}": str(i) * 96 for i in range(4)},
            },
        )
    )

    payload = {
        "attestation": _make_attestation("token-d", mrtd),
        "vm_name": "vm-preflight",
        "node_size": "tiny",
        "datacenter": "gcp:us-central1-a",
    }

    # First registration is rejected -> unverified baseline is recorded.
    first = client.post("/api/v1/agents/register", json=payload)
    assert first.status_code == 403

    preflight_before = client.post(
        "/api/v1/apps/hello-tdx/versions/1.0.0/deploy/preflight",
        json={"node_size": "tiny", "allowed_datacenters": ["gcp:us-central1-a"]},
    )
    assert preflight_before.status_code == 200
    assert preflight_before.json()["eligible"] is False
    issue_codes = [issue["code"] for issue in preflight_before.json().get("issues", [])]
    assert "AGENT_NOT_VERIFIED" in issue_codes or "NO_ELIGIBLE_AGENTS" in issue_codes

    trusted_mrtd_store.upsert(mrtd, mrtd_type="agent", note="deploy-preflight baseline")
    second = client.post("/api/v1/agents/register", json=payload)
    assert second.status_code == 200
    agent_id = second.json()["agent_id"]

    # Registration alone does not mark tunnel health; set realistic deploy prerequisites.
    agent_store.update_tunnel_info(
        agent_id,
        tunnel_id="test-tunnel",
        hostname="agent-preflight.example.com",
        tunnel_token=None,
    )
    agent_store.update_health(agent_id, "healthy")

    preflight_after = client.post(
        "/api/v1/apps/hello-tdx/versions/1.0.0/deploy/preflight",
        json={
            "node_size": "tiny",
            "allowed_datacenters": ["gcp:us-central1-a"],
            "allowed_clouds": ["gcp"],
        },
    )
    assert preflight_after.status_code == 200
    data_after = preflight_after.json()
    assert data_after["eligible"] is True
    assert data_after["selected_agent_id"] == agent_id
    assert data_after["selected_datacenter"] == "gcp:us-central1-a"
    assert data_after["selected_cloud"] == "gcp"


def test_reregistration_rejects_identity_or_metadata_drift(client, monkeypatch):
    mrtd_a = "e" * 96
    mrtd_b = "f" * 96
    trusted_mrtd_store.upsert(mrtd_a, mrtd_type="agent", note="mrtd-a")
    trusted_mrtd_store.upsert(mrtd_b, mrtd_type="agent", note="mrtd-b")
    monkeypatch.setattr(
        "app.attestation.verify_attestation_token",
        _mock_verify_by_token(
            {
                "token-a": mrtd_a,
                "token-b": mrtd_b,
            }
        ),
    )

    base_payload = {
        "attestation": _make_attestation("token-a", mrtd_a),
        "vm_name": "vm-drift-check",
        "node_size": "tiny",
        "datacenter": "gcp:us-central1-a",
    }
    first = client.post("/api/v1/agents/register", json=base_payload)
    assert first.status_code == 200

    # MRTD drift for same vm_name must be rejected.
    mrtd_drift_payload = {
        **base_payload,
        "attestation": _make_attestation("token-b", mrtd_b),
    }
    mrtd_drift = client.post("/api/v1/agents/register", json=mrtd_drift_payload)
    assert mrtd_drift.status_code == 409
    assert "mrtd changed" in mrtd_drift.json()["detail"].lower()

    # Datacenter drift for same vm_name must be rejected.
    dc_drift_payload = {**base_payload, "datacenter": "gcp:us-central1-b"}
    dc_drift = client.post("/api/v1/agents/register", json=dc_drift_payload)
    assert dc_drift.status_code == 409
    assert "datacenter changed" in dc_drift.json()["detail"].lower()

    # Node size drift for same vm_name must be rejected.
    size_drift_payload = {**base_payload, "node_size": "llm"}
    size_drift = client.post("/api/v1/agents/register", json=size_drift_payload)
    assert size_drift.status_code == 409
    assert "node_size changed" in size_drift.json()["detail"].lower()
