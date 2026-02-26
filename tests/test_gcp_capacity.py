from __future__ import annotations

import asyncio

from app import gcp_capacity


def test_ownership_scope_labels_include_expected_values(monkeypatch):
    monkeypatch.setenv("EASYENCLAVE_NETWORK_NAME", "Trippy-Drifter-2c6b1c")
    monkeypatch.setenv("EASYENCLAVE_ENV", "staging")
    monkeypatch.setenv("EASYENCLAVE_BOOT_ID", "bootstrap-22260503213-1")
    monkeypatch.setenv("EASYENCLAVE_CP_URL", "https://app-staging.easyenclave.com")
    monkeypatch.setenv("EASYENCLAVE_RELEASE_TAG", "v0.1.10")
    monkeypatch.setenv("EASYENCLAVE_GIT_SHA", "e451f2f3d9a4f0f0a61a8c0de5ce8b1f9ad2beef")

    labels = gcp_capacity._ownership_scope_labels()

    assert labels["ee-network"] == "trippy-drifter-2c6b1c"
    assert labels["ee-env"] == "staging"
    assert labels["ee-cp-boot"] == "bootstrap-22260503213-1"
    assert labels["ee-cp-host"] == "app-staging-easyenclave-com"
    assert labels["ee-release"] == "v0-1-10"
    assert labels["ee_release"] == "v0-1-10"
    assert labels["ee-git-sha"] == "e451f2f3d9a4f0f0a61a8c0de5ce8b1f9ad2beef"
    assert labels["ee_git_sha"] == "e451f2f3d9a4f0f0a61a8c0de5ce8b1f9ad2beef"


def test_instance_owned_by_current_scope_requires_matching_network_and_env(monkeypatch):
    monkeypatch.setenv("EASYENCLAVE_NETWORK_NAME", "solar-spectrum-e19f1e")
    monkeypatch.setenv("EASYENCLAVE_ENV", "production")

    assert gcp_capacity._instance_owned_by_current_scope(
        {"ee-network": "solar-spectrum-e19f1e", "ee-env": "production"}
    )
    assert not gcp_capacity._instance_owned_by_current_scope(
        {"ee-network": "solar-spectrum-e19f1e", "ee-env": "staging"}
    )
    assert not gcp_capacity._instance_owned_by_current_scope(
        {"ee-network": "trippy-drifter-2c6b1c", "ee-env": "production"}
    )
    assert not gcp_capacity._instance_owned_by_current_scope({"ee-env": "production"})


def test_list_managed_instances_owned_only_requires_network_scope(monkeypatch):
    monkeypatch.delenv("EASYENCLAVE_NETWORK_NAME", raising=False)
    monkeypatch.delenv("EASYENCLAVE_ENV", raising=False)

    assert asyncio.run(gcp_capacity.list_managed_instances(owned_only=True)) == []
