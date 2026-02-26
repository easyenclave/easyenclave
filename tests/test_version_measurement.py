import base64
import hashlib

import pytest

import app.version_measurement as vm


@pytest.mark.asyncio
async def test_measure_compose_resolves_images(monkeypatch):
    async def fake_resolve_digest(image: str, client):  # noqa: ARG001
        assert image == "nginx:latest"
        return "sha256:" + ("ab" * 32)

    monkeypatch.setattr(vm, "resolve_digest", fake_resolve_digest)

    compose = "services:\n  web:\n    image: nginx:latest\n"
    compose_b64 = base64.b64encode(compose.encode()).decode()
    measurement = await vm.measure_compose(
        compose_b64,
        node_size="tiny",
        signature_mode="disabled",
    )

    assert measurement["node_size"] == "tiny"
    assert measurement["measurement_type"] == "cp_digest_resolution"
    assert measurement["compose_hash"] == hashlib.sha256(compose.encode()).hexdigest()
    assert "web" in measurement["resolved_images"]
    assert measurement["resolved_images"]["web"]["original"] == "nginx:latest"
    assert measurement["resolved_images"]["web"]["digest"].startswith("sha256:")
