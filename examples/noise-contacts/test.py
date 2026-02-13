#!/usr/bin/env python3
"""Integration test for noise-contacts.

Validates:
1. Noise XX handshake over HTTP messages
2. Attestation claims bound to Noise static identity
3. Encrypted register + lookup flow for contacts
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from noise.connection import Keypair, NoiseConnection

NOISE_PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_BLAKE2s"
TIMEOUT = int(os.environ.get("TIMEOUT", "300"))
RETRY_INTERVAL = int(os.environ.get("RETRY_INTERVAL", "5"))


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def build_initiator() -> tuple[NoiseConnection, str]:
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_hex = priv.public_key().public_bytes_raw().hex()

    conn = NoiseConnection.from_name(NOISE_PROTOCOL_NAME)
    conn.set_as_initiator()
    conn.set_keypair_from_private_bytes(Keypair.STATIC, priv_bytes)
    conn.start_handshake()
    return conn, pub_hex


def wait_for_health(client: httpx.Client, service_url: str) -> None:
    deadline = time.monotonic() + TIMEOUT
    url = f"{service_url.rstrip('/')}/health"

    while True:
        try:
            resp = client.get(url, timeout=10)
            if resp.status_code == 200 and resp.json().get("status") == "healthy":
                print("[health] service is healthy")
                return
        except Exception:
            pass

        if time.monotonic() >= deadline:
            raise RuntimeError("noise-contacts did not become healthy in time")

        print(f"[health] waiting {RETRY_INTERVAL}s...")
        time.sleep(RETRY_INTERVAL)


def run_noise_flow(client: httpx.Client, service_url: str) -> None:
    conn, initiator_pub_hex = build_initiator()

    init_url = f"{service_url.rstrip('/')}/noise/handshake/init"
    finalize_url = f"{service_url.rstrip('/')}/noise/handshake/finalize"
    request_url = f"{service_url.rstrip('/')}/noise/request"

    # Message 1 -> init
    m1 = conn.write_message()
    init_resp = client.post(init_url, json={"msg1_b64": b64e(m1)}, timeout=20)
    init_resp.raise_for_status()
    init_data = init_resp.json()
    session_id = init_data["session_id"]
    print(f"[noise] session_id={session_id}")

    # Read message 2, write message 3
    conn.read_message(b64d(init_data["msg2_b64"]))
    m3 = conn.write_message()

    # Finalize handshake with attestation claims bound to initiator static key
    finalize_payload = {
        "session_id": session_id,
        "msg3_b64": b64e(m3),
        "attestation": {
            "peer_id": "ci-noise-client",
            "mrtd": os.environ.get("TEST_MRTD", "ci-demo-mrtd"),
            "noise_static_pubkey": initiator_pub_hex,
            "rtmrs": {
                "rtmr0": "demo",
                "rtmr1": "demo",
                "rtmr2": "demo",
                "rtmr3": "demo",
            },
        },
    }
    fin_resp = client.post(finalize_url, json=finalize_payload, timeout=20)
    fin_resp.raise_for_status()
    fin_data = fin_resp.json()

    if not fin_data.get("binding", {}).get("noise_key_matches_attestation"):
        raise RuntimeError("attestation/noise binding check failed")

    print("[noise] handshake finalized")

    def roundtrip(payload: dict) -> dict:
        ct = conn.encrypt(json.dumps(payload).encode("utf-8"))
        resp = client.post(
            request_url,
            json={"session_id": session_id, "ciphertext_b64": b64e(ct)},
            timeout=20,
        )
        resp.raise_for_status()
        body = resp.json()
        pt = conn.decrypt(b64d(body["ciphertext_b64"]))
        return json.loads(pt.decode("utf-8"))

    reg = roundtrip({"op": "register", "user_id": "alice", "contact": "+15551234567"})
    if not reg.get("ok"):
        raise RuntimeError(f"register failed: {reg}")

    lookup_hit = roundtrip({"op": "lookup", "user_id": "alice", "contact": "+15551234567"})
    if lookup_hit.get("exists") is not True:
        raise RuntimeError(f"lookup hit failed: {lookup_hit}")

    lookup_miss = roundtrip({"op": "lookup", "user_id": "alice", "contact": "+15559876543"})
    if lookup_miss.get("exists") is not False:
        raise RuntimeError(f"lookup miss failed: {lookup_miss}")

    print("[noise] encrypted contact flow passed")


def main() -> int:
    service_url = os.environ.get("SERVICE_URL")
    if not service_url:
        print("SERVICE_URL is required", file=sys.stderr)
        return 2

    print(f"Testing noise-contacts at {service_url}")

    with httpx.Client(verify=False) as client:
        wait_for_health(client, service_url)
        run_noise_flow(client, service_url)

    print("All checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
