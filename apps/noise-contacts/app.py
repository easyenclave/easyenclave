"""Noise Contacts demo service.

This example demonstrates how to bind a Noise session identity (remote static
key) to attestation metadata at handshake time.

Security model (demo):
- Noise handshake provides channel confidentiality/integrity.
- Client sends attestation metadata during handshake finalization.
- Service verifies the attestation's claimed Noise static key matches the
  key proven in the Noise handshake.
- Optional policy checks can enforce trusted MRTDs and per-peer constraints.

This is intentionally simple to show integration points. In production, attestation
claims should be verified cryptographically against Intel TA / control plane APIs.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi import FastAPI, HTTPException
from noise.connection import Keypair, NoiseConnection
from pydantic import BaseModel, Field

NOISE_PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_BLAKE2s"
SESSION_TTL_SECONDS = int(os.environ.get("NOISE_SESSION_TTL_SECONDS", "900"))
MAX_SESSIONS = int(os.environ.get("NOISE_MAX_SESSIONS", "1000"))
ATTESTATION_MODE = os.environ.get("NOISE_ATTESTATION_MODE", "warn").strip().lower()


def _load_server_static_private_key() -> bytes:
    raw = os.environ.get("NOISE_STATIC_PRIVATE_KEY", "").strip()
    if raw:
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise RuntimeError("NOISE_STATIC_PRIVATE_KEY must be 64 hex chars") from exc
        if len(key) != 32:
            raise RuntimeError("NOISE_STATIC_PRIVATE_KEY must decode to 32 bytes")
        return key

    # Demo fallback for convenience: ephemeral per boot.
    return X25519PrivateKey.generate().private_bytes_raw()


def _load_trusted_mrtds() -> set[str]:
    raw = os.environ.get("TRUSTED_MRTDS", "").strip()
    if not raw:
        raw = os.environ.get("TRUSTED_AGENT_MRTDS", "").strip()
    return {item.strip() for item in raw.split(",") if item.strip()}


def _load_trusted_peers() -> dict[str, dict[str, Any]]:
    raw = os.environ.get("TRUSTED_PEERS_JSON", "").strip()
    if not raw:
        return {}

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("TRUSTED_PEERS_JSON must be valid JSON") from exc

    if not isinstance(parsed, dict):
        raise RuntimeError("TRUSTED_PEERS_JSON must be an object")

    normalized: dict[str, dict[str, Any]] = {}
    for peer_id, policy in parsed.items():
        if not isinstance(peer_id, str) or not peer_id:
            continue
        if not isinstance(policy, dict):
            continue
        noise_static = str(policy.get("noise_static_pubkey", "")).strip().lower()
        allowed_mrtds_raw = policy.get("mrtds", [])
        allowed_mrtds: set[str] = set()
        if isinstance(allowed_mrtds_raw, list):
            for item in allowed_mrtds_raw:
                if isinstance(item, str) and item.strip():
                    allowed_mrtds.add(item.strip())
        normalized[peer_id] = {
            "noise_static_pubkey": noise_static,
            "mrtds": allowed_mrtds,
        }
    return normalized


SERVER_STATIC_PRIVATE_KEY = _load_server_static_private_key()
SERVER_STATIC_PUBLIC_KEY = (
    X25519PrivateKey.from_private_bytes(SERVER_STATIC_PRIVATE_KEY)
    .public_key()
    .public_bytes_raw()
    .hex()
)
TRUSTED_MRTDS = _load_trusted_mrtds()
TRUSTED_PEERS = _load_trusted_peers()

if ATTESTATION_MODE not in {"strict", "warn", "disabled"}:
    ATTESTATION_MODE = "warn"


@dataclass
class NoiseSession:
    conn: NoiseConnection
    created_at: float
    expires_at: float
    lock: threading.Lock = field(default_factory=threading.Lock)
    handshake_complete: bool = False
    peer_id: str | None = None
    attestation_verified: bool = False
    binding_details: dict[str, Any] = field(default_factory=dict)


_sessions: dict[str, NoiseSession] = {}
_sessions_lock = threading.Lock()
_contacts: dict[str, set[str]] = {}
_contacts_lock = threading.Lock()


class HandshakeInitRequest(BaseModel):
    msg1_b64: str = Field(..., description="Noise message #1 (base64)")


class AttestationClaims(BaseModel):
    peer_id: str
    mrtd: str
    noise_static_pubkey: str
    rtmrs: dict[str, str] | None = None


class HandshakeFinalizeRequest(BaseModel):
    session_id: str
    msg3_b64: str = Field(..., description="Noise message #3 (base64)")
    attestation: AttestationClaims


class NoiseRequest(BaseModel):
    session_id: str
    ciphertext_b64: str


app = FastAPI(title="Noise Contacts Demo", version="0.1.0")


def _b64_decode(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid base64 payload: {exc}") from exc


def _b64_encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _new_responder_connection() -> NoiseConnection:
    conn = NoiseConnection.from_name(NOISE_PROTOCOL_NAME)
    conn.set_as_responder()
    conn.set_keypair_from_private_bytes(Keypair.STATIC, SERVER_STATIC_PRIVATE_KEY)
    conn.start_handshake()
    return conn


def _cleanup_expired_sessions() -> None:
    now = time.time()
    with _sessions_lock:
        expired = [sid for sid, sess in _sessions.items() if sess.expires_at < now]
        for sid in expired:
            _sessions.pop(sid, None)


def _verify_attestation_binding(
    claims: AttestationClaims, remote_static_pubkey: str
) -> tuple[bool, dict[str, Any], list[str]]:
    notes: list[str] = []
    failures: list[str] = []

    claimed_noise_key = claims.noise_static_pubkey.strip().lower()
    mrtd = claims.mrtd.strip()

    key_matches = claimed_noise_key == remote_static_pubkey
    if not key_matches:
        failures.append("attestation.noise_static_pubkey does not match Noise remote static key")

    mrtd_trusted = True
    if TRUSTED_MRTDS:
        mrtd_trusted = mrtd in TRUSTED_MRTDS
        if not mrtd_trusted:
            failures.append("attestation.mrtd is not in TRUSTED_MRTDS")
    else:
        notes.append("TRUSTED_MRTDS not configured; MRTD check skipped")

    peer_policy_ok = True
    if TRUSTED_PEERS:
        policy = TRUSTED_PEERS.get(claims.peer_id)
        if not policy:
            peer_policy_ok = False
            failures.append(f"peer_id '{claims.peer_id}' not present in TRUSTED_PEERS_JSON")
        else:
            expected_key = str(policy.get("noise_static_pubkey", "")).strip().lower()
            allowed_mrtds: set[str] = policy.get("mrtds", set())
            if expected_key and expected_key != claimed_noise_key:
                peer_policy_ok = False
                failures.append("peer policy noise_static_pubkey mismatch")
            if allowed_mrtds and mrtd not in allowed_mrtds:
                peer_policy_ok = False
                failures.append("peer policy does not allow this mrtd")
    else:
        notes.append("TRUSTED_PEERS_JSON not configured; peer policy check skipped")

    verified = key_matches and mrtd_trusted and peer_policy_ok
    details = {
        "mode": ATTESTATION_MODE,
        "peer_id": claims.peer_id,
        "mrtd": mrtd,
        "noise_key_matches_attestation": key_matches,
        "mrtd_trusted": mrtd_trusted,
        "peer_policy_ok": peer_policy_ok,
        "failures": failures,
        "notes": notes,
    }

    if ATTESTATION_MODE == "disabled":
        details["notes"].append("NOISE_ATTESTATION_MODE=disabled; verification not enforced")
        return True, details, failures

    if ATTESTATION_MODE == "warn":
        return True, details, failures

    # strict
    return verified, details, failures


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "service": "noise-contacts",
        "protocol": NOISE_PROTOCOL_NAME.decode("ascii"),
        "responder_static_pubkey": SERVER_STATIC_PUBLIC_KEY,
        "attestation_mode": ATTESTATION_MODE,
    }


@app.get("/health")
def health() -> dict[str, Any]:
    _cleanup_expired_sessions()
    with _sessions_lock:
        session_count = len(_sessions)
    with _contacts_lock:
        user_count = len(_contacts)
    return {
        "status": "healthy",
        "service": "noise-contacts",
        "protocol": NOISE_PROTOCOL_NAME.decode("ascii"),
        "responder_static_pubkey": SERVER_STATIC_PUBLIC_KEY,
        "attestation_mode": ATTESTATION_MODE,
        "trusted_mrtd_count": len(TRUSTED_MRTDS),
        "trusted_peer_count": len(TRUSTED_PEERS),
        "active_sessions": session_count,
        "users": user_count,
    }


@app.post("/noise/handshake/init")
def noise_handshake_init(request: HandshakeInitRequest) -> dict[str, Any]:
    _cleanup_expired_sessions()

    msg1 = _b64_decode(request.msg1_b64)
    conn = _new_responder_connection()

    try:
        conn.read_message(msg1)
        msg2 = conn.write_message()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Noise handshake init failed: {exc}") from exc

    with _sessions_lock:
        if len(_sessions) >= MAX_SESSIONS:
            raise HTTPException(status_code=503, detail="Too many active Noise sessions")
        session_id = secrets.token_urlsafe(24)
        _sessions[session_id] = NoiseSession(
            conn=conn,
            created_at=time.time(),
            expires_at=time.time() + SESSION_TTL_SECONDS,
        )

    return {
        "session_id": session_id,
        "msg2_b64": _b64_encode(msg2),
        "protocol": NOISE_PROTOCOL_NAME.decode("ascii"),
        "responder_static_pubkey": SERVER_STATIC_PUBLIC_KEY,
        "expires_in_seconds": SESSION_TTL_SECONDS,
    }


@app.post("/noise/handshake/finalize")
def noise_handshake_finalize(request: HandshakeFinalizeRequest) -> dict[str, Any]:
    _cleanup_expired_sessions()

    with _sessions_lock:
        session = _sessions.get(request.session_id)

    if session is None:
        raise HTTPException(status_code=404, detail="Noise session not found or expired")

    msg3 = _b64_decode(request.msg3_b64)

    with session.lock:
        if session.handshake_complete:
            raise HTTPException(status_code=409, detail="Handshake already finalized")

        try:
            session.conn.read_message(msg3)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Noise handshake finalize failed: {exc}") from exc

        remote_static_pubkey = (
            session.conn.noise_protocol.handshake_state.rs.public_bytes.hex().lower()
        )
        allowed, binding_details, failures = _verify_attestation_binding(
            request.attestation,
            remote_static_pubkey,
        )
        if not allowed:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Attestation verification failed",
                    "binding": binding_details,
                    "failures": failures,
                },
            )

        session.handshake_complete = True
        session.peer_id = request.attestation.peer_id
        session.attestation_verified = (
            binding_details["noise_key_matches_attestation"]
            and binding_details["mrtd_trusted"]
            and binding_details["peer_policy_ok"]
        )
        session.binding_details = binding_details

    return {
        "status": "ok",
        "session_id": request.session_id,
        "peer_id": session.peer_id,
        "attestation_verified": session.attestation_verified,
        "binding": binding_details,
    }


@app.post("/noise/request")
def noise_request(request: NoiseRequest) -> dict[str, Any]:
    _cleanup_expired_sessions()

    with _sessions_lock:
        session = _sessions.get(request.session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Noise session not found or expired")

    ciphertext = _b64_decode(request.ciphertext_b64)

    with session.lock:
        if not session.handshake_complete:
            raise HTTPException(status_code=409, detail="Noise handshake not complete")

        try:
            plaintext = session.conn.decrypt(ciphertext)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Noise decrypt failed: {exc}") from exc

        try:
            message = json.loads(plaintext.decode("utf-8"))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid request payload: {exc}") from exc

        op = str(message.get("op", "")).strip().lower()

        if op == "register":
            user_id = str(message.get("user_id", "")).strip()
            contact = str(message.get("contact", "")).strip()
            if not user_id or not contact:
                raise HTTPException(status_code=400, detail="register requires user_id and contact")
            with _contacts_lock:
                _contacts.setdefault(user_id, set()).add(contact)
                count = len(_contacts[user_id])
            response = {"ok": True, "op": "register", "user_id": user_id, "contacts": count}
        elif op == "lookup":
            user_id = str(message.get("user_id", "")).strip()
            contact = str(message.get("contact", "")).strip()
            if not user_id or not contact:
                raise HTTPException(status_code=400, detail="lookup requires user_id and contact")
            with _contacts_lock:
                exists = contact in _contacts.get(user_id, set())
            response = {
                "ok": True,
                "op": "lookup",
                "user_id": user_id,
                "contact": contact,
                "exists": exists,
            }
        elif op == "list":
            user_id = str(message.get("user_id", "")).strip()
            if not user_id:
                raise HTTPException(status_code=400, detail="list requires user_id")
            with _contacts_lock:
                contacts = sorted(_contacts.get(user_id, set()))
            response = {"ok": True, "op": "list", "user_id": user_id, "contacts": contacts}
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported op '{op}'")

        response["peer_id"] = session.peer_id
        response["attestation_verified"] = session.attestation_verified

        try:
            response_ct = session.conn.encrypt(json.dumps(response).encode("utf-8"))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Noise encrypt failed: {exc}") from exc

    return {
        "session_id": request.session_id,
        "ciphertext_b64": _b64_encode(response_ct),
    }
