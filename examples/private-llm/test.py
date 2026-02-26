#!/usr/bin/env python3
"""Smoke test for Private LLM — tests direct, proxy, and OpenAI client access.

Env vars:
    SERVICE_URL     — Direct tunnel URL (e.g. https://agent-xyz.easyenclave.com)
    EASYENCLAVE_URL — Control plane URL (e.g. https://app.easyenclave.com)
"""

import os
import sys
import time

import httpx
import httpx as _httpx
from easyenclave import EasyEnclaveClient
from openai import OpenAI

MODEL = "smollm2:135m"
CHAT_PATH = "/v1/chat/completions"
CHAT_BODY = {
    "model": MODEL,
    "messages": [{"role": "user", "content": "Say hello in one sentence."}],
}
TIMEOUT = 300  # 5 minutes
RETRY_INTERVAL = 15


def extract_content(response: httpx.Response) -> str:
    """Extract the assistant message from a chat completion response."""
    data = response.json()
    return data["choices"][0]["message"]["content"]


def test_direct(service_url: str) -> bool:
    """Test LLM via direct Cloudflare tunnel."""
    url = f"{service_url.rstrip('/')}{CHAT_PATH}"
    deadline = time.monotonic() + TIMEOUT

    print(f"[direct] POST {url}")
    with httpx.Client(timeout=60, headers={"user-agent": "EasyEnclave-Test/1.0"}) as client:
        while True:
            try:
                resp = client.post(url, json=CHAT_BODY)
                resp.raise_for_status()
                content = extract_content(resp)
                if content and content != "null":
                    print(f"[direct] OK: {content}")
                    return True
            except (httpx.HTTPError, KeyError, IndexError, ValueError) as e:
                if time.monotonic() >= deadline:
                    print(f"[direct] FAIL: not ready after {TIMEOUT}s — {e}")
                    return False
                print(f"[direct] Model not ready, retrying in {RETRY_INTERVAL}s...")
                time.sleep(RETRY_INTERVAL)


def test_proxy(easyenclave_url: str) -> bool:
    """Test LLM via SDK proxy."""
    print(f"[proxy] Connecting to {easyenclave_url} (verify=False for CI)")
    client = EasyEnclaveClient(easyenclave_url, verify=False)
    llm = client.service("private-llm")
    deadline = time.monotonic() + TIMEOUT

    print(f"[proxy] POST {llm.base_url}{CHAT_PATH}")
    while True:
        try:
            resp = llm.post(CHAT_PATH, json=CHAT_BODY, timeout=60)
            resp.raise_for_status()
            content = extract_content(resp)
            if content and content != "null":
                print(f"[proxy] OK: {content}")
                return True
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as e:
            if time.monotonic() >= deadline:
                print(f"[proxy] FAIL: not ready after {TIMEOUT}s — {e}")
                return False
            print(f"[proxy] Model not ready, retrying in {RETRY_INTERVAL}s...")
            time.sleep(RETRY_INTERVAL)


def _strip_bot_headers(request: _httpx.Request) -> None:
    """Remove headers that trigger Cloudflare SBFM bot detection."""
    request.headers["user-agent"] = "EasyEnclave-Test/1.0"
    for key in [k for k in request.headers if k.lower().startswith("x-stainless-")]:
        del request.headers[key]


def test_openai(easyenclave_url: str) -> bool:
    """Test LLM via the OpenAI Python client through the proxy."""
    proxy_base = f"{easyenclave_url.rstrip('/')}/proxy/private-llm/v1"
    print(f"[openai] base_url={proxy_base}")

    client = OpenAI(
        base_url=proxy_base,
        api_key="unused",
        http_client=_httpx.Client(
            verify=False,
            event_hooks={"request": [_strip_bot_headers]},
        ),
    )
    deadline = time.monotonic() + TIMEOUT

    while True:
        try:
            completion = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "user", "content": "Say hello in one sentence."}],
                timeout=60,
            )
            content = completion.choices[0].message.content
            if content:
                print(f"[openai] OK: {content}")
                return True
        except Exception as e:
            if time.monotonic() >= deadline:
                print(f"[openai] FAIL: not ready after {TIMEOUT}s — {e}")
                return False
            print(f"[openai] Model not ready, retrying in {RETRY_INTERVAL}s...")
            time.sleep(RETRY_INTERVAL)


def main():
    service_url = os.environ.get("SERVICE_URL", "")
    easyenclave_url = os.environ.get("EASYENCLAVE_URL", "")

    if not service_url and not easyenclave_url:
        print("Set SERVICE_URL and/or EASYENCLAVE_URL")
        sys.exit(1)

    ok = True

    if service_url:
        ok = test_direct(service_url) and ok

    if easyenclave_url:
        ok = test_proxy(easyenclave_url) and ok
        ok = test_openai(easyenclave_url) and ok

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
