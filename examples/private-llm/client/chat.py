#!/usr/bin/env python3
"""Simple chat client for Private LLM using E2E encryption.

Usage:
    # Direct connection (provide Noise pubkey)
    python chat.py wss://service.example.com/ws/noise <noise_pubkey_hex>

    # Via EasyEnclave discovery
    python chat.py --easyenclave private-llm
"""

import asyncio
import sys

from easyenclave.noise import NoiseClient


async def main():
    # Parse arguments
    if len(sys.argv) < 2:
        print("Usage: python chat.py <ws_url> [noise_pubkey]")
        print("       python chat.py --easyenclave <service_name>")
        sys.exit(1)

    if sys.argv[1] == "--easyenclave":
        service_name = sys.argv[2] if len(sys.argv) > 2 else "private-llm"
        client = await NoiseClient.from_easyenclave(service_name)
    else:
        url = sys.argv[1]
        pubkey = sys.argv[2] if len(sys.argv) > 2 else None
        client = NoiseClient(url, server_pubkey=pubkey)

    print("Connecting and verifying attestation...")
    async with client:
        result = await client.verify()

        if not result.secure:
            print(f"Verification failed: {result.error}")
            sys.exit(1)

        print(f"Connected to verified TEE (MRTD: {result.mrtd[:16]}...)")
        print("Type messages to chat. Press Ctrl+C to exit.\n")

        messages = []
        while True:
            try:
                user_input = input("You: ")
                messages.append({"role": "user", "content": user_input})

                response = await client.call("chat", {"messages": messages})
                assistant_msg = response.get("message", {})
                content = assistant_msg.get("content", "")

                print(f"Assistant: {content}\n")
                messages.append(assistant_msg)

            except KeyboardInterrupt:
                print("\nGoodbye!")
                break


if __name__ == "__main__":
    asyncio.run(main())
