"""Run inside Ubuntu. Enter the API key without putting it in shell history."""
from __future__ import annotations

import getpass
import os
import tempfile

import packetpilot
from pp_settings import api_config, key_path
from pp_llm import LLMError


def main():
    path = key_path()
    if path.exists() and input("A key is already saved. Replace it? [y/N] ").strip().lower() != "y":
        return
    print("Paste your configured provider's API key below. The characters will stay hidden.")
    key = getpass.getpass("API key: ").strip()
    from dataclasses import replace
    replace(api_config(packetpilot.ROOT), api_key=key).endpoint()
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".key-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("DEEPSEEK_API_KEY=" + key + "\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print("Key saved privately outside the project. PacketPilot will read it on the next request.")
    print("No model request was sent and the key was not displayed.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, LLMError):
        raise SystemExit("The key could not be saved. Check the value and file permissions.") from None
