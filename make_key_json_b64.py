#!/usr/bin/env python3
import base64
import json
from pathlib import Path


def main() -> int:
    key_path = Path("key.json")
    if not key_path.exists():
        print("key.json not found in the current directory")
        return 1

    try:
        payload = json.loads(key_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"key.json is not valid JSON: {exc}")
        return 1

    if not isinstance(payload, dict) or not payload:
        print("key.json must be a non-empty JSON object")
        return 1

    compact_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    encoded = base64.b64encode(compact_json.encode("utf-8")).decode("ascii")
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
