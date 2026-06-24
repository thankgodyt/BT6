#!/usr/bin/env python3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
VALIDATED_DIR = PROJECT_ROOT / "validated"
SCANNED_DIR = PROJECT_ROOT / "scanned"


def main() -> int:
    if not VALIDATED_DIR.exists():
        print(f"Nothing to rename: {VALIDATED_DIR} does not exist.")
        return 1

    if not VALIDATED_DIR.is_dir():
        print(f"Cannot continue: {VALIDATED_DIR} is not a folder.")
        return 1

    if SCANNED_DIR.exists():
        print(f"Cannot continue: {SCANNED_DIR} already exists.")
        return 1

    renamed_files = 0

    for path in sorted(VALIDATED_DIR.iterdir()):
        if not path.is_file() or not path.name.startswith("audit"):
            continue

        new_name = "validation" + path.name[len("audit") :]
        new_path = path.with_name(new_name)

        if new_path.exists():
            print(f"Cannot continue: target file already exists: {new_path}")
            return 1

        path.rename(new_path)
        renamed_files += 1

    VALIDATED_DIR.rename(SCANNED_DIR)

    print(f"Renamed {renamed_files} files from audit* to validation*.")
    print(f"Renamed folder: {VALIDATED_DIR.name} -> {SCANNED_DIR.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
