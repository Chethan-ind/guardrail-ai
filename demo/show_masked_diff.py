"""
show_masked_diff.py
Standalone visual: runs detector+masker directly (no AWS needed at all)
against the fixtures and prints original vs masked side by side. Good
B-roll for the demo video — shows exactly what a reviewer would see in
the GitHub diff after GuardRail rewrites it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.detector import scan_text
from src.masker import mask_content

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def main():
    for path in sorted(FIXTURES_DIR.iterdir()):
        if not path.is_file():
            continue
        content = path.read_text()
        findings = scan_text(content, str(path.name))
        if not findings:
            continue
        masked, _vault_payload = mask_content(content, findings)

        print("\n" + "#" * 72)
        print(f"# {path.name}  ({len(findings)} finding(s))")
        print("#" * 72)
        print("\n--- BEFORE (raw secret in repo) ---")
        print(content)
        print("--- AFTER (what GuardRail commits back) ---")
        print(masked)


if __name__ == "__main__":
    main()
