"""Fail when a pytest junit report has fewer passing tests than the floor recorded in tests/pass_floor.txt.

Usage: ``python scripts/check-pass-floor.py junit.xml``. Raise the floor in the same change that adds tests;
lowering it needs a reason in the commit (a lower number means tests were removed or are being skipped)."""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

FLOOR = Path(__file__).resolve().parent.parent / "tests" / "pass_floor.txt"


def passed(report: Path) -> int:
    root = ET.parse(report).getroot()  # noqa: S314 (our own pytest output)
    suites = [root] if root.tag == "testsuite" else list(root)
    total = sum(int(s.get("tests", 0)) for s in suites)
    bad = sum(int(s.get(k, 0)) for s in suites for k in ("failures", "errors", "skipped"))
    return total - bad


def main(argv: list[str]) -> int:
    floor = int(FLOOR.read_text(encoding="utf-8").split()[0])
    got = passed(Path(argv[1]))
    print(f"passed {got}, floor {floor}")
    if got < floor:
        print("pass count fell below the recorded floor: tests were removed or skipped", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
