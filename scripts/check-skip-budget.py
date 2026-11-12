"""Fail when a pytest junit report has more skipped tests than the ceiling recorded in tests/skip_budget.txt.

Usage: ``python scripts/check-skip-budget.py junit.xml``. Every skip needs a reason in its ``pytest.skip`` or
``skipif`` message; raising the ceiling needs the same justification in the CHANGELOG."""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

BUDGET = Path(__file__).resolve().parent.parent / "tests" / "skip_budget.txt"


def skipped(report: Path) -> int:
    root = ET.parse(report).getroot()  # noqa: S314 (our own pytest output)
    suites = [root] if root.tag == "testsuite" else list(root)
    return sum(int(s.get("skipped", 0)) for s in suites)


def main(argv: list[str]) -> int:
    ceiling = int(BUDGET.read_text(encoding="utf-8").split()[0])
    got = skipped(Path(argv[1]))
    print(f"skipped {got}, ceiling {ceiling}")
    if got > ceiling:
        print("skip count rose above the recorded ceiling: unexplained skips crept in", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
