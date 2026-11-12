"""The skip-budget gate: a junit report with more skips than tests/skip_budget.txt fails the CI step."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_skip_budget", ROOT / "scripts" / "check-skip-budget.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _report(path: Path, skipped: int) -> Path:
    path.write_text(
        f'<?xml version="1.0"?><testsuites><testsuite name="pytest" tests="30" failures="0" errors="0" '
        f'skipped="{skipped}"/></testsuites>',
        encoding="utf-8",
    )
    return path


def test_committed_ceiling_is_a_positive_integer():
    budget = (ROOT / "tests" / "skip_budget.txt").read_text(encoding="utf-8").split()
    assert len(budget) == 1 and int(budget[0]) >= 0


@pytest.mark.parametrize("skipped", [0, 1])
def test_skips_at_or_below_the_ceiling_pass(tmp_path: Path, monkeypatch, skipped: int):
    mod = _load()
    monkeypatch.setattr(mod, "BUDGET", tmp_path / "budget.txt")
    (tmp_path / "budget.txt").write_text("1\n", encoding="utf-8")
    assert mod.main(["check", str(_report(tmp_path / "junit.xml", skipped))]) == 0


def test_one_skip_above_the_ceiling_fails(tmp_path: Path, monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod, "BUDGET", tmp_path / "budget.txt")
    (tmp_path / "budget.txt").write_text("24\n", encoding="utf-8")
    assert mod.main(["check", str(_report(tmp_path / "junit.xml", 25))]) == 1


def test_the_real_report_format_counts_suite_skips(tmp_path: Path):
    mod = _load()
    nested = tmp_path / "junit.xml"
    nested.write_text(
        '<?xml version="1.0"?><testsuites>'
        '<testsuite name="a" tests="5" skipped="2"/><testsuite name="b" tests="5" skipped="3"/></testsuites>',
        encoding="utf-8",
    )
    assert mod.skipped(nested) == 5
