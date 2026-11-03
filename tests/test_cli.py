import json

import pytest

from headerscan import cli
from headerscan.models import Finding, ScanResult, Severity, Status
from headerscan.scanner import ScanError


def fake_result(status: Status) -> ScanResult:
    f = Finding("x", "X", Severity.HIGH, status, "detail")
    return ScanResult("https://a.test", "https://a.test/", 200, [], [f])


def test_exit_0_when_grade_meets_minimum(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", lambda *a, **k: fake_result(Status.PASS))
    assert cli.main(["a.test"]) == 0
    assert "Grade A" in capsys.readouterr().out


def test_exit_1_when_below_min_grade(monkeypatch):
    monkeypatch.setattr(cli, "scan", lambda *a, **k: fake_result(Status.FAIL))
    assert cli.main(["a.test"]) == 1
    assert cli.main(["a.test", "--min-grade", "F"]) == 0


def test_exit_2_on_scan_error(monkeypatch):
    def boom(*a, **k):
        raise ScanError("nope")

    monkeypatch.setattr(cli, "scan", boom)
    assert cli.main(["a.test"]) == 2


def test_json_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", lambda *a, **k: fake_result(Status.PASS))
    cli.main(["a.test", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["grade"] == "A"


def test_hostile_markup_in_header_does_not_crash(monkeypatch, capsys):
    f = Finding("x", "X", Severity.LOW, Status.WARN, "d", value="[/bold][red]pwn[/")
    r = ScanResult("https://a.test", "https://a.test/", 200, [], [f])
    monkeypatch.setattr(cli, "scan", lambda *a, **k: r)
    cli.main(["a.test"])
    assert "[red]pwn" in capsys.readouterr().out


def test_requires_a_url():
    with pytest.raises(SystemExit):
        cli.main([])
