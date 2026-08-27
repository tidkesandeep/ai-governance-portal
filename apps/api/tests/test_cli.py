from __future__ import annotations

from types import SimpleNamespace

import pytest

from aigov.cli.main import build_parser, gate_exit_code, main


def test_gate_exit_codes() -> None:
    assert gate_exit_code("ALLOW") == 0
    assert gate_exit_code("BLOCK") == 1
    assert gate_exit_code("REVIEW") == 2
    assert gate_exit_code("mystery") == 1


def test_cli_help_exits_zero() -> None:
    with pytest.raises(SystemExit) as exited:
        main(["--help"])
    assert exited.value.code == 0


def test_cli_no_command_prints_help(capsys) -> None:
    assert main([]) == 0
    captured = capsys.readouterr()
    assert "Operator and CI surface" in captured.out


def test_cli_gate_allow_exit_zero(monkeypatch) -> None:
    monkeypatch.setattr(
        "aigov.cli.main.request",
        lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {"outcome": "ALLOW"}),
    )
    assert main(["gate", "sys_demo"]) == 0


def test_cli_gate_block_exit_one(monkeypatch) -> None:
    monkeypatch.setattr(
        "aigov.cli.main.request",
        lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {"outcome": "BLOCK"}),
    )
    assert main(["gate", "sys_demo"]) == 1


def test_cli_gate_review_exit_two(monkeypatch) -> None:
    monkeypatch.setattr(
        "aigov.cli.main.request",
        lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {"outcome": "REVIEW"}),
    )
    assert main(["gate", "sys_demo"]) == 2


def test_parser_exposes_operator_commands() -> None:
    parser = build_parser()
    args = parser.parse_args(["github", "check", "sys_x", "--sha", "abc", "--repo", "acme/fraud"])
    assert args.command == "github"
    assert args.github_command == "check"
    assert args.sha == "abc"
