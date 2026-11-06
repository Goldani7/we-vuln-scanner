import io
from unittest.mock import patch

import pytest

rich = pytest.importorskip("rich")

from scanner import ui
from scanner.menu import build_argv, gather_inputs, main


def console():
    return ui.Console(file=io.StringIO(), width=100)


def feed(*answers):
    it = iter(answers)
    return lambda prompt: next(it, "")


def test_minimal_flow_defaults_to_full_mode_rich_terminal_only():
    answers = gather_inputs(console(), feed("https://ex.com", "", "", "", ""))
    assert answers == {"target": "https://ex.com", "mode": "full", "allow_active": False,
                       "scope": "", "output": ""}
    assert build_argv(answers) == ["-t", "https://ex.com", "-m", "full", "--rich"]


def test_blank_target_is_asked_again():
    answers = gather_inputs(console(), feed("", "   ", "https://ex.com", "2", "n", "1"))
    assert answers["target"] == "https://ex.com" and answers["mode"] == "web"


@pytest.mark.parametrize("choice,mode", [("1", "full"), ("2", "web"), ("3", "email"), ("4", "recon")])
def test_mode_selection(choice, mode):
    answers = gather_inputs(console(), feed("ex.com", choice, "n", "1"))
    assert answers["mode"] == mode


def test_invalid_mode_choice_falls_back_to_full():
    answers = gather_inputs(console(), feed("ex.com", "9", "n", "1"))
    assert answers["mode"] == "full"


def test_active_checks_require_a_scope_path_or_they_stay_off():
    answers = gather_inputs(console(), feed("ex.com", "1", "y", "", "1"))
    assert answers["allow_active"] is False and answers["scope"] == ""


def test_active_checks_enabled_with_scope_path():
    answers = gather_inputs(console(), feed("ex.com", "1", "y", "scope.txt", "1"))
    assert answers["allow_active"] is True and answers["scope"] == "scope.txt"
    argv = build_argv(answers)
    assert "--scope" in argv and "scope.txt" in argv and "--allow-active" in argv


@pytest.mark.parametrize("word", ["y", "Y", "yes", "YES"])
def test_active_accepts_several_affirmative_spellings(word):
    answers = gather_inputs(console(), feed("ex.com", "1", word, "scope.txt", "1"))
    assert answers["allow_active"] is True


def test_output_format_asks_for_a_filename_with_matching_default_extension():
    answers = gather_inputs(console(), feed("ex.com", "1", "n", "3", ""))
    assert answers["output"] == "report.json"


def test_output_format_accepts_custom_filename():
    answers = gather_inputs(console(), feed("ex.com", "1", "n", "2", "my.md"))
    assert answers["output"] == "my.md"
    assert build_argv(answers)[-2:] == ["-o", "my.md"]


def test_no_output_file_means_no_dash_o_in_argv():
    answers = gather_inputs(console(), feed("ex.com", "1", "n", "1"))
    assert "-o" not in build_argv(answers)


def test_build_argv_without_scope_never_adds_allow_active():
    assert build_argv({"target": "x", "mode": "web", "allow_active": True, "scope": "", "output": ""}) == [
        "-t", "x", "-m", "web", "--rich"]


def test_main_delegates_to_cli_with_the_built_argv():
    with patch("scanner.menu.gather_inputs", return_value={"target": "ex.com", "mode": "web",
                                                            "allow_active": False, "scope": "", "output": ""}), \
         patch("scanner.menu.cli_main", return_value=0) as cli:
        assert main() == 0
    assert cli.call_args.args[0] == ["-t", "ex.com", "-m", "web", "--rich"]


def test_main_handles_ctrl_c_gracefully():
    with patch("scanner.menu.gather_inputs", side_effect=KeyboardInterrupt), \
         patch("scanner.menu.cli_main") as cli:
        assert main() == 1
    assert not cli.called
