import io

import pytest

rich = pytest.importorskip("rich")

from scanner import ui
from scanner.finding import Finding, Severity


def _console():
    return ui.make_console()


def test_rich_is_detected_as_available():
    assert ui.RICH_AVAILABLE is True


def test_banner_contains_brand_target_and_mode(capsys):
    console = ui.Console(file=io.StringIO(), width=100)
    ui.print_banner(console, "https://ex.com", "full")
    out = console.file.getvalue()
    assert "GOLDANI" in out.upper() and "https://ex.com" in out and "full" in out


def test_progress_reporter_tracks_declared_checks():
    console = ui.Console(file=io.StringIO(), width=100)
    with ui.make_progress(console) as progress:
        reporter = ui.ProgressReporter(progress, ["headers", "cookies"])
        assert set(reporter.tasks) == {"headers", "cookies"}
        reporter.on_event("start", "headers")
        reporter.on_event("done", "headers", 3)
        task = next(t for t in progress.tasks if t.id == reporter.tasks["headers"])
        assert task.completed == 1 and "3 achado" in task.description


def test_progress_reporter_handles_unplanned_check():
    console = ui.Console(file=io.StringIO(), width=100)
    with ui.make_progress(console) as progress:
        reporter = ui.ProgressReporter(progress, [])
        reporter.on_event("start", "plugin_x")
        reporter.on_event("done", "plugin_x", 0)
    assert "plugin_x" in reporter.tasks


def test_print_results_renders_table_with_severity_and_hides_info():
    console = ui.Console(file=io.StringIO(), width=120)
    findings = [Finding("headers", Severity.CRITICAL, "achado crítico", confidence="high"),
               Finding("tls", Severity.INFO, "só confirmação")]
    ui.print_results(console, findings, {"target": "https://ex.com"})
    out = console.file.getvalue()
    assert "achado crítico" in out and "CRÍTICO" in out
    assert "só confirmação" not in out  # INFO não entra na tabela de achados


def test_print_results_with_no_actionable_findings_does_not_crash():
    console = ui.Console(file=io.StringIO(), width=100)
    ui.print_results(console, [Finding("x", Severity.INFO, "a")], {"target": "https://ex.com"})
    assert "Nenhum achado acionável" in console.file.getvalue()


def test_print_results_marks_new_from_baseline_status():
    import dataclasses
    console = ui.Console(file=io.StringIO(), width=100)
    f = dataclasses.replace(Finding("x", Severity.HIGH, "achado"), status="new")
    ui.print_results(console, [f], {})
    assert "(NOVO)" in console.file.getvalue()


@pytest.mark.parametrize("severity,confidence,expected", [
    (Severity.CRITICAL, "high", "alto"), (Severity.HIGH, "medium", "alto"),
    (Severity.HIGH, "low", "moderado"), (Severity.MEDIUM, "high", "moderado"),
    (Severity.LOW, "high", "baixo"), (Severity.INFO, "high", "informativo"),
])
def test_exploitability_tag(severity, confidence, expected):
    assert Finding("c", severity, "t", confidence=confidence).exploitability == expected


def test_exploitability_is_in_to_dict():
    assert Finding("c", Severity.HIGH, "t").to_dict()["exploitability"] == "alto"
