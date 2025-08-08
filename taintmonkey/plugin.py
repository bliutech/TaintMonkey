"""
TaintMonkey plugin for pytest.
"""

import pygments
from pygments.lexers import PythonLexer
from pygments.formatters import TerminalFormatter

import pytest

from _pytest._code.code import ReprEntry

from taintmonkey import TaintException

tainted_repr_entries: list[ReprEntry | None] = []

# Gives how far behind of error lines of code context should be given
code_context = 10


__all__ = ["set_code_context"]


def set_code_context(new_code_context: int):
    if isinstance(new_code_context, int):
        global code_context

        code_context = new_code_context


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # Let other hooks run first
    outcome = yield
    report = outcome.get_result()

    if report.when == "call" and report.failed:
        excinfo = call.excinfo
        if excinfo and excinfo.errisinstance(TaintException):
            global tainted_repr_entries

            # Hacky solution to suppress the traceback in terminal
            if len(report.longrepr.reprtraceback.reprentries) > 2:
                report_entry = report.longrepr.reprtraceback.reprentries[-3]

                report.longrepr.reprtraceback.reprentries = (
                    report.longrepr.reprtraceback.reprentries[-1:]
                )
                report.longrepr.reprtraceback.reprentries[-1].lines = []
                report.longrepr.reprtraceback.reprentries[-1].reprfuncargs = None
                report.longrepr.reprtraceback.reprentries[-1].reprlocals = None
                report.longrepr.reprtraceback.reprentries[
                    -1
                ].reprfileloc.path = report_entry.reprfileloc.path
                report.longrepr.reprtraceback.reprentries[
                    -1
                ].reprfileloc.lineno = report_entry.reprfileloc.lineno
            else:
                report_entry = report.longrepr.reprtraceback.reprentries[-1]

            tainted_repr_entries.append(report_entry)


def get_taint_related_reports(terminalreporter):
    failed_reports = terminalreporter.stats.get("failed", [])

    n_taint = "Failed: DID NOT RAISE <class 'taintmonkey.TaintException'>"
    y_taint = "TaintException"

    tainted_reports = []
    for fail_repr in failed_reports:
        fail_repr_str = str(fail_repr.longrepr)
        if y_taint in fail_repr_str and n_taint not in fail_repr_str:
            tainted_reports.append(fail_repr)

    return tainted_reports


def is_function_start(line, error_line):
    phrases = line.split()

    if len(phrases) < 1:
        return False

    error_line_start = error_line.find(error_line.split()[0])
    line_start = line.find(phrases[0])
    if line_start >= error_line_start:
        return False

    if phrases[0] == "def":
        return True
    elif len(phrases) > 1 and phrases[0] == "async" and phrases[1] == "def":
        return True

    return False


def get_function_source_code(file_path, lineno):
    with open(file_path, "r") as f:
        lines = f.readlines()

    lineno -= 1

    source_code = [lines[lineno]]
    while lineno >= 1 and not is_function_start(lines[lineno], source_code[-1]):
        lineno -= 1
        source_code.insert(0, lines[lineno])

    for i in range(len(source_code)):
        if source_code[i][-1:] != "\n":
            source_code[i] += "\n"

    return source_code, lineno + 1


def write_source_code_with_context(terminalreporter, report_entry):
    global code_context

    f_path = report_entry.reprfileloc.path
    lineno = report_entry.reprfileloc.lineno
    source_code, func_start = get_function_source_code(f_path, lineno)

    # Get error index in source code and context start index
    err_index = lineno - func_start
    err_msg_start = err_index - code_context
    if err_msg_start < 0:
        err_msg_start = 0

    # Write line of code with label and context
    terminalreporter.write_line(f"CODE:")
    adjust = len(str(lineno))
    for i in range(err_msg_start, err_index + 1):
        format_line_num = str(func_start + i).rjust(adjust)
        # Highlight the code line using pygments
        highlighted = pygments.highlight(
            source_code[i], PythonLexer(), TerminalFormatter()
        )
        terminalreporter.write(f"{format_line_num} {highlighted}")

    # Write "^^^" director
    taint_message = "TAINT REACHED SINK"
    if len(report_entry.lines) > 1 and all(
        c == "^" for c in "".join(report_entry.lines[-1].split())
    ):
        add_space = len(source_code[err_index]) - len(report_entry.lines[-2]) + adjust
        terminalreporter.write(add_space * " " + report_entry.lines[-1])
        terminalreporter.write_line(f" --> {taint_message}")
    else:
        terminalreporter.write_line(f"^^^ {taint_message} ^^^")


def write_single_taint_report(terminalreporter, report, report_number):
    terminalreporter.write_line(f"TEST: {report.nodeid}")

    global tainted_repr_entries

    if not -1 < report_number < len(tainted_repr_entries):
        return

    report_entry = tainted_repr_entries[report_number]

    terminalreporter.write_line(f"LOCATION: {report_entry.reprfileloc}")

    # Show code with context
    write_source_code_with_context(terminalreporter, report_entry)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    # Check to see if the terminal writer exists
    if not hasattr(terminalreporter, "_tw"):
        return

    tainted_reports = get_taint_related_reports(terminalreporter)
    if len(tainted_reports) < 1:
        return

    terminalreporter.write_sep("=", "TAINT EXCEPTION SUMMARY", purple=True)

    # Iterate through tainted reports
    for i in range(len(tainted_reports)):
        report = tainted_reports[i]

        write_single_taint_report(terminalreporter, report, i)

        # Add empty space if not last
        if i < len(tainted_reports) - 1:
            terminalreporter.write_line("\n")
