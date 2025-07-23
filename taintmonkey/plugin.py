"""
TaintMonkey plugin for pytest.
"""


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

    try:
        error_line_start = error_line.find(error_line.split()[0])
        line_start = line.find(phrases[0])
        if line_start >= error_line_start:
            return False
    except IndexError:
        return False

    try:
        if phrases[0] == "def":
            return True
        elif phrases[0] == "async" and phrases[1] == "def":
            return True
    except IndexError:
        return False

    return False


def get_function_source_code(file_path, lineno):
    with open(file_path, "r") as f:
        lines = f.readlines()

    lineno -= 1

    source_code = [lines[lineno]]
    while lineno >= 1 and not is_function_start(lines[lineno], source_code[-1]):
        lineno -= 1
        source_code.insert(0, lines[lineno])

    return source_code, lineno + 1


def write_source_code_with_context(terminalreporter, report_entry, code_context):
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
        terminalreporter.write(f"{format_line_num} {source_code[i]}")

    # Write "^^^" director
    taint_message = "TAINT REACHED SINK"
    try:
        add_space = len(source_code[err_index]) - len(report_entry.lines[-2]) + 2
        terminalreporter.write(add_space * " " + report_entry.lines[-1])
        terminalreporter.write_line(f" --> {taint_message}")
    except IndexError:
        # For some reason not all repr entries generate the "^^^" symbols
        terminalreporter.write_line(f"^^^{taint_message}^^^")


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    # Gives how far behind of error lines of code context should be given
    code_context = 5

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

        terminalreporter.write_line(f"TEST: {report.nodeid}")

        report_entry = report.longrepr.reprtraceback.reprentries[-2]

        terminalreporter.write_line(f"LOCATION: {report_entry.reprfileloc}")

        # Show code with context
        write_source_code_with_context(terminalreporter, report_entry, code_context)

        # Add empty line if not last
        if i < len(tainted_reports) - 1:
            terminalreporter.write_line("\n")
