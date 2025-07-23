import importlib.util
import inspect


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


def get_function_source_code(filename, function_name):
    spec = importlib.util.spec_from_file_location("module", filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    try:
        func = getattr(module, function_name)
    except AttributeError:
        #Get functions and then recursively search
        pass

    return inspect.getsourcelines(func)


def write_source_code_with_context(terminalreporter, report_entry, code_context):
    f_name = report_entry.reprfileloc.message[3:]
    f_path = report_entry.reprfileloc.path
    source_code, func_start = get_function_source_code(f_path, f_name)

    # Get error index in source code and context start index
    err_index = report_entry.reprfileloc.lineno - func_start
    err_msg_start = err_index - code_context
    if err_msg_start < 0:
        err_msg_start = 0

    # Write line of code with label and context
    terminalreporter.write_line(f"CODE:")
    for i in range(err_msg_start, err_index + 1):
        terminalreporter.write(f"{source_code[i]}")

    # Write "^^^" director
    taint_message = "TAINT REACHED SINK"
    try:
        add_space = len(source_code[err_index]) - len(report_entry.lines[-2]) - 1
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
    if len(tainted_reports) < 1: return

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
