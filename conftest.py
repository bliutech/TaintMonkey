def pytest_terminal_summary(terminalreporter, exitstatus, config):

    # Check to see if the terminal writer exists
    if not hasattr(terminalreporter, '_tw'):
        return

    #Get the taint exception error reports
    failed_reports = terminalreporter.stats.get('failed', [])
    not_tainted_string = "Failed: DID NOT RAISE <class 'taintmonkey.TaintException'>"
    taint_related_string = "TaintException"
    tainted_reports = []
    for failed_report in failed_reports:
        if taint_related_string in str(failed_report.longrepr) and not_tainted_string not in str(failed_report.longrepr):
            tainted_reports.append(failed_report)
    if len(tainted_reports) == 0:
        return

    #Write separation line
    terminalreporter.write_sep("=", "TAINT EXCEPTION SUMMARY", purple=True)

    #Iterate through tainted reports
    for i in range(len(tainted_reports)):

        #Set report
        report = tainted_reports[i]

        #Write the report name
        terminalreporter.write_line(f"TEST: {report.nodeid}")

        #Get the report entries and related entry
        report_entries = report.longrepr.chain[0][0].reprentries
        report_entry = report_entries[len(report_entries) - 2]

        #Write the file location
        #terminalreporter.write_line(f"VULNERABILITY: {report.nodeid}")
        report_loc = report_entry.reprfileloc
        terminalreporter.write_line(f"LOCATION: {report_loc}")

        #Write specific source code
        terminalreporter.write_line(f"CODE:")
        report_lines = report_entry.lines
        for line in report_lines:
            terminalreporter.write_line(line)

        #Add empty line if not last
        if i != len(tainted_reports) - 1:
            terminalreporter.write_line("\n")