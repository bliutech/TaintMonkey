import pytest


def test_taint_summary_output(pytester):
    # Simulate a test file that raises TaintException
    pytester.makepyfile("""
        import pytest

        class TaintException(Exception):
            pass

        def test_taint():
            def sink():
                raise TaintException("Taint reached sink")
            sink()
    """)

    # Inject the plugin code (registering as conftest or plugin import)
    pytester.makeconftest("""
        pytest_plugins = ["taintmonkey.plugin"]
    """)

    # Run pytest and capture results
    result = pytester.runpytest()

    # Assert that our plugin's summary shows up
    result.stdout.fnmatch_lines(
        [
            "*= TAINT EXCEPTION SUMMARY =*",
            "*TEST: test_taint_summary_output.py::test_taint*",
            "*LOCATION:*",
            "*TAINT REACHED SINK*",
        ]
    )
