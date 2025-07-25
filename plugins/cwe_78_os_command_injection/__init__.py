"""
TaintMonkey plugin to detect OS Command Injection.

CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
https://cwe.mitre.org/data/definitions/78.html

# How to run?
From the root of the repository, run the following.

```
PYTHONPATH=. python3 plugins/cwe_78_os_command_injection/__init__.py
```
"""

import pytest

from taintmonkey import TaintException, TaintMonkey
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function, original_function

import os, sys
from urllib.parse import urlencode


VERIFIERS = []
SANITIZERS = []
SINKS = ["os.popen"]


@patch_function(
    "dataset.cwe_78_os_command_injection.insecure_novalidation.app.open_file_command"
)
def new_open_file_command(file: TaintedStr):
    return TaintedStr(original_function(file))


@pytest.fixture()
def taintmonkey():
    from dataset.cwe_78_os_command_injection.insecure_novalidation.app import app

    tm = TaintMonkey(app, verifiers=VERIFIERS, sanitizers=SANITIZERS, sinks=SINKS)

    fuzzer = DictionaryFuzzer(app, "plugins/cwe_78_os_command_injection/corpus.txt")
    tm.set_fuzzer(fuzzer)

    return tm


def test_taint_exception(taintmonkey):
    client = taintmonkey.get_client()
    with pytest.raises(TaintException):
        client.get("/insecure?file=/etc/passwd")


def test_command_injection(taintmonkey):
    client = taintmonkey.get_client()
    with pytest.raises(TaintException):
        client.get(f"/insecure?file=example.txt;ls")


def test_fuzz(taintmonkey):
    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'file': data})}")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
