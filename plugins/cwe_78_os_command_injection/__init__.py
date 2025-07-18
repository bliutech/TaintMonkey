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
import os
import sys

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function

import os, sys


SOURCES = []
SANITIZERS = []
SINKS = ["os.popen"]

# Monkey patching

old_popen = os.popen


@patch_function("os.popen")
def new_popen(cmd: TaintedStr, mode: str = "r", buffering: int = -1) -> os._wrap_close:
    if cmd.is_tainted():
        raise TaintException("potential vulnerability")
    return old_popen(cmd, mode, buffering)

# Import the vulnerable application
import dataset.cwe_78_os_command_injection.insecure_novalidation.app as vulnerable_app

# Store original function for restoration
old_open_file_command = vulnerable_app.open_file_command

@patch_function("dataset.cwe_78_os_command_injection.insecure_novalidation.app.open_file_command")
def new_open_file_command(file: TaintedStr):
    return TaintedStr(old_open_file_command(file))


# https://flask.palletsprojects.com/en/stable/testing/
@pytest.fixture()
def app():
    app = vulnerable_app.app

    register_taint_client(app)
    return app

@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def fuzzer(app):
    return DictionaryFuzzer(app, "plugins/cwe_78_os_command_injection/dictionary.txt")


def test_taint_exception(client):
    with pytest.raises(TaintException):
        client.get("/insecure?file=/etc/passwd")


def test_command_injection(client):
    with pytest.raises(TaintException):
        client.get("/insecure?file=example.txt;ls")


def test_fuzz(fuzzer):
    from urllib.parse import urlencode

    counter = 0
    with fuzzer.get_context() as (client, inputs):
        for data in inputs:
            print(f"[Fuzz Attempt {counter}] {data}")
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'file': data})}")
            counter += 1

if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
