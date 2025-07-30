"""
TaintMonkey plugin to detect OS Command Injection.

CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
https://cwe.mitre.org/data/definitions/78.html

# How to run?
From the root of the repository, run the following:

    PYTHONPATH=. python3 plugins/cwe_78_os_command_injection/__init__.py
"""

import sys
import os
import pytest
import importlib
from urllib.parse import urlencode

from taintmonkey import TaintException, TaintMonkey
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import original_function


VERIFIERS = [
    "dataset.cwe_78_os_command_injection.secure_novalidation.app.is_safe_path",
    "dataset.cwe_78_os_command_injection.secure_novalidation_system.app.is_safe_path",
    "dataset.cwe_78_os_command_injection.secure_double_extension.app.is_safe_path",
    "dataset.cwe_78_os_command_injection.secure_double_extension_system.app.is_safe_path"
]

SANITIZERS = []

SINKS = ["os.system", "os.popen"]

TEST_CONFIGS = {
    "insecure_novalidation": {
        "app_path": "dataset.cwe_78_os_command_injection.insecure_novalidation.app",
        "route": "/insecure"
    },
    "secure_novalidation": {
        "app_path": "dataset.cwe_78_os_command_injection.secure_novalidation.app",
        "route": "/secure"
    },
    "insecure_novalidation_system": {
        "app_path": "dataset.cwe_78_os_command_injection.insecure_novalidation_system.app",
        "route": "/insecure"
    },
    "secure_novalidation_system": {
        "app_path": "dataset.cwe_78_os_command_injection.secure_novalidation_system.app",
        "route": "/secure"
    },
    "insecure_double_extension": {
        "app_path": "dataset.cwe_78_os_command_injection.insecure_double_extension.app",
        "route": "/insecure"
    },
    "secure_double_extension": {
        "app_path": "dataset.cwe_78_os_command_injection.secure_double_extension.app",
        "route": "/secure"
    },
    "insecure_double_extension_system": {
        "app_path": "dataset.cwe_78_os_command_injection.insecure_double_extension_system.app",
        "route": "/insecure"
    },
    "secure_double_extension_system": {
        "app_path": "dataset.cwe_78_os_command_injection.secure_double_extension_system.app",
        "route": "/secure"
    }
}


@pytest.fixture
def taintmonkey(request):
    config = TEST_CONFIGS[request.param]
    app_module = importlib.import_module(config["app_path"])
    app = app_module.app

    tm = TaintMonkey(app, verifiers=VERIFIERS, sanitizers=SANITIZERS, sinks=SINKS)
    fuzzer = DictionaryFuzzer(app, "plugins/cwe_78_os_command_injection/corpus.txt")
    tm.set_fuzzer(fuzzer)

    @tm.patch.function(f"{config['app_path']}.open_file_command")
    def new_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    tm.route = config["route"]
    return tm


@pytest.mark.parametrize("taintmonkey", ["insecure_novalidation"], indirect=True)
def test_taint_exception(taintmonkey):
    client = taintmonkey.get_client()
    with pytest.raises(TaintException):
        client.get(f"{taintmonkey.route}?file=/etc/passwd")


@pytest.mark.parametrize("taintmonkey", ["insecure_novalidation"], indirect=True)
def test_command_injection(taintmonkey):
    client = taintmonkey.get_client()
    with pytest.raises(TaintException):
        client.get(f"{taintmonkey.route}?file=example.txt;ls")


@pytest.mark.parametrize("taintmonkey", ["insecure_novalidation"], indirect=True)
def test_fuzz_insecure_novalidation(taintmonkey):
    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"{taintmonkey.route}?{urlencode({'file': data})}")


@pytest.mark.parametrize("taintmonkey", ["secure_novalidation"], indirect=True)
def test_fuzz_secure_novalidation(taintmonkey):
    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            client.get(f"{taintmonkey.route}?{urlencode({'file': data})}")


@pytest.mark.parametrize("taintmonkey", ["insecure_novalidation_system"], indirect=True)
def test_fuzz_insecure_novalidation_system(taintmonkey):
    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"{taintmonkey.route}?{urlencode({'file': data})}")


@pytest.mark.parametrize("taintmonkey", ["secure_novalidation_system"], indirect=True)
def test_fuzz_secure_novalidation_system(taintmonkey):
    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            client.get(f"{taintmonkey.route}?{urlencode({'file': data})}")


@pytest.mark.parametrize("taintmonkey", ["insecure_double_extension"], indirect=True)
def test_fuzz_insecure_double_extension(taintmonkey):
    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"{taintmonkey.route}?{urlencode({'file': data})}")


@pytest.mark.parametrize("taintmonkey", ["secure_double_extension"], indirect=True)
def test_fuzz_secure_double_extension(taintmonkey):
    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            client.get(f"{taintmonkey.route}?{urlencode({'file': data})}")


@pytest.mark.parametrize("taintmonkey", ["insecure_double_extension_system"], indirect=True)
def test_fuzz_insecure_double_extension_system(taintmonkey):
    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"{taintmonkey.route}?{urlencode({'file': data})}")


@pytest.mark.parametrize("taintmonkey", ["secure_double_extension_system"], indirect=True)
def test_fuzz_secure_double_extension_system(taintmonkey):
    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            client.get(f"{taintmonkey.route}?{urlencode({'file': data})}")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))

