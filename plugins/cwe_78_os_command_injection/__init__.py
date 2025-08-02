"""
TaintMonkey plugin to detect OS Command Injection.

CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
https://cwe.mitre.org/data/definitions/78.html

# How to run?
From the root of the repository, run the following:

    PYTHONPATH=. python3 plugins/cwe_78_os_command_injection/__init__.py
"""

import pytest
import sys
from urllib.parse import urlencode

from taintmonkey import TaintException, TaintMonkey
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import original_function

VERIFIERS = [

]
SANITIZERS = []
SINKS = ["os.system", "os.popen"]


@pytest.fixture()
def taintmonkey():
    from dataset.cwe_78_os_command_injection.insecure_novalidation.app import app

    tm = TaintMonkey(app, verifiers=VERIFIERS, sanitizers=SANITIZERS, sinks=SINKS)

    fuzzer = DictionaryFuzzer(app, "plugins/cwe_78_os_command_injection/corpus.txt")
    tm.set_fuzzer(fuzzer)

    @tm.patch.function(
        "dataset.cwe_78_os_command_injection.insecure_novalidation.app.open_file_command"
    )
    def patched_open_file_command(file: TaintedStr):
        command = TaintedStr(original_function(file))
        if not file.is_tainted():
            command.sanitize()
        return command

    @tm.patch.function(
        "dataset.cwe_78_os_command_injection.secure_novalidation.app.open_file_command"
    )
    def patched_open_file_command(file: TaintedStr):
        command = TaintedStr(original_function(file))
        if not file.is_tainted():
            command.sanitize()
        return command

    @tm.patch.function(
        "dataset.cwe_78_os_command_injection.secure_novalidation.app.is_safe_path"
    )
    def patched_is_safe_path(path):
        # path.sanitize()
        # print(f"\n\nhello\n\n")
        return original_function(path)

    @tm.patch.function(
        "dataset.cwe_78_os_command_injection.insecure_novalidation_system.app.open_file_command"
    )
    def patched_open_file_command(file: TaintedStr):
        command = TaintedStr(original_function(file))
        if not file.is_tainted():
            command.sanitize()
        return command

    @tm.patch.function(
        "dataset.cwe_78_os_command_injection.secure_novalidation_system.app.open_file_command"
    )
    def patched_open_file_command(file: TaintedStr):
        command = TaintedStr(original_function(file))
        if not file.is_tainted():
            command.sanitize()
        return command

    @tm.patch.function(
        "dataset.cwe_78_os_command_injection.insecure_double_extension.app.open_file_command"
    )
    def patched_open_file_command(file: TaintedStr):
        command = TaintedStr(original_function(file))
        if not file.is_tainted():
            command.sanitize()
        return command

    @tm.patch.function(
        "dataset.cwe_78_os_command_injection.secure_double_extension.app.open_file_command"
    )
    def patched_open_file_command(file: TaintedStr):
        command = TaintedStr(original_function(file))
        if not file.is_tainted():
            command.sanitize()
        return command

    @tm.patch.function(
        "dataset.cwe_78_os_command_injection.insecure_double_extension_system.app.open_file_command"
    )
    def patched_open_file_command(file: TaintedStr):
        command = TaintedStr(original_function(file))
        if not file.is_tainted():
            command.sanitize()
        return command
    
    @tm.patch.function(
        "dataset.cwe_78_os_command_injection.secure_double_extension_system.app.open_file_command"
    )
    def patched_open_file_command(file: TaintedStr):
        command = TaintedStr(original_function(file))
        if not file.is_tainted():
            command.sanitize()
        return command

    return tm


def test_fuzz_insecure_novalidation(taintmonkey):
    from dataset.cwe_78_os_command_injection.insecure_novalidation.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'file': data})}")


def test_fuzz_secure_novalidation(taintmonkey):
    from dataset.cwe_78_os_command_injection.secure_novalidation.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


# def test_fuzz_insecure_novalidation_system(taintmonkey):
#     from dataset.cwe_78_os_command_injection.insecure_novalidation_system.app import app

#     taintmonkey.set_app(app)

#     with taintmonkey.get_fuzzer().get_context() as (client, get_input):
#         for data in get_input():
#             with pytest.raises(TaintException):
#                 client.get(f"/insecure?{urlencode({'file': data})}")


# def test_fuzz_secure_novalidation_system(taintmonkey):
#     from dataset.cwe_78_os_command_injection.secure_novalidation_system.app import app

#     taintmonkey.set_app(app)

#     with taintmonkey.get_fuzzer().get_context() as (client, get_input):
#         for data in get_input():
#             client.get(f"/secure?{urlencode({'file': data})}")


# def test_fuzz_insecure_double_extension(taintmonkey):
#     from dataset.cwe_78_os_command_injection.insecure_double_extension.app import app

#     taintmonkey.set_app(app)

#     with taintmonkey.get_fuzzer().get_context() as (client, get_input):
#         for data in get_input():
#             with pytest.raises(TaintException):
#                 client.get(f"/insecure?{urlencode({'file': data})}")


# def test_fuzz_secure_double_extension(taintmonkey):
#     from dataset.cwe_78_os_command_injection.secure_double_extension.app import app

#     taintmonkey.set_app(app)

#     with taintmonkey.get_fuzzer().get_context() as (client, get_input):
#         for data in get_input():
#             client.get(f"/secure?{urlencode({'file': data})}")


# def test_fuzz_insecure_double_extension_system(taintmonkey):
#     from dataset.cwe_78_os_command_injection.insecure_double_extension_system.app import (
#         app,
#     )

#     taintmonkey.set_app(app)

#     with taintmonkey.get_fuzzer().get_context() as (client, get_input):
#         for data in get_input():
#             with pytest.raises(TaintException):
#                 client.get(f"/insecure?{urlencode({'file': data})}")


# def test_fuzz_secure_double_extension_system(taintmonkey):
#     from dataset.cwe_78_os_command_injection.secure_double_extension_system.app import (
#         app,
#     )

#     taintmonkey.set_app(app)

#     with taintmonkey.get_fuzzer().get_context() as (client, get_input):
#         for data in get_input():
#             client.get(f"/secure?{urlencode({'file': data})}")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
