"""
TaintMonkey plugin to detect SQL Injection.

CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
https://cwe.mitre.org/data/definitions/89.html

# How to run?
From the root of the repository, run the following.

```
PYTHONPATH=. python3 plugins/cwe_89_sql_injection/__init__.py
```
"""

import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import original_function

import sys

# Define sources, sanitizers, and sinks
VERIFIERS = [
    "dataset.secure_alphamumeric_signup.app.pattern_match",
    "dataset.secure_alphanumeric_login.app.pattern_match",
    "dataset.secure_login.app.sanitize_input",
    "dataset.secure_second_layer.app.sanitize_query",
    "dataset.secure_signup.app.sanitize_input",
]
SANITIZERS = []
SINKS = []

# Monkey patching
import sqlalchemy
from typing import Any, Optional
from sqlalchemy.sql.base import Executable
from sqlalchemy.engine.interfaces import _CoreAnyExecuteParams
from sqlalchemy.orm._typing import OrmExecuteOptionsParameter
from sqlalchemy import util
from sqlalchemy.orm.session import _BindArguments
from sqlalchemy.engine import Result

old_session_execute = sqlalchemy.orm.session.Session.execute


@pytest.fixture()
def taintmonkey():
    from dataset.cwe_89_sql_injection.insecure_alphanumeric_signup.app import app

    tm = TaintMonkey(app, verifiers=VERIFIERS, sanitizers=SANITIZERS, sinks=SINKS)

    fuzzer = DictionaryFuzzer(app, "plugins/cwe_89_sql_injection/corpus.txt")
    tm.set_fuzzer(fuzzer)

    @tm.patch.function(
        "dataset.cwe_89_sql_injection.insecure_alphanumeric_login.app.pattern_match"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_89_sql_injection.secure_alphanumeric_login.app.pattern_match"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_89_sql_injection.insecure_alphanumeric_signup.app.pattern_match"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_89_sql_injection.secure_alphanumeric_signup.app.pattern_match"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function("dataset.cwe_89_sql_injection.insecure_login.app.insecure_input")
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function("dataset.cwe_89_sql_injection.secure_login.app.sanitize_input")
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_89_sql_injection.insecure_signup.app.create_insecure_user_query"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function("dataset.cwe_89_sql_injection.secure_signup.app.sanitize_input")
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_89_sql_injection.insecure_second_layer.app.insecure_query"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_89_sql_injection.secure_second_layer.app.sanitize_query"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    return tm

def test_fuzz_insecure_alphanumeric_login(taintmonkey):
    from dataset.cwe_89_sql_injection.insecure_alphanumeric_login.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_secure_alphanumeric_login(taintmonkey):
    from dataset.cwe_89_sql_injection.secure_alphanumeric_login.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_insecure_alphanumeric_signup(taintmonkey):
    from dataset.cwe_89_sql_injection.insecure_alphanumeric_signup.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_secure_alphanumeric_signup(taintmonkey):
    from dataset.cwe_89_sql_injection.secure_alphanumeric_signup.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_insecure_login(taintmonkey):
    from dataset.cwe_89_sql_injection.insecure_login.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_secure_login(taintmonkey):
    from dataset.cwe_89_sql_injection.secure_login.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_insecure_signup(taintmonkey):
    from dataset.cwe_89_sql_injection.insecure_signup.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_secure_signup(taintmonkey):
    from dataset.cwe_89_sql_injection.secure_signup.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_insecure_second_layer(taintmonkey):
    from dataset.cwe_89_sql_injection.insecure_second_layer.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_secure_second_layer(taintmonkey):
    from dataset.cwe_89_sql_injection.secure_second_layer.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
