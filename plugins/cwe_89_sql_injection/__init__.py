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
from taintmonkey.patch import patch_function

import sys

# Define sources, sanitizers, and sinks
SOURCES = []
SANITIZERS = []
SINKS = [
    "dataset.cwe_89_sql_injection_testcase.cwe_89_sql_injection_testcase1.app.create_insecure_user_query"
]

# Patch utility functions
import dataset.cwe_89_sql_injection_testcase.cwe_89_sql_injection_testcase1.app

old_create_insecure_user_query = dataset.cwe_89_sql_injection_testcase.cwe_89_sql_injection_testcase1.app.create_insecure_user_query


@patch_function(
    "dataset.cwe_89_sql_injection_testcase.cwe_89_sql_injection_testcase1.app.create_insecure_user_query"
)
def new_create_insecure_user_query(username: TaintedStr, password: TaintedStr):
    query_string = (
        f"INSERT INTO user (username, password) VALUES ('{username}', '{password}')"
    )
    if username.is_tainted():
        raise TaintException("potential SQL injection vulnerability in username")
    if password.is_tainted():
        raise TaintException("potential SQL injection vulnerability in password")
    return old_create_insecure_user_query(username, password)


@pytest.fixture()
def app():
    from dataset.cwe_89_sql_injection_testcase.cwe_89_sql_injection_testcase1.app import (
        app,
    )

    register_taint_client(app)
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def fuzzer(app):
    # Corpus of SQL injection payloads
    return DictionaryFuzzer(app, "plugins/cwe_89_sql_injection/dictionary.txt")


def test_taint_exception(client):
    with pytest.raises(TaintException):
        client.post("/insecure-signup?username=admin'--&password=test")


def test_no_taint_exception(client):
    # Expect no exception with secure endpoint
    client.post("/secure-signup?username=admin'--&password=test")


def test_fuzz(fuzzer):
    from urllib.parse import urlencode

    counter = 0
    with fuzzer.get_context() as (client, inputs):
        for data in inputs:
            print(f"\n[Fuzz Attempt {counter}] Testing payload: {data}")
            with pytest.raises(TaintException):
                client.post(
                    f"/insecure-signup?{urlencode({'username': data, 'password': 'test'})}"
                )
            counter += 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
