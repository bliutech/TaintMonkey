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
SOURCES = [
    "dataset.cwe_89_sql_injection.testcase1_insecure_signup.app.create_insecure_user_query"
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


@patch_function("sqlalchemy.orm.session.Session.execute")
def new_session_execute(
    statement: Executable,
    params: Optional[_CoreAnyExecuteParams] = None,
    *,
    execution_options: OrmExecuteOptionsParameter = util.EMPTY_DICT,
    bind_arguments: Optional[_BindArguments] = None,
    _parent_execute_state: Optional[Any] = None,
    _add_event: Optional[Any] = None,
) -> Result[Any]:
    print("Gurt")
    return old_session_execute(
        statement=statement,
        params=params,
        execution_options=execution_options,
        bind_arguments=bind_arguments,
        _parent_execute_state=_parent_execute_state,
        _add_event=_add_event,
    )


# Patch utility functions
import dataset.cwe_89_sql_injection.testcase1_insecure_signup.app

old_create_insecure_user_query = dataset.cwe_89_sql_injection.testcase1_insecure_signup.app.create_insecure_user_query


@patch_function(
    "dataset.cwe_89_sql_injection.testcase1_insecure_signup.app.create_insecure_user_query"
)
def new_create_insecure_user_query(username: TaintedStr, password: TaintedStr):
    if username.is_tainted() or password.is_tainted():
        return TaintedStr(old_create_insecure_user_query(username, password))
    return old_create_insecure_user_query(username, password)


@pytest.fixture()
def app():
    from dataset.cwe_89_sql_injection.testcase1_insecure_signup.app import (
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
    return DictionaryFuzzer(app, "plugins/cwe_89_sql_injection/corpus.txt")


def test_taint_exception(client):
    with pytest.raises(TaintException):
        client.post("/insecure-signup?username=admin'--&password=test")


def test_no_taint_exception(client):
    # Expect no exception with secure endpoint
    client.post("/secure-signup?username=admin'--&password=test")


# TODO(bliutech): this test case is broken, need to fix it
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
