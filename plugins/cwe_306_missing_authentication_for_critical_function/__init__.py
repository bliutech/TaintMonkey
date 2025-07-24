"""
TaintMonkey plugin to detect bad authentication practices

CWE-287: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
https://cwe.mitre.org/data/definitions/287.html

# How to run?
From the root of the repository, run the following.

```
PYTHONPATH=. python3 plugins/cwe_287_improper_authentication/__init__.py
```
"""

import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function

import sys

# These lists have no impact (for now)
SOURCES = ["get_username"]

SANITIZERS = ["user_taken"]

SINKS = ["sign_up"]


# Patch utility functions
import dataset.cwe_306_missing_authentication_for_critical_function.sign_up_bypass.app


old_get_username = dataset.cwe_306_missing_authentication_for_critical_function.sign_up_bypass.app.get_username


@patch_function(
    "dataset.cwe_306_missing_authentication_for_critical_function.sign_up_bypass.app.get_username"
)
def new_get_username(this_request):
    return TaintedStr(old_get_username(this_request))


old_user_taken = dataset.cwe_306_missing_authentication_for_critical_function.sign_up_bypass.app.user_taken


@patch_function(
    "dataset.cwe_306_missing_authentication_for_critical_function.sign_up_bypass.app.user_taken"
)
def new_user_taken(user_given: TaintedStr, database_given):
    user_given.sanitize()
    return old_user_taken(user_given, database_given)


old_sign_up = dataset.cwe_306_missing_authentication_for_critical_function.sign_up_bypass.app.sign_up


@patch_function(
    "dataset.cwe_306_missing_authentication_for_critical_function.sign_up_bypass.app.sign_up"
)
def new_sign_up(username: TaintedStr, password, user_database):
    if username.is_tainted():
        raise TaintException("potential vulnerability")
    return old_sign_up(username, password, user_database)


# https://flask.palletsprojects.com/en/stable/testing/
@pytest.fixture()
def app():
    from dataset.cwe_306_missing_authentication_for_critical_function.sign_up_bypass.app import (
        app,
    )

    register_taint_client(app)

    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def fuzzer(app):
    return DictionaryFuzzer(
        app,
        "plugins/cwe_306_missing_authentication_for_critical_function/dictionary.txt",
    )


def test_taint_exception(client):
    with pytest.raises(TaintException):
        client.post(
            "/insecure/signup",
            data={
                "username": "alice",
                "password": "alice123",
            },
        )


def test_no_taint_exception(client):
    # Expect no exception
    client.post(
        "/secure/signup",
        data={
            "username": "alice",
            "password": "alice123",
        },
    )


# TODO(bliutech): need to clean up this test case. Having multiple fuzzers in the same test is not a good practice.
def test_fuzz(fuzzer):
    print("\n\nInsecure Fuzz Start")
    counter = 0
    with fuzzer.get_context() as (client, inputs):
        for data in inputs:
            print(f"[Fuzz Attempt {counter}] {data}")
            # Demonstrating fuzzer capabilities
            with pytest.raises(TaintException):
                client.post(
                    "/insecure/signup",
                    data={
                        "username": data,
                        "password": "takeover_password",
                    },
                )
            counter += 1
    print("Insecure Fuzz Finished")

    print("\n\nSecure Fuzz Start")
    counter = 0
    with fuzzer.get_context() as (client, inputs):
        for data in inputs:
            print(f"[Fuzz Attempt {counter}] {data}")
            # Demonstrating fuzzer capabilities
            client.post(
                "/secure/signup",
                data={
                    "username": data,
                    "password": "takeover_password",
                },
            )
            counter += 1
    print("Secure Fuzz Finished")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
