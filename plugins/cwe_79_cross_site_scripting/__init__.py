"""
TaintMonkey plugin to detect Cross-Site Scripting (XSS).

CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
https://cwe.mitre.org/data/definitions/79.html


# Dictionary.txt contains common XSS payloads from the following:
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection


# How to run?
From the root of the repository, run the following.

```
PYTHONPATH=. python3 plugins/cwe_79_xss_1/__init__.py
PYTHONPATH=. pytest -vs plugins/cwe_79_xss_1/__init__.py
```
"""

import pytest

from urllib.parse import urlencode
from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function

import sys

SOURCES = []
SANITIZERS = []
SINKS = ["say_hi"]


import dataset.cwe_79_cross_site_scripting.html_escape_custom_check_response.app

old_say_hi = (
    dataset.cwe_79_cross_site_scripting.html_escape_custom_check_response.app.say_hi
)


@patch_function(
    "dataset.cwe_79_cross_site_scripting.html_escape_custom_check_response.app.say_hi"
)
def new_say_hi(name) -> str:
    if hasattr(name, "is_tainted") and name.is_tainted():
        raise TaintException("potential XSS vulnerability")
    return old_say_hi(name)


@pytest.fixture()
def app():
    from dataset.cwe_79_cross_site_scripting.html_escape_custom_check_response.app import (
        app,
    )

    register_taint_client(app)
    yield (app)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def fuzzer(app):
    return DictionaryFuzzer(app, "plugins/cwe_79_cross_site_scripting/dictionary.txt")


from urllib.parse import urlencode


def test_taint_exception(client):
    payload = "<script>alert('XSS')</script>"
    query = urlencode({"name": payload})
    with pytest.raises(TaintException):
        client.get(f"/insecure-xss?{query}")


def test_no_taint_exception(client):
    payload = "<script>alert('XSS')</script>"
    query = urlencode({"name": payload})
    client.get(f"/secure-xss?{query}")


def test_fuzz(fuzzer):
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure-xss?{urlencode({'name': data})}")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
