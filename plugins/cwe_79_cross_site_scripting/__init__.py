"""
TaintMonkey plugin to detect Cross-Site Scripting (XSS).

CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
https://cwe.mitre.org/data/definitions/79.html


# Dictionary.txt contains common XSS payloads from the following:
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection


# How to run?
From the root of the repository, run the following.

```
PYTHONPATH=. python3 plugins/cwe_79_cross_site_scripting/__init__.py
PYTHONPATH=. pytest -vs plugins/cwe_79_cross_site_scripting/__init__.py
```
"""

import pytest

from taintmonkey import TaintException, TaintMonkey
from taintmonkey.fuzzer import MutationBasedFuzzer, DictionaryFuzzer

import os, sys
from urllib.parse import urlencode

VERIFIERS = [
    "dataset.cwe_79_cross_site_scripting.html_escape_custom_check_response.app.suspicious_input"
]
SANITIZERS = []
SINKS = [
    "dataset.cwe_79_cross_site_scripting.html_escape_custom_check_response.app.say_hi"
]


@pytest.fixture()
def taintmonkey():
    from dataset.cwe_79_cross_site_scripting.html_escape_custom_check_response.app import (
        app,
    )

    tm = TaintMonkey(app, verifiers=VERIFIERS, sanitizers=SANITIZERS, sinks=SINKS)

    fuzzer = DictionaryFuzzer(app, "plugins/cwe_79_cross_site_scripting/corpus.txt")
    tm.set_fuzzer(fuzzer)

    return tm


def test_taint_exception(taintmonkey):
    client = taintmonkey.get_client()
    payload = "<script>alert('XSS')</script>"
    query = urlencode({"name": payload})
    with pytest.raises(TaintException):
        client.get(f"/insecure-xss?{query}")


def test_no_taint_exception(taintmonkey):
    client = taintmonkey.get_client()
    payload = "<script>alert('XSS')</script>"
    query = urlencode({"name": payload})
    client.get(f"/secure-xss?{query}")


def test_fuzz(taintmonkey):
    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure-xss?{urlencode({'name': data})}")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
