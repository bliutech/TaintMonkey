"""
TaintMonkey plugin to detect OS Command Injection.

CWE-918: Server-Side Request Forgery (SSRF)
https://cwe.mitre.org/data/definitions/918.html

# How to run?
From the root of the repository, run the following.

```
PYTHONPATH=. python3 plugins/cwe_918_server_side_request_forgery/__init__.py
```
"""

import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function
from urllib.parse import urlencode

import sys

SOURCES = ["get_url()"]

SANITIZERS = ["check_allow_list"]

SINKS = ["http_request(url)"]

import dataset.cwe_918_server_side_request_forgery.urllib_allow_list_httpclient.app

# Patch sink
old_http_request = dataset.cwe_918_server_side_request_forgery.urllib_allow_list_httpclient.app.http_request


@patch_function(
    "dataset.cwe_918_server_side_request_forgery.urllib_allow_list_httpclient.app.http_request"
)
def new_http_request(url):
    if url.is_tainted():
        raise TaintException("potential vulnerability")
    return old_http_request(url)


# Patch Source
old_get_url = (
    dataset.cwe_918_server_side_request_forgery.urllib_allow_list_httpclient.app.get_url
)


@patch_function(
    "dataset.cwe_918_server_side_request_forgery.urllib_allow_list_httpclient.app.get_url"
)
def new_get_url():
    return TaintedStr(old_get_url())


# Patch Sanitizer
old_check_allow_list = dataset.cwe_918_server_side_request_forgery.urllib_allow_list_httpclient.app.check_allow_list


@patch_function(
    "dataset.cwe_918_server_side_request_forgery.urllib_allow_list_httpclient.app.check_allow_list"
)
def new_check_allow_list(url):
    url.sanitize()
    return old_check_allow_list(url)


# https://flask.palletsprojects.com/en/stable/testing/
@pytest.fixture()
def app():
    from dataset.cwe_918_server_side_request_forgery.urllib_allow_list_httpclient.app import (
        app,
    )

    register_taint_client(app)
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def fuzzer(app):
    # Corpus from https://hacktricks.boitatech.com.br/pentesting-web/ssrf-server-side-request-forgery
    return DictionaryFuzzer(
        app, "plugins/cwe_918_server_side_request_forgery/dictionary.txt"
    )


def test_taint_exception(client):
    with pytest.raises(TaintException):
        client.get(f"/insecure?{urlencode({'url': 'https://evil.com/secure'})}")


def test_no_taint_exception(client):
    # Expect no exception
    client.get(f"/secure?{urlencode({'url': 'https://allowed.com/safe'})}")


def test_fuzz(fuzzer):
    counter = 0
    with fuzzer.get_context() as (client, inputs):
        for data in inputs:
            print(f"[Fuzz Attempt {counter}] {data}")
            # Demonstrating fuzzer capabilities
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'url': data})}")
            counter += 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
