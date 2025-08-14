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

from taintmonkey import TaintException, TaintMonkey
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import original_function

import sys
from urllib.parse import urlencode


VERIFIERS = [
    "dataset.cwe_918_server_side_request_forgery.furl_allow_list_httpclient.app.check_allow_list",
    "dataset.cwe_918_server_side_request_forgery.furl_allow_list_requestsget.app.check_allow_list",
    "dataset.cwe_918_server_side_request_forgery.furl_deny_list_httpclient.app.check_deny_list",
    "dataset.cwe_918_server_side_request_forgery.furl_deny_list_requestsget.app.check_deny_list",
    "dataset.cwe_918_server_side_request_forgery.urllib_allow_list_httpclient.app.check_allow_list",
    "dataset.cwe_918_server_side_request_forgery.urllib_allow_list_requestsget.app.check_allow_list",
    "dataset.cwe_918_server_side_request_forgery.urllib_deny_list_httpclient.app.check_deny_list",
    "dataset.cwe_918_server_side_request_forgery.urllib_deny_list_requestsget.app.check_deny_list",
    "dataset.cwe_918_server_side_request_forgery.yarl_allow_list_requestsget.app.check_allow_list",
    "dataset.cwe_918_server_side_request_forgery.yarl_deny_list_requestsget.app.check_deny_list",
]
SANITIZERS = []
SINKS = [
    "dataset.cwe_918_server_side_request_forgery.furl_allow_list_httpclient.app.http_request",
    "dataset.cwe_918_server_side_request_forgery.furl_allow_list_requestsget.app.http_request",
    "dataset.cwe_918_server_side_request_forgery.furl_deny_list_httpclient.app.http_request",
    "dataset.cwe_918_server_side_request_forgery.furl_deny_list_requestsget.app.http_request",
    "dataset.cwe_918_server_side_request_forgery.urllib_allow_list_httpclient.app.http_request",
    "dataset.cwe_918_server_side_request_forgery.urllib_allow_list_requestsget.app.http_request",
    "dataset.cwe_918_server_side_request_forgery.urllib_deny_list_httpclient.app.http_request",
    "dataset.cwe_918_server_side_request_forgery.urllib_deny_list_requestsget.app.http_request",
    "dataset.cwe_918_server_side_request_forgery.yarl_allow_list_requestsget.app.http_request",
    "dataset.cwe_918_server_side_request_forgery.yarl_deny_list_requestsget.app.http_request",
]


@pytest.fixture()
def taintmonkey():
    from dataset.cwe_918_server_side_request_forgery.furl_allow_list_httpclient.app import (
        app,
    )

    tm = TaintMonkey(app, verifiers=VERIFIERS, sanitizers=SANITIZERS, sinks=SINKS)

    fuzzer = DictionaryFuzzer(
        app, "plugins/cwe_918_server_side_request_forgery/corpus.txt"
    )
    tm.set_fuzzer(fuzzer)

    # Manually Patched Sources
    @tm.patch.function(
        "dataset.cwe_918_server_side_request_forgery.furl_allow_list_httpclient.app.get_url",
    )
    def new_get_url():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_918_server_side_request_forgery.furl_allow_list_requestsget.app.get_url",
    )
    def new_get_url():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_918_server_side_request_forgery.furl_deny_list_httpclient.app.get_url",
    )
    def new_get_url():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_918_server_side_request_forgery.furl_deny_list_requestsget.app.get_url",
    )
    def new_get_url():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_918_server_side_request_forgery.urllib_allow_list_httpclient.app.get_url",
    )
    def new_get_url():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_918_server_side_request_forgery.urllib_allow_list_requestsget.app.get_url",
    )
    def new_get_url():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_918_server_side_request_forgery.urllib_deny_list_httpclient.app.get_url",
    )
    def new_get_url():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_918_server_side_request_forgery.urllib_deny_list_requestsget.app.get_url",
    )
    def new_get_url():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_918_server_side_request_forgery.yarl_allow_list_requestsget.app.get_url",
    )
    def new_get_url():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_918_server_side_request_forgery.yarl_deny_list_requestsget.app.get_url",
    )
    def new_get_url():
        return TaintedStr(original_function())

    return tm


# Test & Fuzzer for Furl Allow List HTTPClient
def test_fuzz_furl_allow_httpclient(taintmonkey):
    from dataset.cwe_918_server_side_request_forgery.furl_allow_list_httpclient.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'url': data})}")


# Test & Fuzzer for Furl Allow List RequestsGet
def test_fuzz_furl_allow_list_requestsget(taintmonkey):
    from dataset.cwe_918_server_side_request_forgery.furl_allow_list_requestsget.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'url': data})}")


# Test & Fuzzer for Furl Deny List HTTPClient
def test_fuzz_furl_deny_list_httpclient(taintmonkey):
    from dataset.cwe_918_server_side_request_forgery.furl_deny_list_httpclient.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'url': data})}")


# Test & Fuzzer for Furl Deny List RequestsGet
def test_fuzz_furl_deny_list_requestsget(taintmonkey):
    from dataset.cwe_918_server_side_request_forgery.furl_deny_list_requestsget.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'url': data})}")


# Test & Fuzzer for Urllib Allow List HTTPClient
def test_fuzz_urllib_allow_httpclient(taintmonkey):
    from dataset.cwe_918_server_side_request_forgery.urllib_allow_list_httpclient.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'url': data})}")


# Test & Fuzzer for Urllib Allow List RequestsGet
def test_fuzz_urllib_allow_list_requestsget(taintmonkey):
    from dataset.cwe_918_server_side_request_forgery.urllib_allow_list_requestsget.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'url': data})}")


# Test & Fuzzer for Urllib Deny List HTTPClient
def test_fuzz_urllib_deny_list_httpclient(taintmonkey):
    from dataset.cwe_918_server_side_request_forgery.urllib_deny_list_httpclient.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'url': data})}")


# Test & Fuzzer for Urllib Deny List RequestsGet
def test_fuzz_urllib_deny_list_requestsget(taintmonkey):
    from dataset.cwe_918_server_side_request_forgery.urllib_deny_list_requestsget.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'url': data})}")


# Test & Fuzzer for Yarl Allow List RequestsGet
def test_fuzz_yarl_allow_list_requestsget(taintmonkey):
    from dataset.cwe_918_server_side_request_forgery.yarl_allow_list_requestsget.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'url': data})}")


# Test & Fuzzer for Yarl Deny List RequestsGet
def test_fuzz_yarl_deny_list_requestsget(taintmonkey):
    from dataset.cwe_918_server_side_request_forgery.yarl_deny_list_requestsget.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'url': data})}")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
