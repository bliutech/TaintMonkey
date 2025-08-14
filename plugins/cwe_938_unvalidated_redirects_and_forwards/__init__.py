"""
TaintMonkey plugin to detect Unvalidated Redirects and Forwards.

CWE CATEGORY: OWASP Top Ten 2013 Category A10 - Unvalidated Redirects and Forwards
https://cwe.mitre.org/data/definitions/928.html

CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
https://cwe.mitre.org/data/definitions/601.html

# How to run?
From the root of the repository, run the following.

```
PYTHONPATH=. python3 plugins/cwe_938_unvalidated_redirects_and_forwards/__init__.py
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
    "dataset.cwe_938_unvalidated_redirects_and_forwards.furl_allow_list_relative_paths.app.check_allow_path",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.furl_allow_list_urls.app.check_allow_list",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.furl_deny_list_urls.app.check_deny_list",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.requests_allow_list.app.check_allow_list",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_relative_paths.app.check_allow_path",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_urls.app.check_allow_list",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_deny_list_urls.app.check_deny_list",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.yarl_allow_list_relative_paths.app.check_allow_path",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.yarl_allow_list_urls.app.check_allow_list",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.yarl_deny_list_urls.app.check_deny_list",
]
SANITIZERS = []
SINKS = [
    "dataset.cwe_938_unvalidated_redirects_and_forwards.furl_allow_list_relative_paths.app.redirect_to",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.furl_allow_list_urls.app.redirect_to",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.furl_deny_list_urls.app.redirect_to",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.requests_allow_list.app.redirect_to",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_relative_paths.app.redirect_to",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_urls.app.redirect_to",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_deny_list_urls.app.redirect_to",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.yarl_allow_list_relative_paths.app.redirect_to",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.yarl_allow_list_urls.app.redirect_to",
    "dataset.cwe_938_unvalidated_redirects_and_forwards.yarl_deny_list_urls.app.redirect_to",
]


@pytest.fixture()
def taintmonkey():
    from dataset.cwe_938_unvalidated_redirects_and_forwards.furl_allow_list_relative_paths.app import (
        app,
    )

    tm = TaintMonkey(app, verifiers=VERIFIERS, sanitizers=SANITIZERS, sinks=SINKS)

    fuzzer = DictionaryFuzzer(
        app, "plugins/cwe_938_unvalidated_redirects_and_forwards/corpus.txt"
    )
    tm.set_fuzzer(fuzzer)

    # Manually Patched Sources
    @tm.patch.function(
        "dataset.cwe_938_unvalidated_redirects_and_forwards.furl_allow_list_relative_paths.app.get_path"
    )
    def new_get_path():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_938_unvalidated_redirects_and_forwards.furl_allow_list_urls.app.get_url"
    )
    def new_get_path():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_938_unvalidated_redirects_and_forwards.furl_deny_list_urls.app.get_url"
    )
    def new_get_path():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_938_unvalidated_redirects_and_forwards.requests_allow_list.app.get_url"
    )
    def new_get_path():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_relative_paths.app.get_path"
    )
    def new_get_path():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_urls.app.get_url"
    )
    def new_get_path():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_deny_list_urls.app.get_url"
    )
    def new_get_path():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_938_unvalidated_redirects_and_forwards.yarl_allow_list_relative_paths.app.get_path"
    )
    def new_get_path():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_938_unvalidated_redirects_and_forwards.yarl_allow_list_urls.app.get_url"
    )
    def new_get_path():
        return TaintedStr(original_function())

    @tm.patch.function(
        "dataset.cwe_938_unvalidated_redirects_and_forwards.yarl_deny_list_urls.app.get_url"
    )
    def new_get_path():
        return TaintedStr(original_function())

    return tm


# Test & Fuzzer for Furl Allow List Relative Paths
def test_fuzz_furl_path(taintmonkey):
    from dataset.cwe_938_unvalidated_redirects_and_forwards.furl_allow_list_relative_paths.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/unvalidated_redirect?{urlencode({'path': data})}")


# Test & Fuzzer for Furl Allow List Urls
def test_fuzz_furl_allow(taintmonkey):
    from dataset.cwe_938_unvalidated_redirects_and_forwards.furl_allow_list_urls.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/unvalidated_redirect?{urlencode({'url': data})}")


# Test & Fuzzer for Furl Deny List Urls
def test_fuzz_furl_deny(taintmonkey):
    from dataset.cwe_938_unvalidated_redirects_and_forwards.furl_deny_list_urls.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/unvalidated_redirect?{urlencode({'url': data})}")


# Test & Fuzzer for Requests Allow List Urls
def test_fuzz_requests_allow(taintmonkey):
    from dataset.cwe_938_unvalidated_redirects_and_forwards.requests_allow_list.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/unvalidated_redirect?{urlencode({'url': data})}")


# Test & Fuzzer for Urllib Allow List Relative Paths
def test_fuzz_urllib_path(taintmonkey):
    from dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_relative_paths.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/unvalidated_redirect?{urlencode({'path': data})}")


# Test & Fuzzer for Urllib Allow List Urls
def test_fuzz_urllib_allow(taintmonkey):
    from dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_urls.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/unvalidated_redirect?{urlencode({'url': data})}")


# Test & Fuzzer for Urllib Deny List Urls
def test_fuzz_urllib_deny(taintmonkey):
    from dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_deny_list_urls.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/unvalidated_redirect?{urlencode({'url': data})}")


# Test & Fuzzer for Yarl Allow List Relative Paths
def test_fuzz_yarl_path(taintmonkey):
    from dataset.cwe_938_unvalidated_redirects_and_forwards.yarl_allow_list_relative_paths.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/unvalidated_redirect?{urlencode({'path': data})}")


# Test & Fuzzer for Yarl Allow List Urls
def test_fuzz_yarl_allow(taintmonkey):
    from dataset.cwe_938_unvalidated_redirects_and_forwards.yarl_allow_list_urls.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/unvalidated_redirect?{urlencode({'url': data})}")


# Test & Fuzzer for Yarl Deny List Urls
def test_fuzz_yarl_deny(taintmonkey):
    from dataset.cwe_938_unvalidated_redirects_and_forwards.yarl_deny_list_urls.app import (
        app,
    )

    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/unvalidated_redirect?{urlencode({'url': data})}")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
