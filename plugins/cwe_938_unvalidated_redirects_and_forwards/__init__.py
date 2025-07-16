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

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function
import flask, sys

SOURCES = ["get_url()"]

SANITIZERS = ["check_allow_list"]

SINKS = ["redirect_to"]

import dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_urls.app


#Sink Patch
old_redirect= dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_urls.app.redirect_to
@patch_function("dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_urls.app.redirect_to")
def new_redirect(url: TaintedStr):
    if url.is_tainted():
        raise TaintException("potential vulnerability")
    return  old_redirect(url)


#Source Patch
old_get_url = dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_urls.app.get_url
@patch_function("dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_urls.app.get_url")
def new_get_url():
    return TaintedStr(old_get_url())


#Santizer Patch
old_check_allow_list = dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_urls.app.check_allow_list
@patch_function("dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_urls.app.check_allow_list")
def new_check_allow_list(url: TaintedStr):
    url.sanitize()
    return old_check_allow_list


# https://flask.palletsprojects.com/en/stable/testing/
@pytest.fixture()
def app():
    from dataset.cwe_938_unvalidated_redirects_and_forwards.urllib_allow_list_urls.app import app
    register_taint_client(app)
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def fuzzer(app):
    # Corpus from https://hacktricks.boitatech.com.br/pentesting-web/open-redirect
    return DictionaryFuzzer(app, "plugins/cwe_938_unvalidated_redirects_and_forwards/dictionary.txt")


def test_taint_exception(client):
    with pytest.raises(TaintException):
        client.get("/unvalidated_redirect?url=https://www.malicious.com/evil")


def test_no_taint_exception(client):
    # Expect no exception
    client.get("/validated_redirect?url=https://www.allowed.com/safe")


def test_fuzz(fuzzer):
    from urllib.parse import urlencode

    counter = 0
    with fuzzer.get_context() as (client, inputs):
        for data in inputs:
            print(f"[Fuzz Attempt {counter}] {data}")
            # Demonstrating fuzzer capabilities
            with pytest.raises(TaintException):
                client.get(f"/unvalidated_redirect?{urlencode({'url': data})}")
            counter += 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
