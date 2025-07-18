"""
TaintMonkey plugin to detect OS Command Injection.

CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
https://cwe.mitre.org/data/definitions/78.html

# How to run?
From the root of the repository, run the following.

```
PYTHONPATH=. python3 plugins/cwe_78_os_command_injection/__init__.py
```
"""
import builtins
import os.path
from urllib.parse import urlencode

import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function

import sys

import werkzeug.security

# TODO(bliutech): this might not be necessary. To simplify fuzzing, all data-flow
# comes from the request object anyways
SOURCES = ["get_page_post", "get_page"]

# TODO(bliutech): look into how to disambiguate function names
SANITIZERS = ["werkzeug.security.safe_join"]

SINKS = ["open"]

# Monkey patching
#UNCOMMENT TO SEE ERROR WITH UNIONS AND RETURN VALUES
old_safe_join = werkzeug.security.safe_join
@patch_function("werkzeug.security.safe_join")
def new_safe_join(directory: str, *pathnames: TaintedStr) -> str | None:
    for pathname in pathnames:
        if isinstance(pathname, TaintedStr):
            pathname.sanitize()
    return old_safe_join(directory, *pathnames)


old_open = builtins.open
@patch_function("builtins.open")
def new_open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    if isinstance(file, TaintedStr) and file.is_tainted():
        raise TaintException("potential vulnerability")
    return old_open(file, mode, buffering, encoding, errors, newline, closefd, opener)


# Patch utility functions
import dataset.cwe_73_external_control_of_path.lfi_insecure_url_bypass_flask_safe_join.app


old_get_page_post = (
    dataset.cwe_73_external_control_of_path.lfi_insecure_url_bypass_flask_safe_join.app.get_page_post
)
@patch_function(
    "dataset.cwe_73_external_control_of_path.lfi_insecure_url_bypass_flask_safe_join.app.get_page_post"
)
def new_get_page_post(this_request):
    return TaintedStr(old_get_page_post(this_request))


old_get_page = (
    dataset.cwe_73_external_control_of_path.lfi_insecure_url_bypass_flask_safe_join.app.get_page
)
@patch_function(
    "dataset.cwe_73_external_control_of_path.lfi_insecure_url_bypass_flask_safe_join.app.get_page"
)
def new_get_page(this_request):
    return TaintedStr(old_get_page(this_request))


# https://flask.palletsprojects.com/en/stable/testing/
@pytest.fixture()
def app():
    from dataset.cwe_73_external_control_of_path.lfi_insecure_url_bypass_flask_safe_join.app import app

    register_taint_client(app)

    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def fuzzer(app):
    # Corpus from https://hacktricks.boitatech.com.br/pentesting-web/command-injection
    return DictionaryFuzzer(app, "plugins/cwe_73_external_control_of_path/dictionary.txt")


def test_taint_exception_url_bypass(client):
    with pytest.raises(TaintException):
        client.get(f"/view?{urlencode({'page': "../../../../../../../../../../../../Windows/PFRO.log"})}")


def test_fuzz(fuzzer):
    print("\n\nInsecure Fuzz Start")
    counter = 0
    with fuzzer.get_context() as (client, inputs):
        for data in inputs:
            print(f"[Fuzz Attempt {counter}] {data}")
            # Demonstrating fuzzer capabilities
            with pytest.raises(TaintException):
                client.get(f"/view?{urlencode({'page': data})}")
            counter += 1
    print("Insecure Fuzz Finished")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
