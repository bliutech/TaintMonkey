"""
TaintMonkey plugin to detect Unrestricted Upload of File with Dangerous Type.

CWE-434: Unrestricted Upload of File with Dangerous Type
https://cwe.mitre.org/data/definitions/434.html

# payloads source
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files

# How to run?
From the root of the repository, run the following.

```
PYTHONPATH=. python3 plugins/cwe_434_unrestricted_file_plugin1/__init__.py
```
"""

import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function

import os, sys

SOURCES = []
SANITIZERS = []
SINKS = []

import dataset.cwe_434_unrestricted_file.testcase1_double_extension.app

from werkzeug.datastructures import FileStorage


old_get_filename = (
    dataset.cwe_434_unrestricted_file.testcase1_double_extension.app.get_filename
)


@patch_function(
    "dataset.cwe_434_unrestricted_file.testcase1_double_extension.app.get_filename"
)
def new_get_filename(file):
    return TaintedStr(old_get_filename(file))


old_safe_wrapper = (
    dataset.cwe_434_unrestricted_file.testcase1_double_extension.app.safe_wrapper
)


@patch_function(
    "dataset.cwe_434_unrestricted_file.testcase1_double_extension.app.safe_wrapper"
)
def new_safe_wrapper(file, filename: TaintedStr):
    if filename.is_tainted():
        raise TaintException("potential vulnerability")
    return old_safe_wrapper(file, filename)


old_is_safe_filename = (
    dataset.cwe_434_unrestricted_file.testcase1_double_extension.app.is_safe_filename
)


@patch_function(
    "dataset.cwe_434_unrestricted_file.testcase1_double_extension.app.is_safe_filename"
)
def new_is_safe_filename(filename: TaintedStr):
    filename.sanitize()
    return old_is_safe_filename(filename)


@pytest.fixture()
def app():
    from dataset.cwe_434_unrestricted_file.testcase1_double_extension.app import app

    register_taint_client(app)

    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def fuzzer(app):
    return DictionaryFuzzer(
        app, "plugins/cwe_434_unrestricted_file_plugin1/dictionary.txt"
    )


def test_fuzz(fuzzer):
    import io

    counter = 0
    with fuzzer.get_context() as (client, inputs):
        for data in inputs:
            print(f"[Fuzz Attempt {counter}] {data}")

            file_data = {"file": (io.BytesIO(b"image data"), TaintedStr(data))}

            res = client.post(
                "/insecure/upload", data=file_data, content_type="multipart/form-data"
            )
            print(res.text)

            counter += 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
