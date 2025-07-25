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

import io

SOURCES = []
SANITIZERS = []
SINKS = []

import dataset.cwe_434_unrestricted_upload_file.allowed_extensions_file_save.app

from werkzeug.datastructures import FileStorage


old_get_filename = dataset.cwe_434_unrestricted_upload_file.allowed_extensions_file_save.app.get_filename


@patch_function(
    "dataset.cwe_434_unrestricted_upload_file.allowed_extensions_file_save.app.get_filename"
)
def new_get_filename(file):
    return TaintedStr(old_get_filename(file))


old_safe_wrapper = dataset.cwe_434_unrestricted_upload_file.allowed_extensions_file_save.app.safe_wrapper


@patch_function(
    "dataset.cwe_434_unrestricted_upload_file.allowed_extensions_file_save.app.safe_wrapper"
)
def new_safe_wrapper(file, filename: TaintedStr):
    if filename.is_tainted():
        raise TaintException("potential vulnerability")
    return old_safe_wrapper(file, filename)


old_is_safe_filename = dataset.cwe_434_unrestricted_upload_file.allowed_extensions_file_save.app.is_safe_filename


@patch_function(
    "dataset.cwe_434_unrestricted_upload_file.allowed_extensions_file_save.app.is_safe_filename"
)
def new_is_safe_filename(filename: TaintedStr):
    filename.sanitize()
    return old_is_safe_filename(filename)


@pytest.fixture()
def app():
    from dataset.cwe_434_unrestricted_upload_file.allowed_extensions_file_save.app import (
        app,
    )

    register_taint_client(app)

    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def fuzzer(app):
    return DictionaryFuzzer(app, "plugins/cwe_434_unrestricted_upload_file/corpus.txt")


# TODO(bliutech): this does not catch the vulnerability, need to fix the patching
def test_fuzz(fuzzer):
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            file_data = {"file": (io.BytesIO(b"image data"), TaintedStr(data))}
            res = client.post(
                "/insecure/upload", data=file_data, content_type="multipart/form-data"
            )
            print(res.text)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
