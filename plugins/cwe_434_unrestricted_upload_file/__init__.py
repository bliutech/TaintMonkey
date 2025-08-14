"""
TaintMonkey plugin to detect Unrestricted Upload of File with Dangerous Type.


CWE-434: Unrestricted Upload of File with Dangerous Type
https://cwe.mitre.org/data/definitions/434.html


# payloads source
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files


# How to run?
From the root of the repository, run the following.


```
PYTHONPATH=. pytest -vs plugins/cwe_434_unrestricted_upload_file/__init__.py
```
"""

import pytest


from taintmonkey import TaintException, TaintMonkey
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function


import os, sys
import io
from werkzeug.datastructures import FileStorage


VERIFIERS = []
SANITIZERS = []
SINKS = [
    "dataset.cwe_434_unrestricted_upload_file.allowed_extensions_file_save.app.safe_wrapper",
    "dataset.cwe_434_unrestricted_upload_file.allowed_extensions_os_path_join.app.file_save",
    "dataset.cwe_434_unrestricted_upload_file.allowed_file_send_file.app.safe_wrapper",
    "dataset.cwe_434_unrestricted_upload_file.extension_allow_list_check_file.app.safe_wrapper",
    "dataset.cwe_434_unrestricted_upload_file.is_allowed_os_path_join_open.app.safe_wrapper",
    "dataset.cwe_434_unrestricted_upload_file.mine_type_file_save.app.safe_wrapper",
    "dataset.cwe_434_unrestricted_upload_file.safe_join_send_file.app.safe_wrapper",
    "dataset.cwe_434_unrestricted_upload_file.safe_join_send_from_directory.app.safe_wrapper",
    "dataset.cwe_434_unrestricted_upload_file.secure_filename_open.app.safe_wrapper",
    "dataset.cwe_434_unrestricted_upload_file.secure_filename_requests_post.app.safe_wrapper",
]


@pytest.fixture()
def taintmonkey():
    from dataset.cwe_434_unrestricted_upload_file.allowed_extensions_file_save.app import (
        app,
    )

    tm = TaintMonkey(app, verifiers=VERIFIERS, sanitizers=SANITIZERS, sinks=SINKS)

    fuzzer = DictionaryFuzzer(
        app, "plugins/cwe_434_unrestricted_upload_file/corpus.txt"
    )
    tm.set_fuzzer(fuzzer)

    return tm


# test and fuzzer
def test_fuzz_allowed_extensions_file_save(taintmonkey):
    from dataset.cwe_434_unrestricted_upload_file.allowed_extensions_file_save.app import (
        app,
    )

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                file_data = {"file": (io.BytesIO(b"image data"), TaintedStr(data))}
                client.post(
                    f"/insecure/upload",
                    data=file_data,
                    content_type="multipart/form-data",
                )


def test_fuzz_allowed_extensions_os_path_join(taintmonkey):
    from dataset.cwe_434_unrestricted_upload_file.allowed_extensions_os_path_join.app import (
        app,
    )

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                file_data = {"file": (io.BytesIO(b"image data"), TaintedStr(data))}
                client.post(
                    f"/insecure/upload",
                    data=file_data,
                    content_type="multipart/form-data",
                )


def test_fuzz_allowed_file_send_file(taintmonkey):
    from dataset.cwe_434_unrestricted_upload_file.allowed_file_send_file.app import (
        app,
    )

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                file_data = {"file": TaintedStr(data)}
                client.post(
                    f"/insecure/download",
                    data=file_data,
                    content_type="application/x-www-form-urlencoded",
                )


def test_fuzz_extension_allow_list_check_file(taintmonkey):
    from dataset.cwe_434_unrestricted_upload_file.extension_allow_list_check_file.app import (
        app,
    )

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                file_data = {"file": (io.BytesIO(b"image data"), TaintedStr(data))}
                client.post(
                    f"/insecure/upload",
                    data=file_data,
                    content_type="multipart/form-data",
                )


def test_fuzz_is_allowed_os_path_join_open(taintmonkey):
    from dataset.cwe_434_unrestricted_upload_file.is_allowed_os_path_join_open.app import (
        app,
    )

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure_read?filename={TaintedStr(data)}")


def test_fuzz_mine_type_file_save(taintmonkey):
    from dataset.cwe_434_unrestricted_upload_file.mine_type_file_save.app import (
        app,
    )

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                file_data = {"file": (io.BytesIO(b"image data"), TaintedStr(data))}
                client.post(
                    f"/insecure_upload",
                    data=file_data,
                    content_type="multipart/form-data",
                )


def test_fuzz_safe_join_send_file(taintmonkey):
    from dataset.cwe_434_unrestricted_upload_file.safe_join_send_file.app import (
        app,
    )

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure_download?filename={TaintedStr(data)}")


def test_fuzz_safe_join_send_from_directory(taintmonkey):
    from dataset.cwe_434_unrestricted_upload_file.safe_join_send_from_directory.app import (
        app,
    )

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                file_data = {"file": (io.BytesIO(b"image data"), TaintedStr(data))}
                client.post(
                    f"/insecure_upload",
                    data=file_data,
                    content_type="multipart/form-data",
                )


def test_fuzz_secure_filename_open(taintmonkey):
    from dataset.cwe_434_unrestricted_upload_file.secure_filename_open.app import (
        app,
    )

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                file_data = {"file": (io.BytesIO(b"image data"), TaintedStr(data))}
                client.post(
                    f"/insecure_upload",
                    data=file_data,
                    content_type="multipart/form-data",
                )


def test_fuzz_secure_filename_requests_post(taintmonkey):
    from dataset.cwe_434_unrestricted_upload_file.secure_filename_requests_post.app import (
        app,
    )

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                file_data = {"file": (io.BytesIO(b"image data"), TaintedStr(data))}
                client.post(
                    f"/insecure_upload",
                    data=file_data,
                    content_type="multipart/form-data",
                )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
