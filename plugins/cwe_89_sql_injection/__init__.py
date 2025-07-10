import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function

import os, sys

@pytest.fixture()
def app():
    from dataset.cwe_89_sql_injection_testcase.cwe_89_sql_injection_testcase1_6 import app

    register_taint_client(app)

    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def fuzzer(app):
    return DictionaryFuzzer(app, "plugins/cwe_89_sql_injection/dictionary.txt")
