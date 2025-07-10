import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function

import os, sys

test_case_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                             'dataset', 'cwe_89_sql_injection_testcase', 'cwe_89_sql_injection_testcase1_6')
sys.path.insert(0, test_case_path)

import db

@pytest.fixture()
def app():
    from app import app
    register_taint_client(app)
    yield app

@pytest.fixture()
def client(app):
    return app.test_client()

@pytest.fixture()
def fuzzer(app):
    return DictionaryFuzzer(app, "plugins/cwe_89_sql_injection/dictionary.txt")

def test_fuzz(fuzzer):
    from urllib.parse import urlencode

    counter = 0
    with fuzzer.get_context() as (client, inputs):
        for data in inputs:
            print(f"[Fuzz Attempt {counter}] {data}")
            try:
                client.post(f"/insecure-signup?{urlencode({'username': data, 'password': 'test'})}")
                client.post(f"/insecure-login?{urlencode({'username': data, 'password': 'test'})}")
                client.get(f"/insecure-second-level?{urlencode({'username': data})}")
                client.post(f"/secure-signup?{urlencode({'username': data, 'password': 'test'})}")
                client.post(f"/secure-login?{urlencode({'username': data, 'password': 'test'})}")
                client.get(f"/secure-second-level?{urlencode({'username': data})}")
                
                counter += 1
            except Exception as e:
                print(f"Error during fuzzing: {str(e)}")
                counter += 1

if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
