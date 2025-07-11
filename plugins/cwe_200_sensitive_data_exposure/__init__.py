from multiprocessing.sharedctypes import Value
"""
TaintMonkey plugin to detect Sensitive Data Exposure.

CWE-200: Exposure of Sensitive Information to an Unauthorized Actor (Sensitive Data Exposure)
https://cwe.mitre.org/data/definitions/200.html

# How to run?
From the root of the repository, run the following.

```
PYTHONPATH=. python3 plugins/cwe_200_sensitive_data_exposure/__init__.py
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

SANITIZERS = ["hash_ssn"]

SINKS = ["app.logger.info"]



# Monkey patching
#------------------------


# Patch utility functions

import dataset.cwe_200_sensitive_data_exposure.test_case01

##Source
old_get = dataset.cwe_200_sensitive_data_exposure.test_case01.get_info
@patch_function("dataset.cwe_200_sensitive_data_exposure.test_case01.get_info")
def new_get(key):
    returned_value = old_get(key)
    if returned_value:
        return TaintedStr(returned_value) 
    return None


##Sink
old_logger = dataset.cwe_200_sensitive_data_exposure.test_case01.log_info

@patch_function("dataset.cwe_200_sensitive_data_exposure.test_case01.log_info")
def new_logger (message):    
    if isinstance(message, TaintedStr) and message.is_tainted():
        raise TaintException("potential vulnerability")
    return old_logger(message)

## Sanitizer
old_hash = dataset.cwe_200_sensitive_data_exposure.test_case01.hash_ssn

@patch_function("dataset.cwe_200_sensitive_data_exposure.test_case01.hash_ssn")
def new_hash(key: TaintedStr):
    key.sanitize()
    return old_hash(key)


#Pytest Functions
#------------------------

# https://flask.palletsprojects.com/en/stable/testing/
@pytest.fixture()
def app():
    from dataset.cwe_200_sensitive_data_exposure.test_case01 import app
    register_taint_client(app)
    yield app

@pytest.fixture()
def client(app):
    return app.test_client()

@pytest.fixture()
def fuzzer(app):
    return DictionaryFuzzer(app, "plugins/cwe_200_sensitive_data_exposure/dictionary.txt")




def test_taint_exception(client):
    with pytest.raises(TaintException):
        client.post("/insecure_register?ssnum=123-45-6789")

def test_no_taint_exception(client):
    # Expect no exception
    client.post("/secure_register?ssnum=123-45-6789")




def test_fuzz(fuzzer):

    counter = 0
    with fuzzer.get_context() as (client, inputs):
        for data in inputs:
            print (f"[Fuzz Attempt {counter}] {data}")
            # Demonstrating fuzzer capabilities
            #with pytest.raises(TaintException):
            client.post(f"/insecure?ssnum={data}")
            counter += 1



if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
