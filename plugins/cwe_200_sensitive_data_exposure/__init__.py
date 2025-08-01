"""
TaintMonkey plugin to detect Sensitive Data Exposure.

CWE-200: Exposure of Sensitive Information to an Unauthorized Actor ('Sensitive Data Exposure')
https://cwe.mitre.org/data/definitions/200.html

# How to run?
From the root of the repository, run the following.

```
PYTHONPATH=. python3 plugins/cwe_200_sensitive_data_exposure/__init__.py
```
"""

import pytest

from taintmonkey import TaintException, TaintMonkey
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function, original_function

import os, sys
from urllib.parse import urlencode


'''
List of Sanitizers:
    "dataset.cwe_200_sensitive_data_exposure.generalize_log.app.generalize",
    "dataset.cwe_200_sensitive_data_exposure.generalize_print.app.generalize",
    "dataset.cwe_200_sensitive_data_exposure.hash_log.app.hash_ssn",
    "dataset.cwe_200_sensitive_data_exposure.hash_print.app.hash_ssn",
    "dataset.cwe_200_sensitive_data_exposure.mask_log.app.masked",
    "dataset.cwe_200_sensitive_data_exposure.mask_print.app.masked",
    "dataset.cwe_200_sensitive_data_exposure.psudonymization_log.app.psudo",
    "dataset.cwe_200_sensitive_data_exposure.psudonymization_print.app.psudo",
    "dataset.cwe_200_sensitive_data_exposure.token_log.app.tokenize",
    "dataset.cwe_200_sensitive_data_exposure.token_print.app.tokenize"
'''

'''
List of sinks:
    "dataset.cwe_200_sensitive_data_exposure.generalize_log.app.log_info",
    "dataset.cwe_200_sensitive_data_exposure.generalize_print.app.print_info",
    "dataset.cwe_200_sensitive_data_exposure.hash_log.app.log_info",
    "dataset.cwe_200_sensitive_data_exposure.hash_print.app.print_info",
    "dataset.cwe_200_sensitive_data_exposure.mask_log.app.log_info",
    "dataset.cwe_200_sensitive_data_exposure.mask_print.app.print_info",
    "dataset.cwe_200_sensitive_data_exposure.psudonymization_log.app.log_info",
    "dataset.cwe_200_sensitive_data_exposure.psudonymization_print.app.print_info",
    "dataset.cwe_200_sensitive_data_exposure.token_log.app.log_info",
    "dataset.cwe_200_sensitive_data_exposure.token_print.app.print_info"
'''

VERIFIERS = []
SANITIZERS = []
SINKS = []

@pytest.fixture()
def taintmonkey():
    from dataset.cwe_200_sensitive_data_exposure.generalize_log.app import app

    tm = TaintMonkey(app, verifiers=VERIFIERS, sanitizers=SANITIZERS, sinks=SINKS)

    fuzzer = DictionaryFuzzer(app, "plugins/cwe_200_sensitive_data_exposure/corpus.txt")
    tm.set_fuzzer(fuzzer)

    # Manually Patched Sanitizer - TODO(CKC): Figure out why it doesn't work
    # @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.generalize_log.app.generalize")
    # def new_generalize(var):
    #     var.sanitize()
    #     return original_function(var)

    #Manually Patched Sources
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.generalize_log.app.get_info")
    def new_get_info(var):
        return TaintedStr(original_function(var))
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.generalize_print.app.get_info")
    def new_get_info(var):
        return TaintedStr(original_function(var))
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.hash_log.app.get_info")
    def new_get_info(var):
        return TaintedStr(original_function(var))
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.hash_print.app.get_info")
    def new_get_info(var):
        return TaintedStr(original_function(var))
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.mask_log.app.get_info")
    def new_get_info(var):
        return TaintedStr(original_function(var))
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.mask_print.app.get_info")
    def new_get_info(var):
        return TaintedStr(original_function(var))
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.psudonymization_log.app.get_info")
    def new_get_info(var):
        return TaintedStr(original_function(var))
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.psudonymization_print.app.get_info")
    def new_get_info(var):
        return TaintedStr(original_function(var))
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.token_log.app.get_info")
    def new_get_info(var):
        return TaintedStr(original_function(var))
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.token_print.app.get_info")
    def new_get_info(var):
        return TaintedStr(original_function(var))

    #Manually Patched Sinks (will remove once TaintMonkey function is fixed)
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.generalize_log.app.log_info")
    def new_log_info(var):
        if var.is_tainted():
            raise TaintException
        return original_function(var)
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.generalize_print.app.print_info")
    def new_log_info(var):
        if var.is_tainted():
            raise TaintException
        return original_function(var)
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.hash_log.app.log_info")
    def new_log_info(var):
        if var.is_tainted():
            raise TaintException
        return original_function(var)

    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.hash_print.app.print_info")
    def new_log_info(var):
        if var.is_tainted():
            raise TaintException
        return original_function(var)
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.mask_log.app.log_info")
    def new_log_info(var):
        if var.is_tainted():
            raise TaintException
        return original_function(var)

    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.mask_print.app.print_info")
    def new_log_info(var):
        if var.is_tainted():
            raise TaintException
        return original_function(var)
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.psudonymization_log.app.log_info")
    def new_log_info(var):
        if var.is_tainted():
            raise TaintException
        return original_function(var)

    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.psudonymization_print.app.print_info")
    def new_log_info(var):
        if var.is_tainted():
            raise TaintException
        return original_function(var)
    
    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.token_log.app.log_info")
    def new_log_info(var):
        if var.is_tainted():
            raise TaintException
        return original_function(var)

    @tm.patch.function("dataset.cwe_200_sensitive_data_exposure.token_print.app.print_info")
    def new_log_info(var):
        if var.is_tainted():
            raise TaintException
        return original_function(var)

    return tm


#Test & Fuzzer for Generalize Log
def test_taint_exception_generalize_log(taintmonkey):
    client = taintmonkey.get_client()
    with pytest.raises(TaintException):
        client.post("/insecure_birthdate?birthdate=01-01-2000")

def test_fuzz_generalize_log(taintmonkey):
    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.post(f"/insecure_birthdate?{urlencode({'birthdate': data})}")


#Test & Fuzzer for Generalize Print
def test_taint_exception_generalize_print(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.generalize_print.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    with pytest.raises(TaintException):
        client.post("/insecure_birthdate?birthdate=01-01-2000")

def test_fuzz_generalize_print(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.generalize_print.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.post(f"/insecure_birthdate?{urlencode({'birthdate': data})}")


#Test & Fuzzer for Hash Log
def test_taint_exception_hash_log(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.hash_log.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    with pytest.raises(TaintException):
        client.post("/insecure_register?ssnum=111-22-3333")

def test_fuzz_hash_log(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.hash_log.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.post(f"/insecure_register?{urlencode({'ssnum': data})}")


#Test & Fuzzer for Hash Print
def test_taint_exception_hash_print(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.hash_print.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    with pytest.raises(TaintException):
        client.post("/insecure_register?ssnum=111-22-3333")

def test_fuzz_hash_print(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.hash_print.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.post(f"/insecure_register?{urlencode({'ssnum': data})}")


#Test & Fuzzer for Mask Log
def test_taint_exception_mask_log(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.mask_log.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    with pytest.raises(TaintException):
        client.post("/insecure_address?home_address=100_Washington_Ave")

def test_fuzz_mask_log(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.mask_log.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.post(f"/insecure_address?{urlencode({'home_address': data})}")


#Test & Fuzzer for Mask Print
def test_taint_exception_mask_print(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.mask_print.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    with pytest.raises(TaintException):
        client.post("/insecure_address?home_address=100_Washington_Ave")

def test_fuzz_mask_print(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.mask_print.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.post(f"/insecure_address?{urlencode({'home_address': data})}")


#Test & Fuzzer for Psudonymization Log
def test_taint_exception_psudonymization_log(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.psudonymization_log.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    with pytest.raises(TaintException):
        client.post("/insecure_phone?phone_number=800-100-2345")

def test_fuzz_psudonymization_log(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.psudonymization_log.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.post(f"/insecure_phone?{urlencode({'phone_number': data})}")


#Test & Fuzzer for Psudonymization Print
def test_taint_exception_psudonymization_print(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.psudonymization_print.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    with pytest.raises(TaintException):
        client.post("/insecure_phone?phone_number=800-100-2345")

def test_fuzz_psudonymization_print(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.psudonymization_print.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.post(f"/insecure_phone?{urlencode({'phone_number': data})}")


#Test & Fuzzer for Token Log
def test_taint_exception_token_log(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.token_log.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    with pytest.raises(TaintException):
        client.post("/insecure_bank?bank_number=123456789")

def test_fuzz_token_log(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.token_log.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.post(f"/insecure_bank?{urlencode({'bank_number': data})}")


#Test & Fuzzer for Token Print
def test_taint_exception_token_print(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.token_print.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    with pytest.raises(TaintException):
        client.post("/insecure_bank?bank_number=123456789")

def test_fuzz_token_print(taintmonkey):
    from dataset.cwe_200_sensitive_data_exposure.token_print.app import app
    taintmonkey.set_app(app)

    client = taintmonkey.get_client()

    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.post(f"/insecure_bank?{urlencode({'bank_number': data})}")



# Sanitizer patching doesn't work yet - TODO(CKC): Figure out why it doesn't work
# def test_no_taint_exception(taintmonkey):
#     client = taintmonkey.get_client()
#     client.post("/secure_birthdate?birthdate=01-01-2000")



if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
