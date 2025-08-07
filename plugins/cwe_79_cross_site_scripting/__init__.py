"""
TaintMonkey plugin to detect Cross-Site Scripting (XSS).

CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
https://cwe.mitre.org/data/definitions/79.html


# corpus.txt contains common XSS payloads from the following:
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection


# How to run?
From the root of the repository, run the following.

```
PYTHONPATH=. python3 plugins/cwe_79_cross_site_scripting/__init__.py
PYTHONPATH=. pytest -vs plugins/cwe_79_cross_site_scripting/__init__.py
```
"""

import pytest

from taintmonkey import TaintException, TaintMonkey
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.fuzzer import MutationBasedFuzzer

import os, sys
from urllib.parse import urlencode
from taintmonkey.patch import original_function

VERIFIERS = [
    
]
SANITIZERS = []
SINKS = [

]


@pytest.fixture()
def taintmonkey():
    from dataset.cwe_79_cross_site_scripting.html_escape_custom_check_response.app import (
        app,
    )

    tm = TaintMonkey(app, verifiers=VERIFIERS, sanitizers=SANITIZERS, sinks=SINKS)

    fuzzer = DictionaryFuzzer(app, "plugins/cwe_79_cross_site_scripting/corpus.txt")
    tm.set_fuzzer(fuzzer)

    @tm.patch.function(
        "dataset.cwe_79_cross_site_scripting.html_escape_custom_check_response.app.say_hi"
    )
    def patched_open_file_command(name: TaintedStr):
        command = TaintedStr(original_function(name))
        if not name.is_tainted():
            command.sanitize()
        return command

    @tm.patch.function(
        "dataset.cwe_79_cross_site_scripting.html_sanitizer_sanitize_template.app.home"
    )
    def patched_open_file_command(name):
        tainted_name = TaintedStr(name)
        command = TaintedStr(original_function(name))
        if not tainted_name.is_tainted():
                command.sanitize()
        return command

    @tm.patch.function(
        "dataset.cwe_79_cross_site_scripting.bleach_clean_response.app.welcome"
    )
    def patched_open_file_command(name):
        command = TaintedStr(original_function(name))
        if not name.is_tainted():
            command.sanitize()
        return command

    @tm.patch.function(
        "dataset.cwe_79_cross_site_scripting.lxml_cleaner_response.app.user_input"
    )
    def patched_open_file_command(name):
        tainted_name = TaintedStr(name)
        command = TaintedStr(original_function(name))
        if not tainted_name.is_tainted():
                command.sanitize()
        return command

    @tm.patch.function(
        "dataset.cwe_79_cross_site_scripting.markupsafe_escape_response.app.say_hi"
    )
    def patched_open_file_command(name):
        tainted_name = TaintedStr(name)
        command = TaintedStr(original_function(name))
        if not tainted_name.is_tainted():
                command.sanitize()
        return command

    return tm






def test_fuzz_html_escape_custom_check_response(taintmonkey):
    from dataset.cwe_79_cross_site_scripting.html_escape_custom_check_response.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure-xss?{urlencode({'name': data})}")


def test_fuzz_html_sanitizer_sanitize_template(taintmonkey):
    from dataset.cwe_79_cross_site_scripting.html_sanitizer_sanitize_template.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'name': data})}")

def test_fuzz_bleach_clean_response(taintmonkey):
    from dataset.cwe_79_cross_site_scripting.bleach_clean_response.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'name': data})}")

def test_fuzz_lxml_cleaner_response(taintmonkey):
    from dataset.cwe_79_cross_site_scripting.lxml_cleaner_response.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/grade_secure?{urlencode({'score': data})}")

def test_fuzz_markupsafe_escape_response(taintmonkey):
    from dataset.cwe_79_cross_site_scripting.markupsafe_escape_response.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'name': data})}")



if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
