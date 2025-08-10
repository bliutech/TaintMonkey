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


VERIFIERS = []
SANITIZERS = []
SINKS = [
    "dataset.cwe_79_cross_site_scripting.html_escape_custom_check_response.app.say_hi",
    "dataset.cwe_79_cross_site_scripting.html_sanitizer_sanitize_template.app.home",
    "dataset.cwe_79_cross_site_scripting.bleach_clean_response.app.welcome",
    "dataset.cwe_79_cross_site_scripting.lxml_cleaner_response.app.user_input",
    "dataset.cwe_79_cross_site_scripting.markupsafe_escape_response.app.say_hi",
    "dataset.cwe_79_cross_site_scripting.bleach_clean_css_format_string.app.gset_text",
    "dataset.cwe_79_cross_site_scripting.html_escape_format_string.app.say_hello",
    "dataset.cwe_79_cross_site_scripting.html_escape_normal_response.app.how_are_you",
    "dataset.cwe_79_cross_site_scripting.lxml_cleaner_post_response.app.welcome",
    "dataset.cwe_79_cross_site_scripting.markupsafe_escape_table_format_String.app.table",
]


@pytest.fixture()
def taintmonkey():
   from dataset.cwe_79_cross_site_scripting.html_escape_custom_check_response.app import app

   tm = TaintMonkey(app, verifiers=VERIFIERS, sanitizers=SANITIZERS, sinks=SINKS)

   fuzzer = DictionaryFuzzer(app, "plugins/cwe_79_cross_site_scripting/corpus.txt")
   tm.set_fuzzer(fuzzer)

   return tm



# test and fuzzer
def test_fuzz_html_escape_custom_check_response(taintmonkey):
   from dataset.cwe_79_cross_site_scripting.html_escape_custom_check_response.app import (
       app,
   )

   taintmonkey.set_app(app)

   with taintmonkey.get_fuzzer().get_context() as (client, get_input):
       for data in get_input():
        with pytest.raises(TaintException):
           client.get(f"/insecure-xss?{urlencode({'name': data})}")



def test_fuzz_html_sanitizer_sanitize_template(taintmonkey):
   from dataset.cwe_79_cross_site_scripting.html_sanitizer_sanitize_template.app import (
       app,
   )


   taintmonkey.set_app(app)


   with taintmonkey.get_fuzzer().get_context() as (client, get_input):
       for data in get_input():
        with pytest.raises(TaintException):
           client.get(f"/insecure?{urlencode({'name': data})}")




def test_fuzz_bleach_clean_response(taintmonkey):
   from dataset.cwe_79_cross_site_scripting.bleach_clean_response.app import app


   taintmonkey.set_app(app)


   with taintmonkey.get_fuzzer().get_context() as (client, get_input):
       for data in get_input():
        with pytest.raises(TaintException):
           client.get(f"/insecure?{urlencode({'name': data})}")




def test_fuzz_lxml_cleaner_response(taintmonkey):
   from dataset.cwe_79_cross_site_scripting.lxml_cleaner_response.app import app


   taintmonkey.set_app(app)


   with taintmonkey.get_fuzzer().get_context() as (client, get_input):
       for data in get_input():
        with pytest.raises(TaintException):
           client.get(f"/grade_insecure?{urlencode({'score': data})}")




def test_fuzz_markupsafe_escape_response(taintmonkey):
   from dataset.cwe_79_cross_site_scripting.markupsafe_escape_response.app import app


   taintmonkey.set_app(app)


   with taintmonkey.get_fuzzer().get_context() as (client, get_input):
       for data in get_input():
        with pytest.raises(TaintException):
           client.get(f"/insecure?{urlencode({'name': data})}")




def test_fuzz_bleach_clean_css_format_string(taintmonkey):
   from dataset.cwe_79_cross_site_scripting.bleach_clean_css_format_string.app import (
       app,
   )


   taintmonkey.set_app(app)


   with taintmonkey.get_fuzzer().get_context() as (client, get_input):
       for data in get_input():
        with pytest.raises(TaintException):
           client.get(f"/style_insecure?{urlencode({'color': data})}")




def test_fuzz_html_escape_format_string(taintmonkey):
   from dataset.cwe_79_cross_site_scripting.html_escape_format_string.app import app


   taintmonkey.set_app(app)


   with taintmonkey.get_fuzzer().get_context() as (client, get_input):
       for data in get_input():
        with pytest.raises(TaintException):
           client.post("/submit_insecure", data={"username": data})




def test_fuzz_html_escape_normal_response(taintmonkey):
   from dataset.cwe_79_cross_site_scripting.html_escape_normal_response.app import app


   taintmonkey.set_app(app)


   with taintmonkey.get_fuzzer().get_context() as (client, get_input):
       for data in get_input():
        with pytest.raises(TaintException):
           client.get(f"/insecure_cookie?{urlencode({'username': data})}")




def test_fuzz_lxml_cleaner_post_response(taintmonkey):
   from dataset.cwe_79_cross_site_scripting.lxml_cleaner_post_response.app import app


   taintmonkey.set_app(app)


   with taintmonkey.get_fuzzer().get_context() as (client, get_input):
       for data in get_input():
        with pytest.raises(TaintException):
           client.post("/insecure_welcome", data={"username": data})




def test_fuzz_markupsafe_escape_table_format_String(taintmonkey):
   from dataset.cwe_79_cross_site_scripting.markupsafe_escape_table_format_String.app import app

   taintmonkey.set_app(app)


   with taintmonkey.get_fuzzer().get_context() as (client, get_input):
       for data in get_input():
        with pytest.raises(TaintException):
           client.get(f"/insecure_table?{urlencode({'name': data})}")




if __name__ == "__main__":
   sys.exit(pytest.main([__file__]))
