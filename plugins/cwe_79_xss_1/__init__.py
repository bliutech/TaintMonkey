"""
TaintMonkey plugin to detect Cross-Site Scripting (XSS).


CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
https://cwe.mitre.org/data/definitions/79.html


# How to run?
From the root of the repository, run the following.


```
PYTHONPATH=. python3 plugins/cwe_79_xss_1/__init__.py
PYTHONPATH=. pytest -vs plugins/cwe_79_xss_1/__init__.py
```
"""


import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function


import sys


SOURCES = []
SANITIZERS = []
SINKS = []


import dataset.cwe_79_xss.xss_1_html_exploit.app
old_say_hi = dataset.cwe_79_xss.xss_1_html_exploit.app.say_hi


@patch_function("dataset.cwe_79_xss.xss_1_html_exploit.app.say_hi")
def new_say_hi(name) -> str:
   if hasattr(name, "is_tainted") and name.is_tainted():
       raise TaintException("potential XSS vulnerability")
   return old_say_hi(name)


@pytest.fixture()
def app():
   from dataset.cwe_79_xss.xss_1_html_exploit.app import app


   register_taint_client(app)


   yield(app)


@pytest.fixture()
def client(app):
   return app.test_client()


@pytest.fixture()
def fuzzer(app):
   return DictionaryFuzzer(app, "plugins/cwe_79_xss_1/dictionary.txt")


def test_taint_exception(client):
   with pytest.raises(TaintException):
       client.get("/insecure?name=<script>alert('XSS')</script>")




def test_no_taint_exception(client):
  
       client.get("/secure?name=<script>alert('XSS')</script>")


def test_fuzz(fuzzer):
   from urllib.parse import urlencode


   counter = 0
   with fuzzer.get_context() as (client, inputs):
       for data in inputs:
           print(f"[Fuzz Attempt {counter}] {data}")
           # Demonstrating fuzzer capabilities
           with pytest.raises(TaintException):
               client.get(f"/insecure?{urlencode({'name': data})}")
           counter += 1
      
if __name__ == "__main__":
  sys.exit(pytest.main([__file__]))