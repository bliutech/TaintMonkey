# TODO(sanitizer): must add sanitizer that checks if the client is using csrf tokens
#                  * right now all plugin does is mark new passwords as tainted and 
#                    raises taint exception when trying to update password (every time)
#                  * having csrf_exempt() means route is insecure, but also worthwile to 
#                    consider that if someone's app is vulnerable to CSRF, they likely don't
#                    have any CSRF token libraries imported/in use

from flask import Flask, request
import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function

import sys

SOURCES = ["get_new_password"]
SANITIZERS = []
SINKS = ["update_password"]

# monkey patching

import dataset.cwe_352_csrf.flask_wtf_post.app

# source
old_get_new_password = dataset.cwe_352_csrf.flask_wtf_post.app.get_new_password

@patch_function(
    "dataset.cwe_352_csrf.flask_wtf_post.app.get_new_password"
)
def new_get_new_password(request):
    return TaintedStr(old_get_new_password(request))

# sanitizer
def is_csrf_vulnerable(app: Flask, endpoint: str):
    view_func = app.view_functions.get(endpoint)
    return "flask_wtf.csrf" not in sys.modules or getattr(view_func, "_csrf_exempt", False) 

    # TODO: have to figure out how to use knowledge of whether or not an endpoint 
    #       is csrf vulnerable to sanitize/not sanitize the new_password
    #       * not sure if we can monkey patch insecure_update b/c we need to pass in 
    #         a Flask object and endpoint for is_csrf_vulnerable to work
    
# sink
old_update_password = dataset.cwe_352_csrf.flask_wtf_post.app.update_password

@patch_function(
    "dataset.cwe_352_csrf.flask_wtf_post.app.get_new_password"
)
def new_update_password(new_password: TaintedStr):
    if new_password.is_tainted():
        raise TaintException("possible vulnerability")
    return old_update_password(new_password)


@pytest.fixture()
def app():
    from dataset.cwe_352_csrf.flask_wtf_post.app import app
    
    register_taint_client(app)

    yield app

@pytest.fixture()
def client(app):
    return app.test_client(use_cookies=True)

@pytest.fixture()
def fuzzer(app):
    return DictionaryFuzzer(app, "plugins/cwe_352_csrf/dictionary.txt")

def test_fuzz(app, fuzzer):
    from urllib.parse import urlencode

    counter = 0
    with fuzzer.get_context() as (attacker, inputs):
        for data in inputs:
            print(f"[Fuzz Attempt {counter}] {data}")
            victim = app.test_client()
            response = victim.post("/register?username=test&password=test")
            response = victim.post("/login?username=test&password=test")
            
            session_cookie = victim.get_cookie("session") 
            assert session_cookie is not None
            
            with pytest.raises(TaintException):
                attacker.set_cookie(domain="localhost", key="session", value=session_cookie.value)

                # some test files use get instead
                response = attacker.post(f"/insecure-update?new_password={urlencode({'file': data})}")
                print(response.data.decode())
            counter += 1

if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))

