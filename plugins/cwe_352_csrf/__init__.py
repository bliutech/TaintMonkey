from flask import Flask, request, current_app
from flask_wtf.csrf import CSRFProtect
import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function, patch_route_handler

import sys

SOURCES = []
SANITIZERS = []
SINKS = []

# monkey patching

import dataset.cwe_352_csrf.flask_wtf_post.app
from dataset.cwe_352_csrf.flask_wtf_post.app import csrf

# # sanitizer
def is_csrf_vulnerable(app: Flask, endpoint: str):
    view_func = app.view_functions.get(endpoint)
    full_name = f"{view_func.__module__}.{view_func.__name__}"
    is_csrf_exempt = full_name in csrf._exempt_views
    return "flask_wtf.csrf" not in sys.modules or is_csrf_exempt 


old_insecure_update = dataset.cwe_352_csrf.flask_wtf_post.app.insecure_update
@patch_function(
    "dataset.cwe_352_csrf.flask_wtf_post.app.insecure_update"
)
@csrf.exempt
@dataset.cwe_352_csrf.flask_wtf_post.app.login_required
def new_insecure_update():
    endpoint = request.endpoint
    app = current_app

    if is_csrf_vulnerable(app, endpoint):
        raise TaintException("possible vulnerability")
    return old_insecure_update()
dataset.cwe_352_csrf.flask_wtf_post.app.app.view_functions['insecure_update'] = new_insecure_update



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