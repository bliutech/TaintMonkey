# TODO(sanitizer): must add sanitizer that checks if the client is using csrf tokens
#                  * right now all plugin does is mark new passwords as tainted and 
#                    raises taint exception when trying to update password (every time)
#                  * having csrf_exempt() means route is insecure, but also worthwile to 
#                    consider that if someone's app is vulnerable to CSRF, they likely don't
#                    have any CSRF token libraries imported/in use

from flask import Flask, request, current_app
from flask_wtf.csrf import CSRFProtect
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
from dataset.cwe_352_csrf.flask_wtf_post.app import csrf

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
    full_name = f"{view_func.__module__}.{view_func.__name__}"
    is_csrf_exempt = full_name in csrf._exempt_views
    return "flask_wtf.csrf" not in sys.modules or is_csrf_exempt 
    

# sink
old_update_password = dataset.cwe_352_csrf.flask_wtf_post.app.update_password

@patch_function(
    "dataset.cwe_352_csrf.flask_wtf_post.app.update_password"
)
def new_update_password(new_password: TaintedStr):
    endpoint = request.endpoint
    app = current_app

    # incorporating sanitizer into monkey patched sink
    if new_password.is_tainted() and is_csrf_vulnerable(app, endpoint):
        raise TaintException("possible vulnerability")
    new_password.sanitize()
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

