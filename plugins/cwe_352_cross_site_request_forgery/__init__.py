from flask import Flask, request, current_app
from flask_wtf.csrf import CSRFProtect
import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer, GrammarBasedFuzzer, MutationBasedFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function

import sys
from urllib.parse import urlencode

SOURCES = []
SANITIZERS = []
SINKS = ["insecure_update"]

# monkey patching

import dataset.cwe_352_cross_site_request_forgery.flask_wtf_post.app
from dataset.cwe_352_cross_site_request_forgery.flask_wtf_post.app import csrf


# # sanitizer
def is_csrf_vulnerable(app: Flask, endpoint: str):
    view_func = app.view_functions.get(endpoint)
    full_name = f"{view_func.__module__}.{view_func.__name__}"
    is_csrf_exempt = full_name in csrf._exempt_views
    return "flask_wtf.csrf" not in sys.modules or is_csrf_exempt


old_insecure_update = (
    dataset.cwe_352_cross_site_request_forgery.flask_wtf_post.app.insecure_update
)


@csrf.exempt
@dataset.cwe_352_cross_site_request_forgery.flask_wtf_post.app.login_required
def new_insecure_update():
    endpoint = request.endpoint
    app = current_app

    if is_csrf_vulnerable(app, endpoint):
        raise TaintException("possible vulnerability")
    return old_insecure_update()


dataset.cwe_352_cross_site_request_forgery.flask_wtf_post.app.app.view_functions[
    "insecure_update"
] = new_insecure_update


@pytest.fixture()
def app():
    from dataset.cwe_352_cross_site_request_forgery.flask_wtf_post.app import app

    register_taint_client(app)

    yield app


@pytest.fixture()
def client(app):
    return app.test_client(use_cookies=True)


@pytest.fixture()
def fuzzer(app):
    return MutationBasedFuzzer(
        app=app, corpus="plugins/cwe_352_cross_site_request_forgery/corpus.txt"
    )


def test_fuzz(app, fuzzer):
    with fuzzer.get_context() as (attacker, input_generator):
        for _, data in zip(range(10), input_generator()):
            victim = app.test_client()
            response = victim.post("/register?username=test&password=test")
            response = victim.post("/login?username=test&password=test")

            session_cookie = victim.get_cookie("session")
            assert session_cookie is not None

            attacker.set_cookie(
                domain="localhost", key="session", value=session_cookie.value
            )
            # some test files use get instead
            response = attacker.post(
                "/insecure-update", json={"new_password": "my_new_password"}
            )
            print(response.data.decode())


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
