import pytest
from flask import Flask, request, redirect, url_for

from taintmonkey.client import register_taint_client
from taintmonkey.taint import TaintedStr


@pytest.fixture
def app():
    app = Flask(__name__)
    register_taint_client(app)

    @app.route("/query", methods=["GET"])
    def query():
        val = request.args.get("key")
        return {
            "value": val,
            "type": str(type(val)),
            "tainted": request.is_tainted(),  # type: ignore
        }

    @app.route("/form", methods=["POST"])
    def form():
        val = request.form.get("key")
        return {
            "value": val,
            "type": str(type(val)),
            "tainted": request.is_tainted(),  # type: ignore
        }

    @app.route("/redirect", methods=["GET"])
    def redirect_handler():
        return redirect(url_for("query", key="redirect"))

    return app


def test_query_param_is_tainted_and_wrapped(app):
    client = app.test_client()
    response = client.get("/query?key=hello")
    data = response.get_json()

    assert data["value"] == "hello"
    assert "TaintedStr" in data["type"]
    assert data["tainted"] is True


def test_form_param_is_tainted_and_wrapped(app):
    client = app.test_client()
    response = client.post("/form", data={"key": "hello"})
    data = response.get_json()

    assert data["value"] == "hello"
    assert "TaintedStr" in data["type"]
    assert data["tainted"] is True


def test_tainted_str_behavior(app):
    client = app.test_client()
    response = client.get("/query?key=world")
    data = response.get_json()

    assert data["value"] == "world"
    assert "TaintedStr" in data["type"]


def test_request_is_marked_tainted(app):
    client = app.test_client()
    response = client.get("/query?key=test")
    data = response.get_json()

    assert data["tainted"] is True


def test_follow_redirects(app):
    client = app.test_client()
    response = client.get("/redirect", follow_redirects=True)
    data = response.get_json()
    print(data)

    assert data["value"] == "redirect"
    assert "TaintedStr" in data["type"]
    assert data["tainted"] is True
