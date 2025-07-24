import pytest
from unittest.mock import MagicMock, patch

from flask import Flask

from taintmonkey import TaintMonkey, TaintException


@pytest.fixture
def flask_app():
    return Flask(__name__)


@pytest.fixture
def mock_patch(monkeypatch):
    def patch_function_mock(path):
        def decorator(func):
            return func

        return decorator

    monkeypatch.setattr("taintmonkey.patch_function", patch_function_mock)
    monkeypatch.setattr("taintmonkey.original_function", lambda *a, **kw: "original")
    return patch_function_mock


@pytest.fixture
def mock_register_taint_client(monkeypatch):
    monkeypatch.setattr("taintmonkey.register_taint_client", MagicMock())


@pytest.fixture
def mock_tainted_str(monkeypatch):
    class MockTaintedStr(str):
        def __new__(cls, val):
            return super().__new__(cls, val)

        def sanitize(self):
            self.sanitized = True  # type: ignore

        def is_tainted(self):
            return getattr(self, "_tainted", True)

        def set_tainted(self, tainted):
            self._tainted = tainted  # type: ignore

    monkeypatch.setattr("taintmonkey.TaintedStr", MockTaintedStr)
    return MockTaintedStr


def test_constructor_registers_lists(flask_app, mock_patch, mock_register_taint_client):
    tm = TaintMonkey(
        app=flask_app,
        sanitizers=["a.sanitize"],
        verifiers=["b.verify"],
        sinks=["c.sink"],
    )

    assert "a.sanitize" in tm._sanitizers
    assert "b.verify" in tm._verifiers
    assert "c.sink" in tm._sinks


def test_get_client_returns_flask_client(
    flask_app, mock_patch, mock_register_taint_client
):
    tm = TaintMonkey(app=flask_app)
    client = tm.get_client()
    assert hasattr(client, "get")
    assert callable(client.get)


def test_set_fuzzer_with_invalid_type_raises(
    flask_app, mock_patch, mock_register_taint_client
):
    tm = TaintMonkey(app=flask_app)
    with pytest.raises(Exception, match="Invalid fuzzer provided"):
        tm.set_fuzzer("not a fuzzer")  # type: ignore


def test_set_and_get_fuzzer(flask_app, mock_patch, mock_register_taint_client):
    from taintmonkey.fuzzer import Fuzzer

    tm = TaintMonkey(app=flask_app)
    fuzzer = MagicMock(spec=Fuzzer)
    tm.set_fuzzer(fuzzer)
    assert tm.get_fuzzer() == fuzzer


def test_get_fuzzer_not_set_raises(flask_app, mock_patch, mock_register_taint_client):
    tm = TaintMonkey(app=flask_app)
    with pytest.raises(Exception, match="Fuzzer has not been set"):
        tm.get_fuzzer()


def test_register_sanitizer_adds_and_patches(
    monkeypatch, flask_app, mock_register_taint_client, mock_tainted_str
):
    patched = {}

    def patch_function_mock(path):
        def decorator(func):
            patched[path] = func
            return func

        return decorator

    monkeypatch.setattr("taintmonkey.patch_function", patch_function_mock)
    monkeypatch.setattr("taintmonkey.original_function", lambda *a, **kw: "clean")

    tm = TaintMonkey(app=flask_app)
    tm.register_sanitizer("sanitize.func")
    assert "sanitize.func" in patched
    result = patched["sanitize.func"]("test")
    assert isinstance(result, mock_tainted_str)


def test_register_sink_blocks_tainted(
    monkeypatch, flask_app, mock_register_taint_client, mock_tainted_str
):
    monkeypatch.setattr("taintmonkey.original_function", lambda *a, **kw: "ok")

    patched_functions = {}

    def patch_function_mock(path):
        def decorator(func):
            patched_functions[path] = func
            return func

        return decorator

    monkeypatch.setattr("taintmonkey.patch_function", patch_function_mock)

    tm = TaintMonkey(app=flask_app)
    tm.register_sink("sink.func")

    assert tm._sinks == ["sink.func"]
    assert "sink.func" in patched_functions

    # Test that calling the patched sink raises if input is tainted
    tainted = mock_tainted_str("bad")
    tainted.set_tainted(True)

    with pytest.raises(TaintException):
        patched_functions["sink.func"](tainted)

    # Test that calling the patched sink passes if input is clean
    clean = mock_tainted_str("good")
    clean.set_tainted(False)

    assert patched_functions["sink.func"](clean) == "ok"


def test_register_verifier_sanitizes(
    monkeypatch, flask_app, mock_register_taint_client, mock_tainted_str
):
    monkeypatch.setattr("taintmonkey.original_function", lambda *a, **kw: "verified")

    patched_functions = {}

    def patch_function_mock(path):
        def decorator(func):
            patched_functions[path] = func
            return func

        return decorator

    monkeypatch.setattr("taintmonkey.patch_function", patch_function_mock)

    tm = TaintMonkey(app=flask_app)
    tm.register_verifier("verify.func")

    assert tm._verifiers == ["verify.func"]
    assert "verify.func" in patched_functions

    tainted = mock_tainted_str("test")
    tainted.sanitize = MagicMock()

    result = patched_functions["verify.func"](tainted)

    tainted.sanitize.assert_called_once()
    assert result == "verified"
