import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function

from urllib.parse import urlencode

SOURCES = []
SANITIZERS = []
SINKS = ["eval"]


def is_dangerous(expr):
    dangerous_patterns = ["__", "import", "eval", "exec", "open", "os.", "subprocess"]
    return any(pattern in str(expr) for pattern in dangerous_patterns)


@patch_function(
    "dataset.cwe_94_improper_generation.insecure_eval_query_parameter.app.calculate_expression"
)
def new_calculate_expression(expression):
    try:
        if (
            isinstance(expression, TaintedStr)
            and expression.is_tainted()
            and is_dangerous(expression)
        ):
            raise TaintException("Potential code injection vulnerability")
        return eval(expression)
    except TaintException:
        raise
    except Exception:
        return "Error"


@pytest.fixture()
def app():
    from dataset.cwe_94_improper_generation.insecure_eval_query_parameter.app import app

    register_taint_client(app)
    return app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def fuzzer(app):
    return DictionaryFuzzer(app, "plugins/cwe_94_improper_generation/corpus.txt")


def test_taint_exception(client):
    with pytest.raises(TaintException):
        client.get("/calculate?expr=__import__('os').system('ls')")


def test_no_taint_exception(client):
    response = client.get("/calculate?expr=2%2B2")
    assert response.status_code == 200


def test_fuzz(fuzzer):
    with fuzzer.get_context() as (client, get_input):
        for data in get_input():
            with pytest.raises(TaintException):
                client.get(f"/calculate?{urlencode({'expr': data})}")


if __name__ == "__main__":
    pytest.main([__file__])
