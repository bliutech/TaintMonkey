import os
import tempfile
import pytest
from flask import Flask

from taintmonkey.fuzzer import Fuzzer, DictionaryFuzzer


@pytest.fixture
def test_app():
    app = Flask(__name__)
    app.config.update(TESTING=True)

    @app.route("/echo")
    def echo():
        return "OK"

    return app


@pytest.fixture
def dummy_corpus_file():
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
        f.write("input1\ninput2\ninput3\n")
        f.flush()
        yield f.name
    os.remove(f.name)


def test_fuzzer_abstract_class_raises(test_app, dummy_corpus_file):
    with pytest.raises(TypeError):
        Fuzzer(test_app, dummy_corpus_file)  # Can't instantiate abstract class


def test_dictionary_fuzzer_loads_inputs(test_app, dummy_corpus_file):
    fuzzer = DictionaryFuzzer(test_app, dummy_corpus_file)
    assert sorted(fuzzer.inputs) == ["input1", "input2", "input3"]


def test_dictionary_fuzzer_context_yields_client_and_inputs(
    test_app, dummy_corpus_file
):
    fuzzer = DictionaryFuzzer(test_app, dummy_corpus_file)

    with fuzzer.get_context() as (client, inputs):
        assert callable(client.get)
        assert sorted(inputs) == ["input1", "input2", "input3"]


def test_fuzzer_load_corpus_missing_file(test_app):
    with pytest.raises(FileNotFoundError):
        DictionaryFuzzer(test_app, "/nonexistent/path/corpus.txt")


def test_fuzzer_context_randomization(test_app, dummy_corpus_file):
    fuzzer = DictionaryFuzzer(test_app, dummy_corpus_file)
    seen_orders = set()

    # Shuffle multiple times to check input order changes
    for _ in range(10):
        with fuzzer.get_context() as (_, inputs):
            seen_orders.add(tuple(inputs))

    assert len(seen_orders) > 1  # High chance some permutations differ
