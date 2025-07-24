import itertools
import os
import tempfile
import pytest
from flask import Flask

from taintmonkey.fuzzer import (
    Fuzzer,
    DictionaryFuzzer,
    GrammarBasedFuzzer,
    MutationBasedFuzzer,
)
from grammarinator.runtime import *


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
    # Can't instantiate abstract class
    with pytest.raises(TypeError):
        Fuzzer(test_app, dummy_corpus_file)  # type: ignore


def test_dictionary_fuzzer_loads_inputs(test_app, dummy_corpus_file):
    fuzzer = DictionaryFuzzer(test_app, dummy_corpus_file)
    assert sorted(fuzzer.inputs) == ["input1", "input2", "input3"]


def test_dictionary_fuzzer_context_yields_client_and_inputs(
    test_app, dummy_corpus_file
):
    fuzzer = DictionaryFuzzer(test_app, dummy_corpus_file)

    with fuzzer.get_context() as (client, get_input):
        assert callable(client.get)
        assert sorted([inp for inp in get_input()]) == ["input1", "input2", "input3"]


def test_dictionary_fuzzer_load_corpus_missing_file(test_app):
    with pytest.raises(FileNotFoundError):
        DictionaryFuzzer(test_app, "/nonexistent/path/corpus.txt")


def test_dictionary_fuzzer_context_randomization(test_app, dummy_corpus_file):
    fuzzer = DictionaryFuzzer(test_app, dummy_corpus_file)
    seen_orders = set()

    # Shuffle multiple times to check input order changes
    for _ in range(10):
        with fuzzer.get_context() as (_, get_input):
            seen_orders.add(tuple([inp for inp in get_input()]))

    assert len(seen_orders) > 1  # High chance some permutations differ


def test_basic_grammar_based_fuzzer_context_yields_client_and_inputs(test_app):
    fuzzer = GrammarBasedFuzzer(app=test_app)

    with fuzzer.get_context() as (client, get_input):
        assert callable(client.get)

        inputs = list(itertools.islice([next(get_input()) for _ in range(10)], 5))

        assert len(inputs) == 5
        for input in inputs:
            assert isinstance(input, UnparserRule)


def test_key_pool_grammar_based_fuzzer_context_yields_client_and_inputs(test_app):
    fuzzer = GrammarBasedFuzzer(
        app=test_app, key_pool_frequency=0.5, key_pool=["key1", "key2", "key3"]
    )

    with fuzzer.get_context() as (client, get_input):
        assert callable(client.get)

        inputs = list(itertools.islice([next(get_input()) for _ in range(10)], 5))

        assert len(inputs) == 5
        for input in inputs:
            assert isinstance(input, UnparserRule)


def test_grammar_based_fuzzer_context_randomization(test_app):
    fuzzer = GrammarBasedFuzzer(app=test_app)
    seen_inputs = set()

    for _ in range(10):
        with fuzzer.get_context() as (_, get_input):
            input = next(get_input())
            seen_inputs.add(input)

    assert len(seen_inputs) > 1  # High chance some permutations differ


def test_mutation_based_fuzzer_loads_inputs(test_app, dummy_corpus_file):
    fuzzer = MutationBasedFuzzer(app=test_app, corpus=dummy_corpus_file)
    assert sorted(fuzzer.inputs) == ["input1", "input2", "input3"]


def test_mutation_based_fuzzer_load_corpus_missing_file(test_app):
    with pytest.raises(FileNotFoundError):
        MutationBasedFuzzer(test_app, "/nonexistent/path/corpus.txt")


def test_mutation_based_fuzzer_context_randomization(test_app, dummy_corpus_file):
    fuzzer = MutationBasedFuzzer(app=test_app, corpus=dummy_corpus_file)
    seen_inputs = set()

    for _ in range(10):
        with fuzzer.get_context() as (_, get_input):
            input = next(get_input())
            seen_inputs.add(input)

    assert len(seen_inputs) > 1


def test_basic_mutation_based_fuzzer_context_yields_client_and_inputs(
    test_app, dummy_corpus_file
):
    fuzzer = MutationBasedFuzzer(app=test_app, corpus=dummy_corpus_file)

    with fuzzer.get_context() as (client, get_input):
        assert callable(client.get)

        inputs = list(itertools.islice([next(get_input()) for _ in range(10)], 5))

        assert len(inputs) == 5
        for input in inputs:
            assert isinstance(input, str)


def test_params_mutation_based_fuzzer_context_yields_client_and_inputs(
    test_app, dummy_corpus_file
):
    fuzzer = MutationBasedFuzzer(
        app=test_app,
        corpus=dummy_corpus_file,
        min_len=3,
        max_len=10,
        min_mutations=2,
        max_mutations=5,
    )

    with fuzzer.get_context() as (client, get_input):
        assert callable(client.get)

        inputs = list(itertools.islice([next(get_input()) for _ in range(10)], 5))

        assert len(inputs) == 5
        for input in inputs:
            assert isinstance(input, str)
