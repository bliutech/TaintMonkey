import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import original_function

import sys

# Define sources, sanitizers, and sinks
VERIFIERS = [
    "dataset.secure_eval_query_json.app.evaluate_math_expression",
    "dataset.secure_eval_query_parameter.app.evaluate_math_expression",
    "dataset.secure_format_string.app.safe_format",
    "dataset.secure_function_access.app.execute_secure",
    "dataset.secure_unchecked_exec.app.execute_secure",
]
SANITIZERS = []
SINKS = ["eval"]


@pytest.fixture()
def taintmonkey():
    from dataset.cwe_94_improper_generation.insecure_eval_query_json.app import app

    tm = TaintMonkey(app, verifiers=VERIFIERS, sanitizers=SANITIZERS, sinks=SINKS)

    fuzzer = DictionaryFuzzer(app, "plugins/cwe_94_improper_generation/corpus.txt")
    tm.set_fuzzer(fuzzer)

    @tm.patch.function(
        "dataset.cwe_94_improper_generation.insecure_eval_query_json.app.calculate_expression"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_94_improper_generation.secure_eval_query_json.app.evaluate_math_expression"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_94_improper_generation.insecure_eval_query_parameter.app.calculate_expression"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_94_improper_generation.secure_eval_query_parameter.app.evaluate_math_expression"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_94_improper_generation.insecure_format_string.app.format_string_eval"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_94_improper_generation.secure_format_string.app.safe_format"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_94_improper_generation.insecure_function_access.app.insecure_function"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_94_improper_generation.secure_function_access.app.execute_secure"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_94_improper_generation.insecure_unchecked_exec.app.execute_insecure"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    @tm.patch.function(
        "dataset.cwe_94_improper_generation.secure_unchecked_exec.app.execute_secure"
    )
    def patched_open_file_command(file: TaintedStr):
        return TaintedStr(original_function(file))

    return tm


def test_fuzz_insecure_eval_query_json(taintmonkey):
    from dataset.cwe_94_improper_generation.insecure_eval_query_json.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_secure_eval_query_json(taintmonkey):
    from dataset.cwe_94_improper_generation.secure_eval_query_json.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_insecure_format_string(taintmonkey):
    from dataset.cwe_94_improper_generation.insecure_format_string.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_secure_format_string(taintmonkey):
    from dataset.cwe_94_improper_generation.secure_format_string.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_insecure_function_access(taintmonkey):
    from dataset.cwe_94_improper_generation.insecure_function_access.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_secure_function_access(taintmonkey):
    from dataset.cwe_94_improper_generation.secure_function_access.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_insecure_unchecked_exec(taintmonkey):
    from dataset.cwe_94_improper_generation.insecure_unchecked_exec.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


def test_fuzz_secure_unchecked_exec(taintmonkey):
    from dataset.cwe_94_improper_generation.secure_unchecked_exec.app import app

    taintmonkey.set_app(app)

    with taintmonkey.get_fuzzer().get_context() as (client, get_input):
        for data in get_input():
            client.get(f"/secure?{urlencode({'file': data})}")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
