import pytest

from taintmonkey import TaintException, TaintMonkey
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.patch import patch_function, original_function
from taintmonkey.taint import TaintedStr

from urllib.parse import urlencode

VERIFIERS = [
    "demo_app.app.is_safe_name",
]
SANITIZERS = []
SINKS = ["os.popen"]


@pytest.fixture()
def taintmonkey(app):
    tm = TaintMonkey(app, sinks=SINKS, sanitizers=SANITIZERS, verifiers=VERIFIERS)

    fuzzer = DictionaryFuzzer(app, "tests/corpus.txt")
    tm.set_fuzzer(fuzzer)

    @patch_function("demo_app.app.get_command")
    def new_get_command(name: TaintedStr):
        res = TaintedStr(original_function(name))
        if not name.is_tainted():
            res.sanitize()
        return res

    return tm


def test_fuzz_insecure_endpoint(taintmonkey):
    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for inp in get_input():
            with pytest.raises(TaintException):
                client.get(f"/insecure?{urlencode({'name': inp})}")


def test_fuzz_secure_endpoint(taintmonkey):
    fuzzer = taintmonkey.get_fuzzer()
    with fuzzer.get_context() as (client, get_input):
        for inp in get_input():
            client.get(f"/secure?{urlencode({'name': inp})}")
