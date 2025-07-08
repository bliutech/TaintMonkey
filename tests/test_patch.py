import pytest

from taintmonkey.patch import (
    PatchException,
    extract_module_and_function,
    load_module,
    type_check,
    patch_function,
)


def test_extract_module_and_function():
    with pytest.raises(PatchException) as e:
        extract_module_and_function("random")
    assert str(e.value) == "Missing module or function from func_path."

    with pytest.raises(PatchException) as e:
        extract_module_and_function("random.")
    assert str(e.value) == "Missing module or function from func_path."

    module, func = extract_module_and_function("random.randint")
    assert module == "random"
    assert func == "randint"

    module, func = extract_module_and_function("foo.bar.baz")
    assert module == "foo.bar"
    assert func == "baz"


def test_load_module():
    with pytest.raises(PatchException) as e:
        load_module("does_not_exist")

    assert str(e.value) == "No module named 'does_not_exist'"

    module_name, _ = extract_module_and_function("random.randint")
    assert module_name == "random"

    module = load_module(module_name)
    assert module == __import__(module_name)


def test_type_check():
    def foo(a: int, b: int) -> int:  # type: ignore
        return 42

    # Incorrect number of arguments
    def bar() -> int:  # type: ignore
        return 42

    with pytest.raises(PatchException) as e:
        type_check(foo, bar)

    assert (
        str(e.value)
        == "Number of function arguments do not match. foo: ['a', 'b'] != bar: []"
    )

    # Incorrect argument type
    def bar(a: str, b: int) -> int:  # type: ignore
        return 42

    with pytest.raises(PatchException) as e:
        type_check(foo, bar)

    assert (
        str(e.value)
        == "Argument types do not match. bar(... a ...): <class 'str'> \u2288 foo(... a ...): <class 'int'>"
    )

    # Incorrect return type
    def bar(a: int, b: int) -> str:
        return "abc"

    with pytest.raises(PatchException) as e:
        type_check(foo, bar)

    assert (
        str(e.value)
        == "Return types do not match. bar: <class 'str'> \u2288 foo: <class 'int'>"
    )

    # Missing annotation. Assume object type and leverage subtyping
    def foo(a: int, b: int):
        return object()  # could be anything

    type_check(foo, bar)


def test_patch_function():
    EXPECTED_VALUE = 42

    @patch_function("random.randint")
    def randint(a: int, b: int) -> int:
        return EXPECTED_VALUE

    import random

    res = random.randint(0, 10)
    assert res == EXPECTED_VALUE
