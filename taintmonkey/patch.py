"""
patch.py - Patch arbitrary programs using monkey patching.

Inspired heavily by monkey patching capabilities in libraries like...
- unittest: https://docs.python.org/3/library/unittest.mock.html#the-patchers
- pytest: https://docs.pytest.org/en/stable/how-to/monkeypatch.html

This implementation is different in that it attempts to provide a patching
interface outside of unit tests and allows for more arbitrary patching.
"""

from collections.abc import Callable
from importlib import import_module
import inspect
from types import ModuleType

__all__ = ["patch_function", "patch_class"]


class PatchException(Exception):
    pass


def extract_module_and_function(func_path: str) -> tuple[str, str]:
    """
    Extracts module and function names from path.
    """

    # Remove empty strings from path
    path = [x for x in filter(lambda xi: xi, func_path.split("."))]
    if len(path) < 2:
        raise PatchException("Missing module or function from func_path.")

    module = ".".join(path[:-1])
    func = path[-1]

    return (module, func)


def load_module(module_name: str) -> ModuleType:
    try:
        module = import_module(module_name)
    except Exception as e:
        raise PatchException(e)

    return module


def type_check(orig_f: Callable, new_f: Callable):
    """
    Type checks the original function with the function used
    for monkey patching to ensure that they have the same type
    signature.

    Raises an exception if part of the function signature does not match.
    """

    orig_sig = inspect.getfullargspec(orig_f)
    new_sig = inspect.getfullargspec(new_f)

    # Remove "self" from argument list. For the purposes of monkey patching,
    # we do not care if it type checks (does not matter).
    orig_args = [arg for arg in filter(lambda x: x != "self", orig_sig.args)]
    new_args = new_sig.args

    # Check matching # of args
    if len(new_args) != len(orig_args):
        raise PatchException(
            f"Number of function arguments do not match. {orig_f.__name__}: {orig_args} != {new_f.__name__}: {new_args}"
        )

    # Check matching argument type
    for o, n in zip(orig_args, new_args):
        orig_type = orig_sig.annotations.get(o, object)
        new_type = new_sig.annotations.get(n, object)
        if not issubclass(new_type, orig_type):
            raise PatchException(
                f"Argument types do not match. {new_f.__name__}(... {n} ...): {new_type} \u2288 {orig_f.__name__}(... {o} ...): {orig_type}"
            )

    # Check matching return type matches subtype relation
    orig_ret = orig_sig.annotations.get("return", object)
    new_ret = new_sig.annotations.get("return", object)
    if not issubclass(new_ret, orig_ret):
        raise PatchException(
            f"Return types do not match. {new_f.__name__}: {new_ret} \u2288 {orig_f.__name__}: {orig_ret}"
        )


def patch_function(func_path: str):
    """
    Decorator to monkey patch a function.
    """
    module_name, func_name = extract_module_and_function(func_path)

    # Monkey patcher decorator
    def patcher(f):
        module = load_module(module_name)
        func = getattr(module, func_name)
        type_check(func, f)
        setattr(module, func_name, f)
        return f

    return patcher


def patch_class(class_path: str):
    """
    Monkey patches a class.
    """
    # TODO(bliutech): add a similar monkey patcher decorator for classes / objects
    pass
