"""
patch.py - Patch arbitrary programs using monkey patching.

Inspired heavily by monkey patching capabilities in libraries like...
- unittest: https://docs.python.org/3/library/unittest.mock.html#the-patchers
- pytest: https://docs.pytest.org/en/stable/how-to/monkeypatch.html

This implementation is different in that it attempts to provide a patching
interface outside of unit tests and allows for more arbitrary patching.
"""
import typing
from collections.abc import Callable
from importlib import import_module
import inspect
from types import ModuleType

__all__ = ["patch_function", "patch_class"]

from jinja2 import is_undefined


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

    """HELPER FUNCTIONS"""
    # Properly check types in case of things like annotations
    import ast
    from typing import Union, get_origin, get_type_hints

    SAFE_TYPES = {
        'List': list,
        'Dict': dict,
        'Union': __import__('typing').Union,
        'Optional': __import__('typing').Optional,
        'Tuple': tuple,
        'int': int,
        'str': str,
        'float': float,
        'bool': bool,
        'Any': __import__('typing').Any,
    }

    def is_safe_annotation(node: ast.AST) -> bool:
        """Recursively check that the AST only contains safe identifiers and subscripts."""
        if isinstance(node, ast.Name):
            return node.id in SAFE_TYPES
        elif isinstance(node, ast.Subscript):
            return is_safe_annotation(node.value) and is_safe_annotation(node.slice)
        elif isinstance(node, ast.Tuple):
            return all(is_safe_annotation(elt) for elt in node.elts)
        elif isinstance(node, ast.Attribute):
            return False
        elif isinstance(node, ast.Constant):
            return True
        return False

    def safe_parse_type(type_str: str) -> ast.AST:
        expr = ast.parse(type_str, mode='eval')
        if not is_safe_annotation(expr.body):
            raise ValueError("Unsafe type annotation")
        return expr.body

    def reconstruct_type(type_str: str):
        node = safe_parse_type(type_str)
        return eval(compile(ast.Expression(node), "<string>", "eval"), {"__builtins__": {}}, SAFE_TYPES)

    """CONTINUE WITH CODE"""

    orig_sig = inspect.getfullargspec(orig_f)
    new_sig = inspect.getfullargspec(new_f)

    #Print sigs (see difference in annotations)
    print(orig_sig)
    print(new_sig)

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

        #Standardize annotations
        try:
            orig_type = reconstruct_type(orig_type)
        except ValueError:
            print("BAD VALUE - OLD")
            raise ValueError()
        except TypeError:
            print("BAD TYPE - OLD")

        try:
            new_type = reconstruct_type(new_type)
        except ValueError:
            print("BAD VALUE - NEW")
            raise ValueError()
        except TypeError:
            print("BAD TYPE - NEW")

        print("GURT", orig_type, "YO", new_type)
        if not issubclass(new_type, orig_type):
            raise PatchException(
                f"Argument types do not match. {new_f.__name__}(... {n} ...): {new_type} \u2288 {orig_f.__name__}(... {o} ...): {orig_type}"
            )

    # Check matching return type matches subtype relation
    """
    THIS IS NOT DOING TOO HOT. PROBLEM IS THAT IT IS UNABLE TO HANDLE UNIONS FROM WHAT I CAN TELL
    I TRIED MAKING SOME FIXES BUT I THINK IT'S A LITTLE OVER MY HEAD AND I DON'T WANT TO DO SOMETHING DUMB THAT MIGHT
    EXPOSE A VULNERABILITY/DOESN'T WORK FOR ALL CASES
    """
    orig_ret = orig_sig.annotations.get("return", object)
    new_ret = new_sig.annotations.get("return", object)
    print("gurt", orig_ret, "yo", new_ret)
    print("gurt", type(orig_ret), "yo", type(orig_ret))
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
