"""
patch.py - Patch arbitrary programs using monkey patching.

Inspired heavily by monkey patching capabilities in libraries like...
- unittest: https://docs.python.org/3/library/unittest.mock.html#the-patchers
- pytest: https://docs.pytest.org/en/stable/how-to/monkeypatch.html

This implementation is different in that it attempts to provide a patching
interface outside of unit tests and allows for more arbitrary patching.
"""

from collections.abc import Callable
from types import ModuleType

from importlib import import_module
import inspect

from contextvars import ContextVar

from taintmonkey.taint import TaintedStr


__all__ = ["MonkeyPatch"]


class PatchException(Exception):
    pass


class ContextVarProxy:
    """
    A proxy class for a ContextVar that allows it to be used like a function.

    Inspired by Werkzeug's Context Locals.
    # https://werkzeug.palletsprojects.com/en/stable/local/
    """

    def __init__(self, context_var):
        self._context_var = context_var

    def __call__(self, *args, **kwargs):
        return self._context_var.get()(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._context_var.get(), name)

    def __setattr__(self, name, value):
        if name == "_context_var":
            super().__setattr__(name, value)
        else:
            setattr(self._context_var.get(), name, value)


class PatchAssist:
    """
    Helper functions to check whether one function is patchable to another.

    A function is patchable to another if all associated types in the new
    function's parameters and returns are the same class or subclasses of
    those in their respective original function counterparts.
    """


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


    @staticmethod
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
        import types

        SAFE_TYPES = {
            "List": list,
            "Dict": dict,
            "Union": __import__("typing").Union,
            "Optional": __import__("typing").Optional,
            "Tuple": tuple,
            "int": int,
            "str": str,
            "float": float,
            "bool": bool,
            "object": object,
            "Any": __import__("typing").Any,
            "TaintedStr": TaintedStr,
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
            elif isinstance(node, ast.BinOp):
                return is_safe_annotation(node.left) and is_safe_annotation(node.right)
            return False

        def safe_parse_type(type_str: str) -> ast.AST:
            # Evaluate just the last part of the string
            # if there are dots just refer to the last class shown, not full path
            # example: taintmonkey.taint.TaintedStr --> TaintedStr
            if "." in type_str:
                index = 0
                for i in range(len(type_str)):
                    if type_str[i] == ".":
                        index = i
                type_str = type_str[index + 1:]
            expr = ast.parse(type_str, mode="eval")
            if not is_safe_annotation(expr.body):
                raise ValueError("Unsafe type annotation")
            return expr.body

        def reconstruct_type(type_str: str):
            node = safe_parse_type(type_str)
            return eval(
                compile(ast.Expression(node), "<string>", "eval"),
                {"__builtins__": {}},
                SAFE_TYPES,
            )

        def standardize_and_check_annotations(this_orig_type, this_new_type, test):
            # Special case with none type, because none doesn't work with issubclass()
            if this_new_type is None and this_orig_type is None:
                return

            if not issubclass(this_new_type, this_orig_type):
                if test == "args":
                    raise PatchException(
                        f"Argument types do not match. {new_f.__name__}(... {n} ...): {this_new_type} \u2288 {orig_f.__name__}(... {o} ...): {this_orig_type}"
                    )
                elif test == "vararg":
                    raise PatchException(
                        f"Variable argument types do not match. {new_f.__name__}(... {n} ...): {this_new_type} \u2288 {orig_f.__name__}(... {o} ...): {this_orig_type}"
                    )
                else:
                    raise PatchException(
                        f"Return types do not match. {new_f.__name__}: {this_new_type} \u2288 {orig_f.__name__}: {this_orig_type}"
                    )

        # Checks to see if the types are right
        def check(this_orig, this_new, test):
            # Reconstruct if needed
            try:
                this_orig = reconstruct_type(this_orig)
            except TypeError:
                pass
            try:
                this_new = reconstruct_type(this_new)
            except TypeError:
                pass
            if isinstance(this_orig, types.UnionType) or isinstance(
                    this_new, types.UnionType
            ):
                # Iterate through type in Union types
                orig_union_types = this_orig.__args__
                new_union_types = this_new.__args__

                # Check length
                if len(orig_union_types) != len(new_union_types):
                    raise PatchException(f"Number of union arguments do not match.")

                # Loop through
                for i in range(len(orig_union_types)):
                    orig_union_type = orig_union_types[i]
                    new_union_type = new_union_types[i]
                    # Standardize annotations
                    standardize_and_check_annotations(orig_union_type, new_union_type, test)

            else:
                # Standardize annotations
                standardize_and_check_annotations(this_orig, this_new, test)

        """CONTINUE WITH CODE"""

        # Get signatures
        orig_sig = inspect.getfullargspec(orig_f)
        new_sig = inspect.getfullargspec(new_f)

        # Check matching return type matches subtype relation
        orig_ret = orig_sig.annotations.get("return", object)
        new_ret = new_sig.annotations.get("return", object)
        check(orig_ret, new_ret, "ret")

        # If the new function has both varargs and varkw, it automatically matches
        if new_sig.varargs and new_sig.varkw:
            return

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
            orig_arg = orig_sig.annotations.get(o, object)
            new_arg = new_sig.annotations.get(n, object)
            check(orig_arg, new_arg, "args")

        # Check matching return type vararg subtype relation
        orig_vararg = orig_sig.annotations.get(orig_sig.varargs, object)
        new_vararg = new_sig.annotations.get(new_sig.varargs, object)
        check(orig_vararg, new_vararg, "vararg")


class MonkeyPatch:
    """
    This class provides all functionality for patching functions.

    It is used by the TaintMonkey class, but functions can also be
    used individually for more nuanced use.

    Inspired heavily by monkey patching capabilities in libraries like...
    - unittest: https://docs.python.org/3/library/unittest.mock.html#the-patchers
    - pytest: https://docs.pytest.org/en/stable/how-to/monkeypatch.html
    """

    _patch_ctx = ContextVar("patch_ctx")
    original_function = ContextVarProxy(_patch_ctx)
    _patched_function_cache: dict[str, list[tuple[int, tuple[object, str, object]]]] = {}


    @staticmethod
    def patch_function(func_path: str, group: int = -1):
        """
        Decorator to monkey patch a function.

        :param func_path: the function path of the added patched function as a string separated by .
        :param group: the affiliated group number that this patch belongs to (typically assigned by TaintMonkey object).
        If you want to create your own custom group, it is recommended to use negative values because positive values
        will be used by TaintMonkey instances. The value 0 is reserved for the original function prior to any monkey
        patching done by this class. Using the value 0 unwisely can lead to errors, proceed with caution
        """
        module_name, func_name = PatchAssist.extract_module_and_function(func_path)

        # Monkey patcher decorator
        def patcher(f):
            module = PatchAssist.load_module(module_name)
            func = getattr(module, func_name)

            PatchAssist.type_check(func, f)
            setattr(module, func_name, f)

            MonkeyPatch.add_patched_function(func_path, (module, func_name, func), group)

            # Store the original function in context variable
            MonkeyPatch._patch_ctx.set(func)

            return f

        return patcher


    @staticmethod
    def add_patched_function(func_path: str, orig_info: tuple[object, str, object], group: int):
        """
        Adds information on a patched function to the cache (shared between all instances)

        The cache is formatted as so:
        Parent Dictionary with func_names as keys
        --> Values: List of monkey patching change logs
        ----> Values: Tuples with the following info:
        ------> Index One
        ------> Index Two: Tuples with the original module, function name, and function object

        If the function has been patched, the info is simply added to its respective change log list

        If this function has not been patched before, the original info passed becomes the default function that will be
        preserved at the first index of the newly created change log list (0). Its tuple will also be assigned group 0.
        Be cautious adding to group 0.

        :param func_path: the function path of the added patched function as a string separated by .
        :param orig_info: a tuple of the original module, function name, and function object
        :param group: the affiliated group number that this patch belongs to (typically assigned by TaintMonkey object)
        Refer to the function patch_function to see how group numbers should be chosen.
        """
        pfc = MonkeyPatch._patched_function_cache

        if pfc.get(func_path) is None:
            pfc[func_path] = [(0, orig_info), (group, orig_info)]
        else:
            pfc[func_path].append((group, orig_info))

        print(pfc)


    @staticmethod
    def remove_patches(group: int):
        """
        Removes all patches associated with the given group number and refreshes the patching. It will switch the
        function back to the most recent patched version of itself, or the original function that is stored at index 0
        with group 0 (unless tampered with)

        :param group: the affiliated group number that this patch belongs to (typically assigned by TaintMonkey object)
        """
        pfc = MonkeyPatch._patched_function_cache

        for func_name in pfc:
            change_logs = pfc[func_name]

            for i in range(len(change_logs) - 1, -1, -1):
                change_log = change_logs[i]

                cl_group = change_log[0]
                if cl_group == group:
                    change_logs.pop(i)

        MonkeyPatch.update_patches()


    @staticmethod
    def update_patches():
        pfc = MonkeyPatch._patched_function_cache

        for change_logs in list(pfc.values()):
            if len(change_logs) > 0:
                module, func_name, func = change_logs[-1][1]

                setattr(module, func_name, func)


    @staticmethod
    def reset_cache():
        pfc = MonkeyPatch._patched_function_cache

        for change_logs in list(pfc.values()):
            done = False

            for change_log in change_logs:
                if not done and change_log[0] == 0:
                    module, func_name, func = change_log[0]

                    setattr(module, func_name, func)

                    done = True

        pfc = {}

    '''def patch_function(self, func_path: str):
        """
        Decorator to monkey patch a function.
        """
        module_name, func_name = PatchAssist.extract_module_and_function(func_path)

        # Monkey patcher decorator
        def patcher(f):
            module = PatchAssist.load_module(module_name)
            func = getattr(module, func_name)
            PatchAssist.type_check(func, f)
            setattr(module, func_name, f)
            # Store the original function in context variable
            MonkeyPatch._patch_ctx.set(func)
            return f

        return patcher'''


    @staticmethod
    def patch_class(class_path: str):
        """
        Monkey patches a class.
        """
        # TODO(bliutech): add a similar monkey patcher decorator for classes / objects
        pass
