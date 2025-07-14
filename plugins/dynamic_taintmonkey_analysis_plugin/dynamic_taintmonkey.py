"""
Dynamic TaintMonkey Analysis Plugin

Meant to dynamically test flask applications without having to manually monkey patch and fuzz

Seeks to automatically taint and fuzz via the user of @source, @sanitizer, and @sink decorators
"""

#TODO: I want to implement a live monkey patching algorithm that tries to find functions that look like they might be
#TODO: user input.

import inspect
import os
from pathlib import Path

import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function

import test_app


class DynamicTaintMonkey:

    def __init__(self):
        self._sources = dict()
        self._sanitizers = dict()
        self._sinks = dict()

    def source(self, func):
        self._sources[func.__name__] = func
        def wrapper(*args, **kwargs):
            return TaintedStr(func(*args, **kwargs))
        return wrapper

    def get_sources(self):
        return self._sources

    def sanitizer(self, sanitizer_type="verify"):

        def decorator(func):
            self._sanitizers[func.__name__] = func

            def wrapper(*args, **kwargs):  # IMPORTANT - the first args should be the tainted string

                #Check argument length
                if not len(args) > 0:
                    raise ValueError("sanitizer - no args passed")
                tainted_string = args[0]

                #Check type
                if  isinstance(tainted_string, str):
                    tainted_string = TaintedStr(tainted_string)
                elif not isinstance(tainted_string, TaintedStr):
                    raise ValueError("sanitizer - first argument is not a tainted string")


                #Sanitize
                if sanitizer_type == "verify":
                    tainted_string.sanitize()
                    return func(*args, **kwargs)
                else:  # TODO: Add more types of sanitizers, right now this is the "sanitizer" type
                    new_tainted_string = TaintedStr(func(*args, **kwargs))
                    new_tainted_string.sanitize()
                    return new_tainted_string

            return wrapper

        return decorator

    def get_sanitizers(self):
        return self._sanitizers


    def sink(self, func):
        self._sinks[func.__name__] = func
        def wrapper(*args, **kwargs):
            if not len(args) > 0:
                raise ValueError("sanitizer - no args passed")
            if not isinstance(args[0], TaintedStr):
                raise ValueError("sanitizer - first argument is not a tainted string")
            tainted_string = args[0]
            if tainted_string.is_tainted():
                raise TaintException("potential vulnerability")
            return func(*args, **kwargs)
        return wrapper

    def get_sinks(self):
        return self._sinks

    @staticmethod
    def get_formatted_path(func_name, func_dict):
        func = func_dict.get(func_name)
        if func is None:
            raise ValueError(f"Function {func_name} not found in dictionary")
        func_path = inspect.getsourcefile(func)
        working_dir = os.getcwd()  # Should be the parent TaintMonkey dir of the repo, otherwise fix
        relative_to_working_dir = Path(func_path).relative_to(Path(working_dir)).with_suffix("")
        func_path = ""  # Reset so we can correctly format
        for part in relative_to_working_dir.parts:
            func_path += part + "."
        func_path += func_name
        return func_path

    #TODO Non functional as of right now - I want to change this functionally
    def monkey_patch_sources(self):
        for func_name in self._sources:
            func = self._sources[func_name]
            func_path = self.get_formatted_path(func_name, self._sources)

            @patch_function(func_path)
            def patched_source(*args, **kwargs):
                print("GURT!")
                return TaintedStr(func(*args, **kwargs))

    #TODO Non functional as of right now - I want to change this functionally
    def monkey_patch_sanitizers(self):
        for func_name in self._sanitizers:
            func = self._sanitizers[func_name]
            func_path = self.get_formatted_path(func_name, self._sanitizers)

            @patch_function(func_path)
            def patched_sanitizer(*args, **kwargs):
                print("GURT!")
                return TaintedStr(func(*args, **kwargs))