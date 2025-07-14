"""
Dynamic TaintMonkey Analysis Plugin

Meant to dynamically test flask applications without having to manually monkey patch and fuzz

Seeks to automatically taint and fuzz via the user of @source, @sanitizer, and @sink decorators
"""
import inspect
import os
from pathlib import Path

import pytest

from taintmonkey import TaintException
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import DictionaryFuzzer
from taintmonkey.taint import TaintedStr
from taintmonkey.patch import patch_function


class DynamicTaintMonkey:

    def __init__(self):
        self._sources = dict()
        self._sanitizers = dict()
        self._sinks = dict()

    def source(self, func):
        self._sources[func.__name__] = func
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper

    def get_sources(self):
        return self._sources

    def sanitizer(self, func):
        print("HELLO")
        self._sanitizers[func.__name__] = func
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper

    def get_sanitizers(self):
        return self._sanitizers


    def sink(self, func):
        self._sinks[func.__name__] = func
        def wrapper(*args, **kwargs):
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

    #TODO Non functional as of right now
    def monkey_patch_sources(self):
        for func_name in self._sources:
            func = self._sources[func_name]
            func_path = self.get_formatted_path(func_name, self._sources)

            def make_patched_source(original_func):
                print(func_path)
                @patch_function(func_path)
                def patched_source(*args, **kwargs):
                    print("GURT!")
                    return TaintedStr(original_func(*args, **kwargs))
                return patched_source

            make_patched_source(func)()

    #TODO Non functional as of right now
    def monkey_patch_sanitizers(self):
        for func_name in self._sanitizers:
            func = self._sanitizers[func_name]
            func_path = self.get_formatted_path(func_name, self._sanitizers)

            @patch_function(func_path)
            def patched_source(*args, **kwargs):
                print("GURT!")
                return TaintedStr(func(*args, **kwargs))