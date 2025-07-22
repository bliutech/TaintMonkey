"""
Utility data structures and methods for TaintMonkey.
"""

from flask import Flask
from flask.testing import FlaskClient

from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import Fuzzer
from taintmonkey.patch import extract_module_and_function, load_module, patch_function
from taintmonkey.taint import TaintedStr


class TaintException(Exception):
    pass


class TaintMonkey:
    """
    Core class for TaintMonkey library.
    """

    _old_implementations = {}
    _fuzzer: Fuzzer | None = None

    def __init__(
        self,
        app: Flask,
        sanitizers: list[str] = [],
        verifiers: list[str] = [],
        sinks: list[str] = [],
    ):
        self._app = app
        register_taint_client(app)

        # Methods to be monkey patched
        self._sanitizers = sanitizers
        self._verifiers = verifiers
        self._sinks = sinks

        for sanitizer in sanitizers:
            self.register_sanitizer(sanitizer)

        for verifier in verifiers:
            self.register_verifier(verifier)

        for sink in sinks:
            self.register_sink(sink)

    def get_client(self) -> FlaskClient:
        """
        Get the TaintClient instance associated with the Flask app.
        :return: An instance of TaintClient.
        """
        return self._app.test_client()

    def set_fuzzer(self, fuzzer: Fuzzer):
        """
        Set the fuzzer to be used by TaintMonkey.
        :param fuzzer: An instance of Fuzzer.
        """
        if not isinstance(fuzzer, Fuzzer):
            raise Exception("Invalid fuzzer provided. Must be an instance of Fuzzer.")
        self._fuzzer = fuzzer

    def get_fuzzer(self) -> Fuzzer | None:
        """
        Get the current fuzzer instance.
        :return: An instance of Fuzzer or None if not set.
        """
        if self._fuzzer is None:
            raise Exception("Fuzzer has not been set.")
        return self._fuzzer

    def register_sanitizer(self, sanitizer: str):
        """
        Register a sanitizer to be used by TaintMonkey.
        :param sanitizer: The path of the sanitizer to register.
        """
        if sanitizer not in self._sanitizers:
            self._sanitizers.append(sanitizer)

        # TODO(bliutech): migrate this later to use contextvars in taintmonkey.patch
        # Monkey patch the old sanitizer if it exists
        module_name, func_name = extract_module_and_function(sanitizer)
        module = load_module(module_name)
        func = getattr(module, func_name)
        self._old_implementations[sanitizer] = func

        @patch_function(sanitizer)
        def patched_sanitizer(*args, **kwargs):
            # Call the original sanitizer function
            ts = TaintedStr(self._old_implementations[sanitizer](*args, **kwargs))
            ts.sanitize()
            return ts

    def register_verifier(self, verifier: str):
        """
        Register a verifier to be used by TaintMonkey.
        :param sanitizer: The path of the verifier to register.
        """
        if verifier not in self._verifiers:
            self._verifiers.append(verifier)

        # TODO(bliutech): migrate this later to use contextvars in taintmonkey.patch
        # Monkey patch the old sanitizer if it exists
        module_name, func_name = extract_module_and_function(verifier)
        module = load_module(module_name)
        func = getattr(module, func_name)
        self._old_implementations[verifier] = func

        @patch_function(verifier)
        def patched_verifier(*args, **kwargs):
            # Check each arg to see if it is a TaintedStr
            for arg in args:
                if isinstance(arg, TaintedStr):
                    # If it is, sanitize it
                    arg.sanitize()

            # Check each keyword argument to see if it is a TaintedStr
            for _, value in kwargs.items():
                if isinstance(value, TaintedStr):
                    # If it is, sanitize it
                    value.sanitize()

            # Call the original verifier function
            return self._old_implementations[verifier](*args, **kwargs)

    def register_sink(self, sink: str):
        """
        Register a sink to be used by TaintMonkey.
        :param sink: The path of the sink to register.
        """
        if sink not in self._sinks:
            self._sinks.append(sink)

        # TODO(bliutech): migrate this later to use contextvars in taintmonkey.patch
        # Monkey patch the old sink if it exists
        module_name, func_name = extract_module_and_function(sink)
        module = load_module(module_name)
        func = getattr(module, func_name)
        self._old_implementations[sink] = func

        @patch_function(sink)
        def patched_sink(*args, **kwargs):
            # Check each arg to see if it is a TaintedStr
            for arg in args:
                if isinstance(arg, TaintedStr):
                    # If it is, check if its tainted
                    if arg.is_tainted():
                        raise TaintException()

            # Check each keyword argument to see if it is a TaintedStr
            for _, value in kwargs.items():
                if isinstance(value, TaintedStr):
                    # If it is, check if its tainted
                    if value.is_tainted():
                        raise TaintException()

            return self._old_implementations[sink](*args, **kwargs)
