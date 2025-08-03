"""
Utility data structures and methods for TaintMonkey.
"""

from flask import Flask
from flask.testing import FlaskClient

import taintmonkey.patch
from taintmonkey.client import register_taint_client
from taintmonkey.fuzzer import Fuzzer
from taintmonkey.patch import MonkeyPatch
from taintmonkey.taint import TaintedStr


# Monkey patch function that calls after every unit test so that it forces the deleting of TaintMonkey objects
import _pytest.python

old_setup = _pytest.python.Function.setup


def new_setup(self) -> None:
    MonkeyPatch.reset_cache()
    return old_setup(self)


# Set patch_function
patch_function = taintmonkey.patch.patch_function


setattr(_pytest.python.Function, "setup", new_setup)


class TaintException(Exception):
    pass


class TaintMonkey:
    """
    Core class for TaintMonkey library.
    """

    _fuzzer: Fuzzer | None = None
    patch = MonkeyPatch()

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

    def set_app(self, app: Flask):
        self._app = app
        register_taint_client(app)
        if self._fuzzer:
            self._fuzzer.set_app(app)

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

        @TaintMonkey.patch.function(sanitizer)
        def patched_sanitizer(*args, **kwargs):
            # Call the original sanitizer function
            return TaintedStr(
                TaintMonkey.patch.original_function(*args, **kwargs)
            ).sanitize()

    def register_verifier(self, verifier: str):
        """
        Register a verifier to be used by TaintMonkey.
        :param verifier: The path of the verifier to register.
        """
        if verifier not in self._verifiers:
            self._verifiers.append(verifier)

        @TaintMonkey.patch.function(verifier)
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
            return TaintMonkey.patch.original_function(*args, **kwargs)

    def register_sink(self, sink: str):
        """
        Register a sink to be used by TaintMonkey.
        :param sink: The path of the sink to register.
        """
        if sink not in self._sinks:
            self._sinks.append(sink)

        @TaintMonkey.patch.function(sink)
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

            return TaintMonkey.patch.original_function(*args, **kwargs)

    def __del__(self):
        MonkeyPatch.reset_cache()
