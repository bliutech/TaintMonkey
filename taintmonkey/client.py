"""
Custom Flask test client for tainting requests.
"""

from flask import Flask, Request, request
from flask.testing import FlaskClient, EnvironBuilder, BaseRequest

import typing as t
from typing import override

import werkzeug
from werkzeug.datastructures.structures import MultiDict, ImmutableMultiDict
from copy import copy

from taintmonkey.taint import TaintedStr


class TaintClient(FlaskClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @override
    def open(
        self,
        *args: t.Any,
        **kwargs: t.Any,
    ):
        """
        Takes advantage of Python's duck typing to clobber the Werkzeug test client's
        request handler `open` function for tainting.

        https://github.com/pallets/werkzeug/blob/main/src/werkzeug/test.py#L1098-L1114
        """

        # checks if environ_overrides dict exists in kwargs
        # if it does, uses the existing one
        # if not, it creates a new empty dict
        # then assigns it to environ_overrides
        environ_overrides = kwargs.setdefault("environ_overrides", {})

        # All requests are assumed to be tainted by default.
        # Add the tainted attribute to Werkzeug request environment.
        environ_overrides["TAINTED"] = True  # type: ignore[assignment]

        # Force execution of https://github.com/pallets/werkzeug/blob/main/src/werkzeug/test.py#L1106
        # to ensure that the request is properly tainted on redirects.
        if isinstance(args[0], werkzeug.test.EnvironBuilder):
            builder = copy(args[0])
            builder.environ_base = self._copy_environ(environ_overrides)  # type: ignore[arg-type]
            args = (builder,)

        return super().open(*args, **kwargs)


class TaintRequest(Request):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._clobber_args()
        self._clobber_form()
        self._clobber_json()

    def is_tainted(self):  # type: ignore
        """
        Checks if the request is tainted.
        """
        return self.environ.get("TAINTED", False)

    def _clobber_args(self):
        new_args = []
        for k, v in self.args.items():
            new_args.append((k, TaintedStr(v)))
        self.args = MultiDict(new_args)  # type: ignore

    def _clobber_form(self):
        new_args = []
        for k, v in self.form.items():
            new_args.append((k, TaintedStr(v)))
        self.form = ImmutableMultiDict(new_args)  # type: ignore

    def _clobber_json(self):
        original_get_json = self.get_json

        def tainted_get_json(*args, **kwargs):
            json_data = original_get_json(*args, **kwargs)
            if json_data is not None and self.is_tainted():
                return self._taint_json_data(json_data)
            return json_data

        self.get_json = tainted_get_json  # type: ignore[method-assign]

    def _taint_json_data(self, data):
        if isinstance(data, str):
            return TaintedStr(data)
        elif isinstance(data, list):
            return [self._taint_json_data(item) for item in data]
        elif isinstance(data, dict):
            return {k: self._taint_json_data(v) for k, v in data.items()}
        return data


def register_taint_client(app: Flask):
    """
    Registers TaintClient class to Flask app to be used
    while testing.

    Example.

    app = Flask(__name__)
    register_taint_client(app)
    """
    app.config.update(
        {
            "TESTING": True,
        }
    )

    # https://github.com/pallets/flask/blob/main/src/flask/wrappers.py#L22
    app.request_class = TaintRequest  # type: ignore[assignment]
    app.test_client_class = TaintClient
