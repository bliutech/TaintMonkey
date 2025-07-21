"""
Custom Flask test client for tainting requests.
"""

from flask import Flask, Request, request
from flask.testing import FlaskClient, EnvironBuilder, BaseRequest

import typing as t
from typing import override

from werkzeug.datastructures.structures import MultiDict, ImmutableMultiDict

from taintmonkey.taint import TaintedStr


# TODO: add TaintClient session handling
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
        return super().open(*args, **kwargs)


class TaintRequest(Request):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._clobber_args()
        self._clobber_form()

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

    # TODO(bliutech): add support for other request constructs
    # such as JSON (i.e. request.json())


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
    app.request_class = TaintRequest
    app.test_client_class = TaintClient
