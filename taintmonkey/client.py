"""
Custom Flask test client for tainting requests.


TODO(bliutech): migrate this example to a unit test.

Example.
app = Flask(__name__)
register_taint_client(app)

@app.route("/", methods=["GET", "POST"])
def example():
    data = request.args.get("example")
    import json
    print("data", type(data), json.dumps(data, indent=4))
    print(data)
    print(request.is_tainted()) # type: ignore
    return "Hello"

app.config.update({
    "TESTING": True,
})

tc = app.test_client()
print(tc.post("/?example=foo", json={
    "example": "data"
}))
"""

from flask import Flask, Request, request
from flask.testing import FlaskClient, EnvironBuilder, BaseRequest

import typing as t
from typing import override

from werkzeug.datastructures.structures import MultiDict

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

        # Build a request object
        # https://github.com/pallets/flask/blob/main/src/flask/testing.py#L228
        request = self._request_from_builder_args(args, kwargs)

        # All requests are assumed to be tainted by default.
        # Add the tainted attribute to Werkzeug request environment.
        request.environ["TAINTED"] = True  # type: ignore[assignment]

        # Force execution of https://github.com/pallets/werkzeug/blob/main/src/werkzeug/test.py#L1106
        return super().open(request)


class TaintRequest(Request):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._clobber_args()

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
