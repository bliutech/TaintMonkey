# Register taintmonkey as a pytest plugin
import pytest

from demo_app.app import app as flask_app

pytest_plugins = ["taintmonkey"]


@pytest.fixture()
def app():
    return flask_app
