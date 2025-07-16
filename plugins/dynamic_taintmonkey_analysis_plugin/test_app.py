"""
CWD (Current Working Directory) should be TaintMonkey (parent of plugins)
"""

from dynamic_taintmonkey import DynamicTaintMonkey
from random import randint
from flask import Flask

app = Flask(__name__)
app.secret_key = "supersecretkey"

dynamic_test = DynamicTaintMonkey()

secret_code = "Woah so secret"


@dynamic_test.source()
def example_source(skib_skib="Yo"):
    return skib_skib


@dynamic_test.sanitizer(sanitizer_type="sanitizer")
def example_sanitizer(this_string, gurt="yo"):
    if this_string == "Yo":
        return "Gurt"
    else:
        return this_string


def example_yo(this_string, gurt="yo"):
    if this_string == "Yo":
        return "Gurt"
    else:
        return this_string


@app.get("/")
def home():
    example_yo("BRO")


def run_example():
    example_yo("hi")


@dynamic_test.sink()
def example_sink(important_string):
    global secret_code
    secret_code = important_string
    return secret_code


def random_process(given_string):
    for i in range(0, 10):
        given_string = given_string + str(randint(0, 10))
    return given_string


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
