from flask import Flask, request

from os import popen

app = Flask(__name__)


def is_safe_name(name: str):
    # Example of a simple sanitization check
    return all(c.isalnum() or c in ("-", "_") for c in name)


def get_command(name: str):
    return f"cat {name}"


@app.get("/insecure")
def insecure_retrieve_file_contents():
    name = request.args.get("name", "default")  # Source
    contents = popen(get_command(name)).read()  # Sink
    return contents


@app.get("/secure")
def secure_retrieve_file_contents():
    name = request.args.get("name", "default")  # Source
    if not is_safe_name(name):
        return "Invalid name", 400
    contents = popen(get_command(name)).read()  # Sink
    return contents
