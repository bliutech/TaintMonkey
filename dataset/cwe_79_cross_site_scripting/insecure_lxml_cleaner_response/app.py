# https://lxml.de/api/lxml.html.clean.Cleaner-class.html

from flask import Flask, request
from lxml.html.clean import Cleaner

app = Flask(__name__)


def user_input(score):
    return f"Your grade: {score}/100"


@app.route("/grade_insecure")
def grade_insecure():
    score = request.args.get("score")
    return user_input(score)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
