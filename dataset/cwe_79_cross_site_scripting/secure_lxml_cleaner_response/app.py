# https://lxml.de/api/lxml.html.clean.Cleaner-class.html

from flask import Flask, request
from lxml.html.clean import Cleaner

app = Flask(__name__)


def user_input(score):
    return f"Your grade: {score}/100"


@app.route("/grade_secure")
def grade_secure():
    score = request.args.get("score", 0)
    cleaner = Cleaner(scripts=True, javascript=True, style=True)
    cleaned_score = cleaner.clean_html(score)
    return user_input(cleaned_score)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
