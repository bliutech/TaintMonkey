## https://markupsafe.palletsprojects.com/en/stable/
from markupsafe import escape
from flask import Flask, request

app = Flask(__name__)


def suspicious_input(name):
    upd_name = escape(name)

    return name != upd_name


def table(name):
    return f"""
    <table border="1">
        <tr>
            <th>Name</th>
        </tr>
        <tr>
            <td>{name}</td>
        </tr>
    </table>
    """


@app.route("/insecure_table")
def insecure_table():
    name = request.args.get("name", "")
    return table(name)


@app.route("/secure_table")
def secure_table():
    name = request.args.get("name", "")

    if suspicious_input(name):
        return "Invalid input detected", 400

    return table(name)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
