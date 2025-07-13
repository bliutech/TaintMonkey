## https://markupsafe.palletsprojects.com/en/stable/
from markupsafe import escape
from flask import Flask, request

app = Flask(__name__)


def suspicious_input(name, age):
    upd_name = escape(name)
    upd_age = escape(age)

    if name != upd_name or age != upd_age:
        return True
    return False


def table(name, age):
    return f"""
    <table border="1">
        <tr>
            <th>Name</th>
            <th>Age</th>
        </tr>
        <tr>
            <td>{name}</td>
            <td>{age}</td>
        </tr>
    </table>
    """


@app.route("/insecure_table")
def insecure_table():
    name = request.args.get("name", "")
    age = request.args.get("age", "")
    return table(name, age)


@app.route("/secure_table")
def secure_table():
    name = request.args.get("name", "")
    age = request.args.get("age", "")

    if suspicious_input(name, age):
        return "Invalid input detected", 400

    return table(name, age)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
