from flask import Flask, request
from db import db, init_db

app = Flask(__name__)
init_db(app)


def insecure_input(username, password):
    query = "SELECT * FROM user WHERE username = :username AND password = :password"
    params = {"username": username, "password": password}
    return query, params


@app.route("/insecure-login", methods=["POST"])
def secure_login():
    username = request.args.get("username")
    password = request.args.get("password")

    if not username or not password:
        return "Username and password are required", 400

    query, params = insecure_input(username, password)
    user = db.session.execute(query, params).fetchone()

    if user:
        return "Secure login successful"
    return "Invalid credentials", 400


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
