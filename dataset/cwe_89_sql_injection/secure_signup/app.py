from flask import Flask, request
from sqlalchemy import text
from db import db, init_db

app = Flask(__name__)
init_db(app)


def sanitize_input(username, password):
    query = text("INSERT INTO user (username, password) VALUES (:username, :password)")
    params = {"username": username, "password": password}
    return query, params


@app.route("/secure-signup", methods=["POST"])
def secure_signup():
    username = request.args.get("username")
    password = request.args.get("password")

    if not username or not password:
        return "Username and password are required", 400

    # for inserting values as string literals rather than potential sql commands
    query, params = sanitize_input(username, password)

    try:
        db.session.execute(query, params)
        db.session.commit()
        return "User created securely", 201
    except Exception as e:
        db.session.rollback()
        return f"Error creating user: {str(e)}", 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
