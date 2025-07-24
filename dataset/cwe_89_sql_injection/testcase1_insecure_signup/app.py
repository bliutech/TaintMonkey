from flask import Flask, request
from sqlalchemy import text
from db import db, init_db

app = Flask(__name__)
init_db(app)

def create_insecure_user_query(username, password):
    return text(
        f"INSERT INTO user (username, password) VALUES ('{username}', '{password}')"
    )

@app.route("/insecure-signup", methods=["POST"])
def insecure_signup():
    username = request.args.get("username")
    password = request.args.get("password")

    if not username or not password:
        return "Username and password are required", 400

    query = create_insecure_user_query(username, password)

    try:
        db.session.execute(query)
        db.session.commit()
        return "User created successfully", 201
    except Exception as e:
        db.session.rollback()
        return f"Error creating user: {str(e)}", 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
