from flask import Flask, request
from sqlalchemy import text
from db import db, init_db

app = Flask(__name__)
init_db(app)


def insecure_query(username):
    query = text(f"SELECT * FROM user WHERE username = '{username}'")
    return query


@app.route("/insecure-second-level", methods=["GET"])
def insecure_second_level():
    username = request.args.get("username")

    if not username:
        return "Username is required", 400

    # second-level, getting from database when needed level, takes literal string
    query = insecure_query(username)

    try:
        result = db.session.execute(query).fetchall()
        if result:
            # not expected to work, means that sql command injection didn't run
            return f"Found users with similar usernames", 200
        return "No users found", 404
    except Exception as e:
        return f"Error: {str(e)}", 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
