# not working

from flask import jsonify
import functools

from flask import Flask, flash, g, redirect, request, session, url_for, Response
from werkzeug.security import check_password_hash, generate_password_hash
from flask_seasurf import SeaSurf

users = {}
app = Flask(__name__)

csrf = SeaSurf(app)

app.config.update(
    SECRET_KEY="dev", SESSION_COOKIE_SAMESITE=None, SESSION_COOKIE_SECURE=True
)


@app.get("/")
def index():
    return "Welcome to this Very Secure Web App!"


@app.get("/register")
@csrf.exempt
def show_register_form():
    return Response(
        """
        <h2>Register</h2>
        <form method="post" action="/register">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">Register</button>
        </form>
    """,
        mimetype="text/html",
    )


@app.post("/register")
@csrf.exempt
def register():
    username = request.args.get("username") or request.form.get("username")
    password = request.args.get("password") or request.form.get("password")
    error = None

    if not username:
        error = "Username is required."
    elif not password:
        error = "Password is required"
    elif username in users:
        error = f"Username {username} is already registered"

    if error:
        return f"Error: {error}", 400

    users[username] = {
        "username": username,
        "password": generate_password_hash(password),
    }
    return "User registered", 200


@app.get("/login")
def show_login_form():
    return Response(
        """
        <h2>Login</h2>
        <form method="post" action="/login">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>
    """,
        mimetype="text/html",
    )


@app.post("/login")
@csrf.exempt
def login():
    username = request.args.get("username") or request.form.get("username")
    password = request.args.get("password") or request.form.get("password")
    error = None
    user = users.get(username)

    if not user:
        error = "Incorrect username."
    elif not check_password_hash(user["password"], password):
        error = "Incorrect password."

    if error:
        return f"Error: {error}", 400

    session.clear()
    session["username"] = username
    return f"User logged in", 200


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not g.user:
            return "Login required!"

        return view(**kwargs)

    return wrapped_view


@app.get("/insecure-update")
def show_insecure_update_form():
    return Response(
        """
        <h2>Insecure Update</h2>
        <form method="post" action="/insecure-update">
            <input type="password" name="new_password" placeholder="New Password" required><br>
            <button type="submit">Update</button>
        </form>
    """,
        mimetype="text/html",
    )


@app.post("/insecure-update")
@login_required
@csrf.exempt
def insecure_update():
    new_password = request.args.get("new_password") or request.form.get("new_password")

    if not new_password:
        return "New password is required", 400

    users[g.user["username"]]["password"] = generate_password_hash(
        new_password, method="pbkdf2:sha256"
    )

    return "Password updated", 200


@app.get("/secure-update")
def show_secure_update_form():
    csrf_token = request.cookies.get("csrf_token", "")
    return Response(
        f'''
        <h2>Secure Update</h2>
        <form method="post" action="/secure-update">
            <input type="password" name="new_password" placeholder="New Password" required><br>
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <button type="submit">Update</button>
        </form>
    ''',
        mimetype="text/html",
    )


@app.post("/secure-update")
@login_required
def secure_update():
    new_password = request.args.get("new_password") or request.form.get("new_password")

    if not new_password:
        return "New password is required", 400

    users[g.user["username"]]["password"] = generate_password_hash(
        new_password, method="pbkdf2:sha256"
    )

    return "Password updated (with csrf token)", 200


@app.before_request
def load_logged_in_user() -> None:
    username = session.get("username")
    g.user = users.get(username)


@app.route("/logout")
def logout():
    session.clear()
    return "Logged Out"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
