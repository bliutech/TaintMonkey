from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = "secret"

# Fake user database
users = {
    "alice": {"password": "alice123", "role": "user"},
    "admin": {"password": "admin123", "role": "admin"},
}


@app.post("/login")
def login_send():
    username = request.form.get("username")
    password = request.form.get("password")

    if username is None or password is None:
        return "username or password not set in request"

    user_info = users.get(username)
    if user_info and user_info["password"] == password:
        session["username"] = username

        role = user_info.get("role")
        if role is None:
            return "role not found in user info"
        session["role"] = role

        return f"Welcome, {username}!"
    return "Invalid credentials"


@app.get("/login")
def login_show():
    return """
        <form method="post">
            <h2>Login</h2>
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
        <br>
        <form action="/logout" method="post">
            <button type="submit">Logout</button>
        </form>
    """


# Bad verifier, shows how it can be misleading (checks must be correct)
def is_user_in_session(user_string, this_session):
    return user_string in this_session


# Sink
def delete_user(user_to_delete):
    return f"User {user_to_delete} deleted (pretend)"


@app.get("/insecure/admin/delete_user")
def insecure_delete_user():
    if not is_user_in_session("username", session):
        return redirect("/login")

    user_to_delete = request.args.get("user")
    if user_to_delete is None:
        return "no user given to delete"

    # No check if current user is admin
    return delete_user(user_to_delete)


# Verifier
def is_admin(this_session, role_string, admin_string):
    return role_string in this_session and this_session.get(role_string) == admin_string


@app.get("/secure/admin/delete_user")
def secure_delete_user():
    # Here we check to make sure that the logged-in user is admin
    if not is_admin(session, "role", "admin"):
        return redirect("/login")

    user_to_delete = request.args.get("user")
    if user_to_delete is None:
        return "no user provided to delete"

    return delete_user(user_to_delete)


@app.post("/logout")
def logout():
    if not session:
        return "No Session"
    session.clear()
    return """
        <h2>You have been logged out.</h2>
        <form action="/login" method="get">
            <button type="submit">Back to Login</button>
        </form>
    """


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
