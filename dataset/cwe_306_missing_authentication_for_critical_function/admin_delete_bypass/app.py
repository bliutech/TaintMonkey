from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = "secret"

# Fake user database
users = {
    "alice": {"password": "alice123", "token": "user"},
    "admin": {"password": "admin123", "token": "admin"},
}


@app.post("/login")
def login_send():
    username = request.form["username"]
    password = request.form["password"]

    user = users.get(username)
    if user and user["password"] == password:
        session["username"] = username
        session["role"] = user["role"]
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


def is_user_in_session(user_string, this_session):
    return user_string in this_session


@app.delete("/insecure/admin/delete_user")
def insecure_delete_user():
    if not is_user_in_session("username", session):
        return redirect("/login")

    user_to_delete = request.args.get("user")
    # CWE-863: No check if current user is admin
    return f"User {user_to_delete} deleted (pretend)"


# Checks to see if a user is authorized as an admin
def is_admin(this_session, role_string, admin_string):
    return role_string in this_session and this_session.get(role_string) == admin_string


@app.delete("/secure/admin/delete_user")
def secure_delete_user():
    # Here we check to make sure that the logged-in user is admin
    if not is_admin(session, "role", "admin"):
        return redirect("/login")

    user_to_delete = request.args.get("user")
    if not user_to_delete:
        return "No user provided to delete"
    user_deleted = users.get(user_to_delete)
    if not user_deleted:
        return "No user found"
    return f"User {user_to_delete} deleted (pretend)"


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
