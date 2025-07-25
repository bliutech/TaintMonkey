from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = "secret"

# Fake user database where key is username & value is password
users = {
    "alice": "alice123",
}


@app.post("/login")
def login_send():
    username = request.form["username"]
    password = request.form["password"]

    if username in users and users[username] == password:
        session["username"] = username
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
        <form action="/signup" method="get">
            <button type="submit">Sign Up</button>
        </form>
    """


@app.post("/signup")
def signup_send():
    username = request.form["username"]
    password = request.form["password"]

    if username in users:
        return "username already taken"
    users[username] = password
    return f"{username}, registered!"


@app.get("/signup")
def signup_show():
    return """
        <form action="/signup" method="post">
            <h2>Sign Up</h2>
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Sign Up">
        </form>
        <br>
        <form action="/login" method="get">
            <button type="submit">Login</button>
        </form>
    """


def is_user_in_session(user_string, this_session):
    return user_string in this_session


@app.delete("/insecure/delete_self")
def insecure_delete_user():
    if not is_user_in_session("username", session):
        return redirect("/login")

    user_to_delete = request.args.get("user")
    if not user_to_delete:
        return "No URL parameter"

    # CWE-863: No check if current user is itself
    return f"User {user_to_delete} deleted (pretend)"


@app.delete("/secure/delete_self")
def secure_delete_user():
    if not is_user_in_session("username", session):
        return redirect("/login")

    user_to_delete = request.args.get("user")
    if not user_to_delete:
        return "No URL parameter"

    # CWE-863: Check if current user is itself
    if not user_and_session_user_match(user_to_delete, "username", session):
        return "Not allowed to delete someone other than self"

    if user_to_delete in users:
        return "this should not happen"
    session.clear()
    users.pop(user_to_delete)
    return f"User {user_to_delete} deleted"


# Monkey patch function
def user_and_session_user_match(user, user_string, this_session):
    return user == this_session[user_string]


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
