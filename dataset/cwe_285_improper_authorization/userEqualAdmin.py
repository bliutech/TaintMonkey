from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = "secret"

# Fake user database
users = {
    "alice": {"password": "alice123", "role": "user"},
    "admin": {"password": "admin123", "role": "admin"}
}

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = users.get(username)
        if user and user["password"] == password:
            session["username"] = username
            session["role"] = user["role"]
            return f"Welcome, {username}!"
        return "Invalid credentials"

    return '''
        <form method="post">
            <h2>Login</h2>
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
        <br>
        <form action="/logout" method="get">
            <button type="submit">Logout</button>
        </form>
    '''


@app.route("/insecure/admin/delete_user")
def insecure_delete_user():
    if "username" not in session:
        return redirect("/login")

    print(session["username"])
    user_to_delete = request.args.get("user")
    #CWE-285: No check if current user is admin
    return f"User {user_to_delete} deleted (pretend)"

#Checks to see if a user is authorized as an admin
def is_admin(this_session):
    return "role" in this_session and this_session.get("role") == "admin"

@app.route("/secure/admin/delete_user")
def secure_delete_user():
    #Here we check to make sure that the logged-in user is admin
    if is_admin(session):
        user_to_delete = request.args.get("user")
        return f"User {user_to_delete} deleted (pretend)"

    return redirect("/login")


@app.route("/logout")
def logout():
    session.clear()
    return '''
        <h2>You have been logged out.</h2>
        <form action="/login" method="get">
            <button type="submit">Back to Login</button>
        </form>
    '''

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)