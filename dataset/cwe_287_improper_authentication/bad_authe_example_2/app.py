from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = "secret"

# Fake user database where key is username & value is password
users = {
    "alice": "alice123",
    "jeff": "jeff123",
}


@app.get("/insecure/login")
def insecure_login_show():
    return '''
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
    '''


@app.post("/insecure/login")
def insecure_login_send():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return "Error - no username or no password"


    db_password = users.get(username)
    if db_password is None:
        return "Error, user not in database"

    if db_password != password:
        return "Invalid credentials"

    redirect_string = f"/set_session?user={username}"
    return redirect(redirect_string)


@app.get("/set_session")
def insecure_set_session():
    username = request.args.get("user")

    if username is None:
        return "Error, user not in request"

    session["username"] = username
    return f"User logged in as: {username}"


@app.get("/secure/login")
def secure_login_show():
    return '''
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
    '''


@app.post("/secure/login")
def secure_login_send():
    username = request.form["username"]
    password = request.form["password"]

    if username in users and users[username] == password:
        session["username"] = username
        return f"Welcome, {username}!"
    return "Invalid credentials"

@app.post("/logout")
def logout():
    if not session:
        return "No Session"
    session.clear()
    return '''
        <h2>You have been logged out.</h2>
        <form action="/insecure/login" method="get">
            <button type="submit">Back to Login</button>
        </form>
    '''

@app.get("/session")
def session_show():
    username = session.get("username")
    if username is None:
        return "No session"

    return f"Your session is: {username}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)