from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "secret"

# Fake user database
users = {
    "alice": {"password": "alice123", "token": "alice secret text"},
    "jeff": {"password": "jeff123", "token": "jeff secret text"},
}


@app.post("/login")
def login_send():
    username = request.form["username"]
    password = request.form["password"]

    user = users.get(username)
    if user and user["password"] == password:
        session["username"] = username
        return f"Welcome, {username}!"
    return "Invalid credentials"


@app.get("/login")
def login_show():
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
        <form action="/secure/signup" method="get">
            <button type="submit">Secure Sign Up</button>
        </form>
        <form action="/insecure/signup" method="get">
            <button type="submit">Insecure Sign Up</button>
        </form>
        <form action="/secret" method="post">
            <button type="submit">Open Secret Token</button>
        </form>
    '''


def is_user_in_session(user_string, this_session):
    return user_string in this_session


@app.post("/secret")
def secret():
    if not is_user_in_session("username", session):
        return f"Session not logged in"
    username = session["username"]

    #This should never be true
    if not user_taken(username, users):
        return "this should not happen"
    token = users[username]["token"]
    return f"{username}'s secret token is {token}!"


@app.post("/insecure/signup")
def insecure_signup_send():
    username = request.form["username"]
    password = request.form["password"]
    token = request.form["token"]

    #Doesn't include userTaken function, meaning someone can override another person's account
    users[username] = {"password": password, "token": token}
    return f"{username}, registered!"

@app.get("/insecure/signup")
def insecure_signup_get():
    return '''
        <form action="/insecure/signup" method="post">
            <h2>Sign Up</h2>
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            Secret Token: <input name="token" type="password"><br>
            <input type="submit" value="Sign Up">
        </form>
        <br>
        <form action="/login" method="get">
            <button type="submit">Login</button>
        </form>
    '''


#Monkey Patch function
def user_taken(user, database):
    return user in database


@app.post("/secure/signup")
def secure_signup_send():
    username = request.form["username"]
    password = request.form["password"]
    token = request.form["token"]

    if user_taken(username, users):
        return "username already taken"
    users[username] = {"password": password, "token": token}
    return f"{username}, registered!"


@app.get("/secure/signup")
def secure_signup_get():
    return '''
        <form action="/secure/signup" method="post">
            <h2>Sign Up</h2>
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            Secret Token: <input name="token" type="password"><br>
            <input type="submit" value="Sign Up">
        </form>
        <br>
        <form action="/login" method="get">
            <button type="submit">Login</button>
        </form>
    '''


@app.post("/logout")
def logout():
    if not session:
        return "No Session"
    session.clear()
    return '''
        <h2>You have been logged out.</h2>
        <form action="/login" method="get">
            <button type="submit">Back to Login</button>
        </form>
    '''


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)