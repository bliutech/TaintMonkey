from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = "secret"

# Fake user database
users = {
    "alice": "alice123",
    "jeff": "jeff123",
}

# Fake token database
tokens = dict()
for user in users:
    tokens[user] = []

tokens["alice"].append("you_found_this_secret!")
tokens["jeff"].append("jeffy_cool_secret")


@app.post("/login")
def login_send():
    username = request.form.get("username")

    password = request.form.get("password")

    if username is None or password is None:
        return "username or password not supplied in post form"

    db_password = users.get(username)
    if db_password and db_password == password:
        session["username"] = username

        return f"""
            Welcome, {username}!
            <br>
            <form action="/home" method="get">
                <button type="submit">To Home</button>
            </form>
        """

    return """
        Invalid credentials
            <br>
        <form action="/home" method="get">
            <button type="submit">To Home</button>
        </form>
    """


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
        <form action="/secure/signup" method="get">
            <button type="submit">Secure Sign Up</button>
        </form>
        <form action="/insecure/signup" method="get">
            <button type="submit">Insecure Sign Up</button>
        </form>
    """


@app.post("/home")
def home_send():
    token = request.form.get("token")
    if token is None:
        return "no token supplied in post form"

    if not is_user_in_session("username", session):
        return "No user in session"

    username = session.get("username")
    if username in tokens:
        tokens[username].append(token)
    else:
        tokens[username] = [token]

    return f"""
        Token {token} added to tokens!
        <br>
        <form action="/home" method="get">
            <button type="submit">Back Home</button>
        </form>
    """


@app.get("/home")
def home_show():
    if not is_user_in_session("username", session):
        return redirect("/login")

    username = session.get("username")
    return f"""
        <h2>Home</h2>
        Hey, {username}!
        <br>
        <form method="post">
            <h2>Secret Tokens</h2>
            Enter Token: <input name="token"><br>
            <input type="submit" value="Add Token">
        </form>
        <form action="/secret" method="post">
            <button type="submit">Open Secret Tokens</button>
        </form>
        <form action="/logout" method="post">
            <button type="submit">Logout</button>
        </form>
    """


def is_user_in_session(user_string, this_session):
    return user_string in this_session


@app.post("/secret")
def secret():
    if not is_user_in_session("username", session):
        return "Session not logged in"
    username = session["username"]

    # This should never be true
    if not username in users:
        return "this should not happen - user"

    user_tokens = tokens.get(username)
    if user_tokens is None:
        return "this should not happen - tokens"

    token_string = f"{username}'s secret tokens are:<br>"
    for token in user_tokens:
        token_string += f" {token}<br>"
    token_string += """
        <form action="/home" method="get">
            <button type="submit">Back Home</button>
        </form>
    """

    return token_string


# Sink
def sign_up(username, password, user_database):
    user_database[username] = password


@app.post("/insecure/signup")
def insecure_signup_send():
    username = request.form.get("username")

    password = request.form.get("password")

    if username is None or password is None:
        return "username or password not supplied in post form"

    # Sink
    sign_up(username, password, users)
    return f"""
        {username}, you're registered!
        <form action="/login" method="get">
            <button type="submit">Login</button>
        </form>
    """


@app.get("/insecure/signup")
def insecure_signup_get():
    return """
        <form action="/insecure/signup" method="post">
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


# Verifier
def user_taken(user_given, password_given, database_given):
    db_password = database_given.get(user_given)

    if db_password == password_given:
        print("user info already exists - user probably clicked wrong button")

    return not db_password is None


@app.post("/secure/signup")
def secure_signup_send():
    username = request.form.get("username")

    password = request.form.get("password")

    if username is None or password is None:
        return "username or password not supplied in post form"

    # Verifier
    if user_taken(username, password, users):
        return """
            Username already taken!
            <form action="/secure/signup" method="get">
                <button type="submit">Back</button>
            </form>
        """

    # Sink
    sign_up(username, password, users)
    return f"""
        {username}, you're registered!
        <form action="/login" method="get">
            <button type="submit">Login</button>
        </form>
    """


@app.get("/secure/signup")
def secure_signup_get():
    return """
        <form action="/secure/signup" method="post">
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
