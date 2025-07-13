from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = "secret"

# Fake user database where key is username & value is password
users = {
    "alice": "alice123",
    "jeff": "jeff123",
}



@app.post("/login")
def login_send():
    username = request.form["username"]
    password = request.form["password"]

    db_password = users.get(username)
    if db_password and db_password == password:
        session["username"] = username

        return f'''
            Welcome, {username}!
        '''
    return '''
        Invalid credentials
    '''


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
        <form action="/secure/reset_password" method="get">
            <button type="submit">Secure Reset Password</button>
        </form>
        <form action="/insecure/reset_password" method="get">
            <button type="submit">Insecure Reset Password</button>
        </form>
    '''

#Source
def get_new_password(this_request):
    return this_request.form.get("new_password")

#Sanitizer
def password_is_correct(old_password, db_password):
    return old_password == db_password

#Sink
def set_new_password(password, username, user_db):
    user_db[username] = password

@app.get("/secure/reset_password")
def secure_reset_password_show():
    return f'''
        <form method="post">
            <h2>Reset Password</h2>
            Username: <input name="username"><br>
            Old Password: <input name="old_password" type="password"><br>
            New Password: <input name="new_password" type="password"><br>
            <input type="submit" value="Reset">
        </form>
    '''

@app.post("/secure/reset_password")
def secure_reset_password_send():
    username = request.form.get("username")
    if username is None:
        return "This should not happen - no username"
    old_password = request.form.get("old_password")
    if old_password is None:
        return "This should not happen - no old password"
    new_password = get_new_password(request)
    if new_password is None:
        return "This should not happen - no new password"

    db_password = users.get(username)
    if db_password is None:
        "No user in database"

    if not password_is_correct(old_password, db_password):
        return "Incorrect password - old password does not match database password"

    set_new_password(new_password, username, users)
    return f'''
        {username}, your password is reset!
        <form action="/login" method="get">
            <button type="submit">Login</button>
        </form>
    '''



@app.get("/insecure/reset_password")
def insecure_reset_password_show():
    return f'''
        <form method="post">
            <h2>Reset Password</h2>
            Username: <input name="username"><br>
            Nww Password: <input name="new_password" type="password"><br>
            <input type="submit" value="Reset">
        </form>
    '''

@app.post("/insecure/reset_password")
def insecure_reset_password_send():
    username = request.form.get("username")
    if username is None:
        return "This should not happen - no username"
    new_password = get_new_password(request)
    if new_password is None:
        return "THis should not happen - no new password"

    db_password = users.get(username)
    if db_password is None:
        "No user in database"

    set_new_password(new_password, username, users)
    return f'''
        {username}, your password is reset!
        <form action="/login" method="get">
            <button type="submit">Login</button>
        </form>
    '''

#Monkey patch?
def user_login_info_correct(username, password, database):
    return username in database and username[username] == password


@app.post("/logout")
def logout():
    if not session:
        return "No Session"
    session.clear()
    return '''
        <h2>You have been logged out.</h2>
    '''

@app.get("/session")
def session_show():
    username = session.get("username")
    if username is None:
        return "No session"

    return f"Your session is: {username}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)