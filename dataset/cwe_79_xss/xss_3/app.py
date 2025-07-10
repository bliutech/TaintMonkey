from flask import Flask, request
import bleach

app = Flask(__name__)

@app.route("/insecure_signup", methods=["GET", "POST"])
def unsafe_signup():
    if request.method == "POST":
        username = request.form.get("username", "")
        return f"<h2>Welcome {username}!</h2>"
    return '''
        <h3>Vulnerable Signup</h3>
        <form method="POST">
        Username: <input name="username"><br>
        <input type="submit" value="Sign Up">
    </form>
    '''

@app.route("/insecure_login", methods=["GET", "POST"])
def unsafe_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        return f"<h2>Welcome back {username}!</h2>"
    return '''
        <h3>Vulnerable Login</h3>
        <form method="POST">
            Username: <input name="username"><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route("/secure_signup", methods=["GET", "POST"])
def secure_signup():
   if request.method == "POST":
    username = request.form.get("username", "")
    # bleach (signup)
    cleanedUsername = bleach.clean(username, tags=[], attributes={}, strip=True)
    return f"<h2>Welcome {cleanedUsername}!</h2>"
   return '''
    <h3>Secure Signup</h3>
    <form method="POST">
        Username: <input name="username"><br>
        <input type="submit" value="Sign Up">
    </form>
   '''

@app.route("/secure_login", methods=["GET", "POST"])
def secure_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        # bleach (login)
        cleanedUsername = bleach.clean(username, tags=[], attributes={}, strip=True)
        return f"<h2>Welcome back {cleanedUsername}!</h2>"
    return '''
        <h3>Secure Login</h3>
        <form method="POST">
            Username: <input name="username"><br>
            <input type="submit" value="Login">
    '''

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

