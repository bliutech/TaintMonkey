from flask import Flask, request, redirect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'insecure_login_show'

users = {
    "admin": "admin123",
    "audrey": "audrey123",
    "sebastian": "sebastian123"
}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

    def get_username(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

#Source
def get_username(this_request):
    return this_request.form.get("username")

@app.get("/login")
def insecure_login_show():
    return '''
        <form method="post">
            <h2>Login</h2>
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
        <br>
        <form action="/current_user" method="get">
            <button type="submit">Current User</button>
        </form>
        <form action="/logout" method="post">
            <button type="submit">Logout</button>
        </form>
    '''

@app.post("/login")
def insecure_login_post():
    username = get_username(request)
    if username is None:
        return "This should not happen - no username"
    password = request.form.get("password")
    if password is None:
        return "This should not happen - no password"

    user = User(username)
    login_user(user) #Sink

    return f"Welcome, {username}!"

@app.post("/logout")
def logout():
    logout_user()
    return "Logged out"

@app.get("/current_user")
@login_required
def show_current_user():
    return f"Currently {current_user.get_username()}"

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080)