from flask import Flask, request, redirect
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey"

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "insecure_login_get"

users = {
    "admin": {"password": "admin123", "role": "admin"},
    "audrey": {"password": "audrey123", "role": "user"},
    "sebastian": {"password": "sebastian123", "role": "user"},
}


class User(UserMixin):
    def __init__(self, username, role="user"):
        self.id = username
        self._role = role

    def get_username(self):
        return self.id

    def get_role(self):
        return self._role


@login_manager.user_loader
def load_user(user_id):
    user_data = users.get(user_id)
    if user_data is None:
        return None
    return User(user_id, user_data["role"])


@app.get("/login")
def insecure_login_get():
    return """
        <form method="post">
            <h2>Login</h2>
            Username: <input name="username"><br>
            Role: <input name="role"><br>
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
    """


@app.post("/login")
def insecure_login_post():
    username = request.form.get("username")
    if username is None:
        return "This should not happen - no username"

    role = request.form.get("role")
    if role is None:
        return "This should not happen - no role"

    password = request.form.get("password")
    if password is None:
        return "This should not happen - no password"

    user = User(username, role)  # Sink
    login_user(user)

    return f"Welcome, {username}!"


@app.post("/logout")
def logout():
    logout_user()
    return "Logged out"


@app.get("/current_user")
@login_required
def show_current_user():
    return (
        f"Currently {current_user.get_username()} with role {current_user.get_role()}"
    )


@app.get("/admin")
@login_required
def for_admin():
    if current_user.get_role() != "admin":
        return redirect("/current_user")
    return "SECRET ONLY FOR ADMINS"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
