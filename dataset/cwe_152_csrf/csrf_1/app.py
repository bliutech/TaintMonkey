from flask import jsonify
import functools

from flask import (
    Flask, flash, g, redirect, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf.csrf import CSRFProtect, generate_csrf

users = {}
app = Flask(__name__)

csrf = CSRFProtect()
csrf.init_app(app)

app.config.update(
    SECRET_KEY = 'dev',
    SESSION_COOKIE_SAMESITE=None,
    SESSION_COOKIE_SECURE=True
)

@app.route('/')
def index():
    return "Welcome to this Very Secure Web App!"

@app.post('/register')
@csrf.exempt
def register():
    username = request.args.get("username") or "test_username"
    password = request.args.get("password") or "test_password"
    error = None

    if not username:
        error = 'Username is required.'
    elif not password:
        error = 'Password is required'
    elif username in users:
        error = f'Username {username} is already registered'

    if error:
        return f"Error: {error}", 400

    users[username] = {
            'username': username,
            'password': generate_password_hash(password)
        }
    return "User registered", 200
    
@app.post('/login')
@csrf.exempt
def login():
    username = request.args.get('username') or "test_username"
    password = request.args.get('password') or "test_password"
    error = None
    user = users.get(username)

    if not user:
        error = 'Incorrect username.'
    elif not check_password_hash(user['password'], password):
        error = 'Incorrect password.'

    if error:
        return f"Error: {error}", 400

    # session is a dict that stores data across requests. 
    # when validation succeeds, the user's id is stored in a new session
    # the data is stored in a cookie that is sent to the browser,
    # and the browser sends it back with subsequent requests.
    # Flask securely signs the data so it can't be tampererd with.
    session.clear()
    session['username'] = username
    csrf_token = generate_csrf()
    return f"User logged in. CSRF Token: {csrf_token}", 200

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not g.user:
            return "Login required!"
        
        return view(**kwargs)
    
    return wrapped_view

@app.put('/insecure-update')
@login_required
@csrf.exempt
def insecure_update():
    new_password = request.args.get('new_password')
    error = None
    
    if not new_password:
        return "New password is required", 400

    users[g.user['username']]['password'] = generate_password_hash(new_password, method='pbkdf2:sha256')

    return "Password updated", 200
    

@app.put('/secure-update')
@login_required
def secure_update():
    new_password = request.args.get('new_password')
    error = None
    
    if not new_password:
        return "New password is required", 400

    users[g.user['username']]['password'] = generate_password_hash(new_password, method='pbkdf2:sha256')

    return "Password updated (with csrf token)", 200
    
@app.before_request
def load_logged_in_user() -> None:
    username = session.get('username')
    g.user = users.get(username)

@app.route('/logout')
def logout():
    session.clear()
    return "Logged Out"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)