from itsdangerous.signer import NoneAlgorithm
import functools

from flask import (
    Flask, flash, g, redirect, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from db import *

app = Flask(__name__)

app.secret_key = 'dev'

app.config['DATABASE'] = 'cwe_152_csrf.sqlite'
with app.app_context():
    init_db()
init_app(app)

@app.route('/')
def index():
    return "Welcome to this Very Secure Web App!"

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.args.get("username") or "test_username"
        password = request.args.get("password") or "test_password"
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password, method='pbkdf2:sha256'))
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return "User registered", 200
            
        return f"Error: {error}", 400
    
    return "Send a POST request to register with ?username=...&password=...", 200

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.args.get('username') or "test_username"
        password = request.args.get('password') or "test_password"
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None and user is not None:
            # session is a dict that stores data across requests. 
            # when validation succeeds, the user's id is stored in a new session
            # the data is stored in a cookie that is sent to the browser,
            # and the browser sends it back with subsequent requests.
            # Flask securely signs the data so it can't be tampererd with.
            session.clear()
            session['user_id'] = user['id']
            return "User logged in and session established", 200
        
        return f"Error: {error}", 400

    return "Send a POST request to log in with ?username=...&password=...", 200

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return "Login required!"
        
        return view(**kwargs)
    
    return wrapped_view

@app.route('/insecure-update', methods=('GET', 'PUT'))
@login_required
def insecure_update():
    if request.method == 'PUT':
        new_password = request.args.get('new_password')
        db = get_db()
        error = None
        
        if not new_password:
            return "New password is required", 400

        hashed_pw = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.execute(
            "UPDATE user SET password = ? WHERE id = ?",
            (hashed_pw, g.user['id'])
        )
        db.commit()
        return "Password updated", 200
    
    return "Send a PUT request to update password with ?new_password=...", 200


@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@app.route('/logout')
def logout():
    session.clear()
    return "Logged Out"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
