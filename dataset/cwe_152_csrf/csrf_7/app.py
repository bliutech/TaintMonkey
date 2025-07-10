from flask import jsonify
import functools

from flask import (
    Flask, flash, g, redirect, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
import secrets

users = {}
app = Flask(__name__)

app.config.update(
    SECRET_KEY = 'dev',
    SESSION_COOKIE_SAMESITE=None,
    SESSION_COOKIE_SECURE=True
)

@app.get('/')
def index():
    return 'Welcome to this Very Secure Web App!'

# js code to test in browser console:
# let res = await fetch('https://shiny-sniffle-74w799vjw6jfw57v-8080.app.github.dev/register?username=shay&password=bar', {method:'POST', mode:'no-cors'})
@app.post('/register')
def register():
    username = request.args.get('username')
    password = request.args.get('password') 
    error = None

    if not username:
        error = 'Username is required.'
    elif not password:
        error = 'Password is required'
    elif username in users:
        error = f'Username {username} is already registered'

    if error:
        return f'Error: {error}', 400

    users[username] = {
            'username': username,
            'password': generate_password_hash(password)
        }
    return 'User registered', 200
    
@app.post('/login')
def login():
    username = request.args.get('username')
    password = request.args.get('password') 
    error = None
    user = users.get(username)

    if not user:
        error = 'Incorrect username.'
    elif not check_password_hash(user['password'], password):
        error = 'Incorrect password.'

    if error:
        return f'Error: {error}', 400

    session.clear()
    session['username'] = username

    csrf_token = secrets.token_urlsafe(32)
    if 'csrf_nonces' not in session:
        session['csrf_nonces'] = []
    session['csrf_nonces'].append(csrf_token)
    session.modified = True

    return f'User logged in, CSRF token: {csrf_token}', 200

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not g.user:
            return 'Login required!'
        
        return view(**kwargs)
    
    return wrapped_view

@app.post('/insecure-update')
@login_required
def insecure_update():
    new_password = request.args.get('new_password') or request.form.get('new_password')
    error = None
    
    if not new_password:
        return 'New password is required', 400

    users[g.user['username']]['password'] = generate_password_hash(new_password, method='pbkdf2:sha256')

    return 'Password updated', 200
    

@app.post('/secure-update')
@login_required
def secure_update():
    new_password = request.args.get('new_password') or request.form.get('new_password')
    csrf_token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken') or ''

    nonces = session.get('csrf_nonces', [])
    valid = True
    if csrf_token not in nonces:
        valid = False

    if not valid:
        return 'Invalid or missing CSRF token', 403

    nonces.remove(csrf_token)
    session['csrf_nonces'] = nonces
    session.modified = True

    if not new_password:
        return 'New password is required', 400

    users[g.user['username']]['password'] = generate_password_hash(new_password, method='pbkdf2:sha256')

    return 'Password updated', 200
    
@app.before_request
def load_logged_in_user() -> None:
    username = session.get('username')
    g.user = users.get(username)

@app.route('/logout')
def logout():
    session.clear()
    return 'Logged Out'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)