from flask_wtf.csrf import generate_csrf
from flask_wtf.csrf import CSRFProtect
from flask import jsonify
import functools

from flask import (
    Flask, flash, g, redirect, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

users = {}
app = Flask(__name__)

csrf = CSRFProtect()
csrf.init_app(app)

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
@csrf.exempt
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
@csrf.exempt
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
    csrf_token = generate_csrf()
    return f'User logged in, CSRF token: {csrf_token}', 200

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not g.user:
            return 'Login required!'
        
        return view(**kwargs)
    
    return wrapped_view

@app.post('/insecure-delete')
@csrf.exempt
@login_required
def insecute_delete():
    del users[g.user['username']]
    session.clear()
    return 'Account deleted'
    

@app.post('/secure-delete')
@login_required
def secure_delete():
    del users[g.user['username']]
    session.clear()
    return 'Account deleted'
    
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