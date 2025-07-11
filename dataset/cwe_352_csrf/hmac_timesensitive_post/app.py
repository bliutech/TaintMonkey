from flask import jsonify
import functools

from flask import (
    Flask, flash, g, redirect, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
import hmac, hashlib, base64, time

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

def generate_csrf_hmac(username: str, path: str, timestamp: int) -> str:
    secret = app.config['SECRET_KEY']
    message = f'{username}:/secure-update:{timestamp}'.encode('utf-8')
    digest = hmac.new(secret.encode('utf-8'), message, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(digest).decode('utf-8')
    return token
    
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

    timestamp = int(time.time())
    token = generate_csrf_hmac(username, '/secure-transfer', timestamp)

    return jsonify({
        'message': 'User logged in',
        'csrf_token': token,
        'timestamp': timestamp
    })

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
    
    if not new_password:
        return 'New password is required', 400

    users[g.user['username']]['password'] = generate_password_hash(new_password, method='pbkdf2:sha256')

    return 'Password updated', 200

@app.post('/secure-update')
@login_required
def secure_update():
    new_password = request.args.get('new_password') or request.form.get('new_password')
    received_token = request.headers.get('X-CSRFToken')
    timestamp = request.headers.get('X-CSRFTime')

    if not received_token or not timestamp:
        return 'Missing CSRF token or timestamp', 403

    if not new_password:
        return 'New password is required', 400

    try:
        timestamp = int(timestamp)
    except ValueError:
        return 'Invalid tiemstamp', 400

    if abs(time.time() - timestamp) > 500:
        return 'CSRF token expired', 403

    expected_token = generate_csrf_hmac(g.user['username'], '/secure-update', timestamp)

    if not hmac.compare_digest(received_token, expected_token):
        return f'Invalid CSRF token - expected: {expected_token}, received: {received_token}', 403

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