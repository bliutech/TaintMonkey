from flask import Flask, request
from sqlalchemy import text
import db
import re
from db import init_db

app = Flask(__name__)
init_db(app)

@app.route('/secure-login', methods=['POST'])
def secure_login():
    username = request.args.get('username')
    password = request.args.get('password')
    
    if not username or not password:
        return "Username and password are required", 400

    pattern = '^[a-zA-Z0-9]+$'
    if not re.search(pattern, username) or not re.search(pattern, password):
        return "Invalid input: only alphanumeric characters are allowed", 400

    query = text("SELECT * FROM user WHERE username = :username AND password = :password")
    user = db.db.session.execute(query, {"username": username, "password": password}).fetchone()

    if user: 
        return "Login successful"
    return "Invalid login", 401

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)