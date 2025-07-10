from flask import Flask, request
from sqlalchemy import text
import db
import re
from db import init_db

app = Flask(__name__)
init_db(app)

def pattern_match(username, password):
    pattern = '^[a-zA-Z0-9]+$'
    if not re.search(pattern, username) or not re.search(pattern, password):
        return "Invalid input: only alphanumeric characters are allowed", 400

@app.route('/insecure-signup', methods=['POST'])
def insecure_signup():
    username = request.args.get('username')
    password = request.args.get('password')
    
    # quick return if not valid response
    if not username or not password:
        return "Username and password are required", 400
    
    error = pattern_match(username, password)
    if error:
        return error
    
    # same issue with using direct username and passwords
    query = text(f"INSERT INTO user (username, password) VALUES ('{username}', '{password}')")
    
    try:
        db.db.session.execute(query)
        db.db.session.commit()
        return "User created successfully", 201
    except Exception as e:
        db.db.session.rollback()
        return f"Error creating user", 500

@app.route('/secure-login', methods=['POST'])
def secure_login():
    username = request.args.get('username')
    password = request.args.get('password')
    
    if not username or not password:
        return "Username and password are required", 400

    error = pattern_match(username, password)
    if error:
        return error

    query = text("SELECT * FROM user WHERE username = :username AND password = :password")
    user = db.db.session.execute(query, {"username": username, "password": password}).fetchone()

    if user: 
        return "Login successful"
    return "Invalid login", 401

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8080)