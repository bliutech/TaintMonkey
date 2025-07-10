from flask import Flask, request
from sqlalchemy import text
from db import db, init_db

app = Flask(__name__)
init_db(app)

@app.route('/insecure-login', methods=['POST'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')

    if "'" in username:
        return "Invalid username: single quote not allowed", 400
    
    if not request.args.get('username') or not request.args.get('password'):
        return "Username and password are required", 400

    query = text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")
    user = db.session.execute(query).fetchone()

    if user:
        return "Login successful"
    return "Invalid credentials", 401

@app.route('/insecure-signup', methods=['POST'])
def insecure_signup():
    username = request.args.get('username')
    password = request.args.get('password')
    
    if not username or not password:
        return "Username and password are required", 400
    
    query = text(f"INSERT INTO user (username, password) VALUES ('{username}', '{password}')")
    
    try:
        db.session.execute(query)
        db.session.commit()
        return "User created successfully", 201
    except Exception as e:
        db.session.rollback()
        return f"Error creating user: {str(e)}", 500
    
@app.route('/secure-signup', methods=['POST'])
def secure_signup():
    username = request.args.get('username')
    password = request.args.get('password')
    
    if not username or not password:
        return "Username and password are required", 400

    # for inserting values as string literals rather than potential sql commands
    query = text("INSERT INTO user (username, password) VALUES (:username, :password)")
    
    try:
        db.session.execute(query, {"username": username, "password": password})
        db.session.commit()
        return "User created securely", 201
    except Exception as e:
        db.session.rollback()
        return f"Error creating user: {str(e)}", 500

@app.route('/secure-login', methods=['POST'])
def secure_login():
    username = request.args.get('username')
    password = request.args.get('password')
    
    if not username or not password:
        return "Username and password are required", 400

    query = text("SELECT * FROM user WHERE username = :username AND password = :password")
    user = db.session.execute(query, {"username": username, "password": password}).fetchone()

    if user:
        return "Secure login successful"
    return "Invalid credentials", 400

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8080)