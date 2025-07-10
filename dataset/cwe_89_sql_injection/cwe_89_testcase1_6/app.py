from flask import Flask, request
from sqlalchemy import text
from db import db, init_db

app = Flask(__name__)
init_db(app)

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
    
@app.route('/insecure-login', methods=['POST'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')
    
    if not request.args.get('username') or not request.args.get('password'):
        return "Username and password are required", 400

    query = text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")
    user = db.session.execute(query).fetchone()

    if user:
        return "Login successful"
    return "Invalid credentials", 401

@app.route('/insecure-second-level', methods=['GET'])
def insecure_second_level():
    username = request.args.get('username')
    
    if not username:
        return "Username is required", 400
    
    # second-level, getting from database when needed level, takes literal string
    query = text(f"SELECT * FROM user WHERE username = '{username}'")
    
    try:
        result = db.session.execute(query).fetchall()
        if result:
            # not expected to work, means that sql command injection didn't run
            return f"Found users with similar usernames", 200
        return "No users found", 404
    except Exception as e:
        return f"Error: {str(e)}", 500
    
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

@app.route('/secure-second-level', methods=['GET'])
def secure_second_level():
    username = request.args.get('username')
    
    if not username:
        return "Username is required", 400
    
    # second-level, getting from database when needed level, takes full string as a string rather 
    query = text(f"SELECT * FROM user WHERE username = :username")
    
    try:
        result = db.session.execute(query, {"username": username}).fetchall()
        if result:
            # system works to not run sql command and properly find users
            return f"Found others with similar usernames", 200
        return "No users found", 404
    except Exception as e:
        return f"Error: {str(e)}", 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8080)