from flask import Flask, request
from sqlalchemy import text
from db import db

app = Flask(__name__)

@app.route('/insecure-login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    if "'" in username:
        return "Invalid username: single quote not allowed", 400

    query = text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")
    user = db.session.execute(query).fetchone()

    if user:
        return "Login successful"
    return "Invalid credentials", 401

@app.route('/secure-login', methods=['POST'])
def secure_login():
    username = request.form['username']
    password = request.form['password']

    query = text("SELECT * FROM user WHERE username = :username AND password = :password")
    user = db.session.execute(query, {"username": username, "password": password}).fetchone()

    if user:
        return "Secure login successful"
    return "Invalid credentials", 400