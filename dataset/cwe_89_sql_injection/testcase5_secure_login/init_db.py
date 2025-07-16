from flask import Flask
from db import db, init_db
from sqlalchemy import Column, Integer, String
import os

# Delete the database file if it exists
db_path = os.path.join("instance", "your_database.db")
if os.path.exists(db_path):
    os.remove(db_path)
    print("Removed existing database file.")

app = Flask(__name__)
init_db(app)


class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f"<User {self.username}>"


with app.app_context():
    # Drop all tables and recreate them
    db.drop_all()
    db.create_all()

    print("User table created.")

    # Add test users
    admin = User(username="admin", password="adminpass")
    user = User(username="testuser", password="password123")

    db.session.add(admin)
    db.session.add(user)
    db.session.commit()
    print("Database initialized with test users.")


print("Database setup complete!")
