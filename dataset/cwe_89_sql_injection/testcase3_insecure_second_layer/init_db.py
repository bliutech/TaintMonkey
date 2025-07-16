from flask import Flask
from db import db, init_db
from sqlalchemy import Column, Integer, String


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
    db.create_all()

    from sqlalchemy import inspect

    inspector = inspect(db.engine)
    if "user" in inspector.get_table_names():
        print("User table exists.")

        if User.query.count() == 0:
            admin = User(username="admin", password="adminpass")
            user = User(username="testuser", password="password123")

            db.session.add(admin)
            db.session.add(user)
            db.session.commit()
            print("Database initialized with test users.")
        else:
            print("Database already contains users.")
    else:
        print("User table does not exist. Creating it now...")
        db.create_all()
        admin = User(username="admin", password="adminpass")
        user = User(username="testuser", password="password123")

        db.session.add(admin)
        db.session.add(user)
        db.session.commit()
        print("User table created and initialized with test users.")


print("Database setup complete!")
