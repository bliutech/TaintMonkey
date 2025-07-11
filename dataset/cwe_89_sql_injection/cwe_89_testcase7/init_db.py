from flask import Flask
from db import db, init_db
from sqlalchemy import Column, Integer, String


app = Flask(__name__)
init_db(app)


class User(db.Model):
   id = db.Column(db.Integer, primary_key=True)
   username = db.Column(db.String(80), unique=True, nullable=False)
   password = db.Column(db.String(120), nullable=False)

   def __repr__(self):
       return f'<User {self.username}>'

with app.app_context():
   db.create_all()
  
   if User.query.count() == 0:
       admin = User(username='admin', password='adminpass')
       user = User(username='testuser', password='password123')
      
       db.session.add(admin)
       db.session.add(user)
       db.session.commit()
       print("Database initialized with test users.")
   else:
       print("Database already contains users.")

print("Database setup complete!")