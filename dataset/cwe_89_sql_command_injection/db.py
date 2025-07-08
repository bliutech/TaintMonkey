from flask import Flask
from flask_sqlalchemy import SQLAlchemy
   
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
   
db = SQLAlchemy(app)