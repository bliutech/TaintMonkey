from flask_sqlalchemy import SQLAlchemy

# Create SQLAlchemy instance without binding to an app yet
db = SQLAlchemy()

def init_db(app):
    """Initialize the database with the given Flask app"""
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    
    # Create tables
    with app.app_context():
        db.create_all()