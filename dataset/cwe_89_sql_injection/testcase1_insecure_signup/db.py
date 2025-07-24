from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
db.session.execute


def init_db(app):
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///your_database.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

    with app.app_context():
        db.create_all()
