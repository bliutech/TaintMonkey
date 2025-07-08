import sqlite3
from datetime import datetime

import click
from flask import current_app, g

def get_db():
    """Returns database connection"""
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db

def close_db(e=None):
    db = g.pop('db', None)

    if db is not None:
        db.close()

def init_db():
    db = get_db()

    with current_app.open_resource('schema.sql') as f:
        data = f.read()
        if isinstance(data, bytes):
            data = data.decode('utf8')
        db.executescript(data)

@click.command('init-db')
def init_db_command():
    init_db()
    click.echo('Initialized the databse')

sqlite3.register_converter(
    "timestamp", lambda v: datetime.fromisoformat(v.decode())
)

def init_app(app):
    app.teardown_appcontext(close_db) # tells flask to call close_db when cleaning up after returning a response
    app.cli.add_command(init_db_command) # adds a new command that can be called with the flask command