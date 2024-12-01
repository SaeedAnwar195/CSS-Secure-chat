from flask import g
from core.models import db


def init_db(app):
    """Initialize the SQLAlchemy database"""
    db.init_app(app)

    with app.app_context():
        db.create_all()


def get_db():
    """Get database session"""
    if 'db' not in g:
        g.db = db
    return g.db


def close_db(e=None):
    """Close database session"""
    g.pop('db', None)
