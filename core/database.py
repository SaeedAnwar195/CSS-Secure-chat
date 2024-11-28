import sqlite3
from flask import g, current_app

class Database:
    def __init__(self, database_path=None):
        if database_path is None:
            database_path = current_app.config['DATABASE']
        self.database_path = database_path
        self.connection = None

    def connect(self):
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_db(self):
        if not hasattr(g, 'sqlite_db'):
            g.sqlite_db = self.connect()
        return g.sqlite_db

    def close_db(self, error=None):
        if hasattr(g, 'sqlite_db'):
            g.sqlite_db.close()

    def ensure_connection(self):
        if not self.connection:
            self.connection = self.connect()

    def execute_query(self, query, params=()):
        db = self.get_db()
        cursor = db.cursor()
        try:
            cursor.execute(query, params)
            db.commit()
            return True
        except sqlite3.Error as er:
            print(f"DB query execution failure: {er}")
            db.rollback()
            raise
        finally:
            cursor.close()

    def execute_vquery(self, query, *params):
        db = self.get_db()
        cursor = db.cursor()
        try:
            cursor.execute(query, params)
            db.commit()
            return cursor.lastrowid
        except sqlite3.Error as er:
            print(f"DB query execution failure: {er}")
            db.rollback()
            raise
        finally:
            cursor.close()

    def fetch_query(self, query, params=()):
        db = self.get_db()
        cursor = db.cursor()
        try:
            cursor.execute(query, params)
            result = cursor.fetchall()
            return [dict(row) for row in result]
        except sqlite3.Error as er:
            print(f"DB query execution failure: {er}")
            return None
        finally:
            cursor.close()

    def insert_query(self, query, params):
        return self.execute_query(query, params)

    def disconnect(self):
        self.close_db()
        if self.connection:
            self.connection.close()
            self.connection = None
        print("Database connection is disconnected")