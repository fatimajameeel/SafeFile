import sqlite3
import os
from flask import g

# The pathes to the database files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "safefile.db")


"""
Get a database connection for the current request.
If it doesn't exist yet, create it and save it in 'g'.
"""


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)  # Create a new connection
        conn.row_factory = sqlite3.Row  # Make rows behave like dictionaries
        g.db = conn  # Store the connection in the request (g)
    return g.db  # Returns the connection


"""
Close the database connection at the end of the request.
Flask will call this automatically if we register it.
"""


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()
