from sqlite3 import *

def connect_db(db_name):
    """Connect to the SQLite database."""
    conn = connect(db_name)
    return conn

def create_table(conn):
    """Create the applications table if it doesn't exist."""
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            path TEXT NOT NULL,
            icon BLOB
        )
    ''')
    conn.commit()

def add_application(conn, name, path, icon):
    """Add a new application to the database."""
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO applications (name, path, icon)
        VALUES (?, ?, ?)
    ''', (name, path, icon))
    conn.commit()

def get_applications(conn):
    """Retrieve all applications from the database."""
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, path, icon FROM applications')
    return cursor.fetchall()

def delete_application(conn, app_id):
    """Delete an application from the database by its ID."""
    cursor = conn.cursor()
    cursor.execute('DELETE FROM applications WHERE id = ?', (app_id,))
    conn.commit()

def close_db(conn):
    """Close the database connection."""
    conn.close()
    