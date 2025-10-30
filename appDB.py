from sqlite3 import *
import io
import sqlite3
from PIL import Image, ImageTk

def image_to_blob(image: Image.Image) -> bytes:
    """Convertit une image PIL en données binaires."""
    with io.BytesIO() as output:
        image.save(output, format="PNG")
        return output.getvalue()

def blob_to_image(blob: bytes) -> Image.Image:
    """Recrée une image PIL à partir de données binaires."""
    return Image.open(io.BytesIO(blob))

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
    cursor.execute("""
        INSERT INTO applications (name, path, icon)
        VALUES (?, ?, ?)
    """, (name, path, image_to_blob(icon)))
    conn.commit()

def get_applications(conn):
    """Retrieve all applications from the database."""
    cursor = conn.cursor()
    cursor.execute("SELECT name, path, icon FROM applications")
    apps = []
    for name, path, blob in cursor.fetchall():
        image_pil = Image.open(io.BytesIO(blob))
        image_tk = ImageTk.PhotoImage(image_pil)
        apps.append((name, path, image_tk))
    return apps

def delete_application(conn, app_id):
    """Delete an application from the database by its ID."""
    cursor = conn.cursor()
    cursor.execute('DELETE FROM applications WHERE id = ?', (app_id,))
    conn.commit()

def close_db(conn):
    """Close the database connection."""
    conn.close()
    
def get_path(conn, app_name):
    """Retrieve the path of an application by its name."""
    cursor = conn.cursor()
    cursor.execute('SELECT path FROM applications WHERE name = ?', (app_name,))
    result = cursor.fetchone()
    return result[0] if result else None