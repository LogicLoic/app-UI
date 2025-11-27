from sqlite3 import *
import io
import sqlite3
from PIL import Image, ImageTk

def image_to_blob(image: Image.Image) -> bytes:
    """Convert a PIL image to binary data."""
    with io.BytesIO() as output:
        image.save(output, format="PNG")
        return output.getvalue()

def blob_to_image(blob: bytes) -> Image.Image:
    """Return a PIL image from binary data."""
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
            name TEXT PRIMARY KEY,
            path TEXT NOT NULL,
            icon BLOB,
            tags TEXT
        )
    ''')
    conn.commit()

def add_application(conn, name, path, icon):
    """Add a new application to the database."""
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM applications WHERE name = ?', (name,))
    if cursor.fetchone()[0] > 0:
        return True  # Application already exists
    cursor.execute("""
        INSERT INTO applications (name, path, icon)
        VALUES (?, ?, ?)
    """, (name, path, image_to_blob(icon)))
    conn.commit()
    return False  # Application added successfully

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

def delete_application(conn, app_name):
    """Delete an application from the database by its name."""
    cursor = conn.cursor()
    cursor.execute('DELETE FROM applications WHERE name = ?', (app_name,))
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
    
def get_icon(conn, app_name):
    """Retrieve the icon of an application by its name."""
    cursor = conn.cursor()
    cursor.execute('SELECT icon FROM applications WHERE name = ?', (app_name,))
    result = cursor.fetchone()
    if result:
        blob = result[0]
        image_pil = Image.open(io.BytesIO(blob)).convert("RGBA")
        return image_pil
    return None

def get_tags(conn, app_name):
    """Retrieve the tags of an application by its name."""
    cursor = conn.cursor()
    cursor.execute('SELECT tags FROM applications WHERE name = ?', (app_name,))
    result = cursor.fetchone()
    if result and result[0]:
        return result[0].split(',')
    return []

def get_all_tags(conn):
    """Retrieve all unique tags from the database."""
    cursor = conn.cursor()
    cursor.execute('SELECT tags FROM applications')
    tags_set = set()
    for (tags_str,) in cursor.fetchall():
        if tags_str:
            tags = tags_str.split(',')
            tags_set.update(tags)
    return list(tags_set)

def update_tags(conn, app_name, tags):
    """Update the tags for a given application."""
    cursor = conn.cursor()
    tags_str = ','.join(tags)
    cursor.execute('UPDATE applications SET tags = ? WHERE name = ?', (tags_str, app_name))
    conn.commit()

def exists_application(conn, app_name):
    """Check if an application exists in the database by its name."""
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM applications WHERE name = ?', (app_name,))
    return cursor.fetchone()[0] > 0