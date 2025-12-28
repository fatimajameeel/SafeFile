import sqlite3
from werkzeug.security import generate_password_hash
import os

#  Path to the database file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "safefile.db")

# Connect to the database
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# INSERT ROLES

roles = [
    (1, "normal_user", "Regular user who uploads and scans files"),
    (2, "soc_analyst", "SOC team member with extended privileges"),
]

for role in roles:
    cursor.execute(
        "INSERT OR IGNORE INTO role (role_id, role_name, description) VALUES (?, ?, ?)", role)

# INSERT TEST USERS


# Create hashed passwords
password1 = generate_password_hash("normalpassword")
password2 = generate_password_hash("socpassword")

users = [
    ("normal", password1, "normal@example.com", 1),  # role 1 → normal user
    ("soc", password2, "soc@example.com", 2),        # role 2 → soc analyst
]

for u in users:
    cursor.execute(
        "INSERT INTO user (username, password_hash, email, role_id) VALUES (?, ?, ?, ?)", u)

# Save (commit) changes
conn.commit()
conn.close()

print("Database seeded successfully!")
