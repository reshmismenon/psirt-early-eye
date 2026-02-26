import sqlite3

def get_user(user_id):
    # SQL Injection vulnerability - will trigger CRITICAL alert
    query = "SELECT * FROM users WHERE id = " + user_id
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()

# Hardcoded secret - will trigger HIGH alert
API_KEY = "sk-1234567890abcdefghijklmnop"
DATABASE_PASSWORD = "MySecretPassword123"
