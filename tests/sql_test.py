import sqlite3

def get_user(user_id):
    # Fixed: Using parameterized query to prevent SQL injection
    query = "SELECT * FROM users WHERE id = ?"
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query, (user_id,))
    return cursor.fetchall()

# Fixed: Using environment variables instead of hardcoded secrets
API_KEY = os.getenv('API_KEY', '')
DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD',
