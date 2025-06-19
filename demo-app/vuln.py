from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)
DATABASE = 'users.db'

def init_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL
        )
    ''')
    users = [
        ('alice', 'alice@example.com'),
        ('bob', 'bob@example.com'),
        ('charlie', 'charlie@example.com'),
        ('david', 'david@example.com'),
        ('eve', 'eve@example.com'),
    ]
    cursor.executemany("INSERT INTO users (username, email) VALUES (?, ?)", users)
    conn.commit()
    conn.close()

@app.route('/search', methods=['POST'])
def validate_user():
    data = request.get_json()
    username = data.get('username', '')

    # 💀 Directly inject the input into the SQL query (no filters, no encoding, fully vulnerable)
    query = f"SELECT * FROM users WHERE username = '{username}'"

    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        return jsonify(result)
    except sqlite3.Error as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
