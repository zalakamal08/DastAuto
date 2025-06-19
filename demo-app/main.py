from flask import Flask, request, jsonify
import sqlite3
import os
import urllib.parse

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
    raw_data = request.get_data(as_text=True)
    data = request.get_json()
    username = data.get('username', '')

    # ❌ Block if raw single quote used
    if "'" in username:
        return jsonify({"error": "Invalid character"}), 400

    # ✅ Check if %27 is in raw body
    if '%27' not in raw_data:
        return jsonify({"error": "Suspicious input rejected"}), 400

    # ✅ Decode %27 to real `'`
    username_decoded = urllib.parse.unquote(username)

    # 💀 Vulnerable query using unsafe formatting
    query = f"SELECT * FROM users WHERE username = '{username_decoded}'"

    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        return jsonify(result)
    except sqlite3.Error:
        return jsonify([])

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
