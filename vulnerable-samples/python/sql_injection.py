"""
VULNERABLE SAMPLE: SQL Injection
Kategori: OWASP A03:2021 - Injection
"""

import sqlite3


# ===== VULNERABLE: SQL Injection via string formatting =====
def get_user_by_username_vulnerable(username):
    """Mencari user berdasarkan username - RENTAN terhadap SQL Injection"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULNERABILITY: Input langsung dimasukkan ke query tanpa sanitasi
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()


# ===== VULNERABLE: SQL Injection via % formatting =====
def login_vulnerable(username, password):
    """Login function - RENTAN terhadap SQL Injection"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULNERABILITY: f-string langsung digunakan dalam query
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    return result is not None


# ===== VULNERABLE: SQL Injection via format() =====
def get_orders_by_user_vulnerable(user_id):
    """Mengambil orders berdasarkan user_id - RENTAN"""
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()

    # VULNERABILITY: .format() digunakan untuk menyusun query
    query = "SELECT * FROM orders WHERE user_id = {}".format(user_id)
    cursor.execute(query)
    return cursor.fetchall()


# ===== SECURE: Parameterized Query =====
def get_user_by_username_secure(username):
    """Mencari user berdasarkan username - AMAN menggunakan parameterized query"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # SECURE: Menggunakan parameter binding
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()


# ===== SECURE: Parameterized Login =====
def login_secure(username, password):
    """Login function - AMAN"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # SECURE: Placeholder ? untuk parameter binding
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    result = cursor.fetchone()
    return result is not None


if __name__ == "__main__":
    # Contoh serangan SQL Injection:
    # username = "admin' --"         -> bypass login
    # username = "' OR '1'='1"       -> dump semua user
    # username = "'; DROP TABLE users; --"  -> destroy data
    print("Demo SQL Injection vulnerabilities")
    print("Username input: admin' OR '1'='1' --")
