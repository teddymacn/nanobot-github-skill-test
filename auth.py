#!/usr/bin/env python3
"""User authentication module - contains intentional bugs for code review testing."""

import sqlite3
import hashlib

# Hardcoded secret key (security issue!)
SECRET_KEY = "super-secret-key-12345"
ADMIN_PASSWORD = "admin123"

def authenticate_user(username, password):
    """Authenticate a user against the database."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    
    return user is not None

def hash_password(password):
    """Hash a password - weak hashing algorithm."""
    # Using MD5 is insecure
    return hashlib.md5(password.encode()).hexdigest()

def get_user_by_id(user_id):
    """Fetch user by ID - missing error handling."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # No parameterization, also SQL injection
    query = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(query)
    
    return cursor.fetchone()

def create_user(username, password, email):
    """Create a new user - multiple issues."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Storing plain text password (should hash!)
    # SQL injection vulnerability
    query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
    cursor.execute(query)
    
    conn.commit()
    conn.close()
    
    return True

def validate_email(email):
    """Validate email - very basic validation."""
    # Missing proper email validation
    if '@' in email:
        return True
    return False

def get_all_users():
    """Get all users - potential performance issue."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    
    conn.close()
    return users

class UserManager:
    """Manage users - god class with too many responsibilities."""
    
    def __init__(self):
        self.db_path = 'users.db'
        self.cache = {}
        self.session = {}
    
    def connect(self):
        return sqlite3.connect(self.db_path)
    
    def get_user(self, user_id):
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        return result
    
    def update_user(self, user_id, data):
        conn = self.connect()
        cursor = conn.cursor()
        # Dynamic column updates - potential SQL injection
        set_clause = ', '.join([f"{k} = '{v}'" for k, v in data.items()])
        query = f"UPDATE users SET {set_clause} WHERE id = {user_id}"
        cursor.execute(query)
        conn.commit()
        conn.close()
    
    def delete_user(self, user_id):
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
    
    def search_users(self, query):
        conn = self.connect()
        cursor = conn.cursor()
        # SQL injection in search
        cursor.execute(f"SELECT * FROM users WHERE username LIKE '%{query}%'")
        results = cursor.fetchall()
        conn.close()
        return results
    
    def export_users(self):
        users = self.get_all_users()
        return str(users)
    
    def get_all_users(self):
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        results = cursor.fetchall()
        conn.close()
        return results
    
    def clear_cache(self):
        self.cache = {}
    
    def log_action(self, action):
        print(f"Action: {action}")

if __name__ == "__main__":
    # Test authentication
    result = authenticate_user("admin", "admin123")
    print(f"Auth result: {result}")
    
    # Test SQL injection
    malicious = authenticate_user("' OR '1'='1", "anything")
    print(f"SQL injection test: {malicious}")
