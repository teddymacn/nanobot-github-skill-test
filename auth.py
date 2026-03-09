"""
Authentication module - INTENTIONAL ISSUES FOR CODE REVIEW TEST
This file contains security vulnerabilities and code quality issues
for testing the code-reviewer and receiving-code-review skills.
"""

import sqlite3
import hashlib

# Issue 1: Hardcoded credentials (CRITICAL SECURITY)
ADMIN_PASSWORD = "admin123"
DB_PASSWORD = "super_secret_db_pass"
API_KEY = "sk-1234567890abcdef"

def authenticate_user(username, password):
    """Authenticate user - has SQL injection vulnerability"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Issue 2: SQL injection via f-string (CRITICAL SECURITY)
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    
    # Issue 3: Plaintext password comparison (SECURITY)
    if result and result[2] == password:
        return True
    return False

def hash_password(password):
    """Hash password - uses weak hashing algorithm"""
    # Issue 4: MD5 is cryptographically broken (SECURITY)
    return hashlib.md5(password.encode()).hexdigest()

def get_user_by_id(user_id):
    """Get user by ID - no input validation"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Issue 5: SQL injection, no type checking (SECURITY)
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    return cursor.fetchone()

def create_user(username, password, email):
    """Create new user - multiple issues"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Issue 6: SQL injection (SECURITY)
    # Issue 7: No input validation (SECURITY)
    # Issue 8: Storing plaintext password (SECURITY)
    query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
    cursor.execute(query)
    conn.commit()
    
    # Issue 9: Not closing connection properly
    return cursor.lastrowid

def update_user_profile(user_id, data):
    """Update user profile - dangerous pattern"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Issue 10: Mass assignment vulnerability (SECURITY)
    # Issue 11: SQL injection (SECURITY)
    for key, value in data.items():
        query = f"UPDATE users SET {key} = '{value}' WHERE id = {user_id}"
        cursor.execute(query)
    
    conn.commit()
    return True

class SessionManager:
    """Session management with multiple issues"""
    
    # Issue 12: Mutable default argument (CODE QUALITY)
    def __init__(self, sessions={}):
        self.sessions = sessions
    
    # Issue 13: No type hints (CODE QUALITY)
    def create_session(self, user_id):
        import random
        import string
        # Issue 14: Weak session token generation (SECURITY)
        token = ''.join(random.choices(string.ascii_letters, k=16))
        self.sessions[token] = user_id
        return token
    
    # Issue 15: No validation (SECURITY)
    def get_user(self, token):
        return self.sessions[token]  # Will raise KeyError if missing
    
    # Issue 16: Bare except clause (CODE QUALITY)
    def clear_session(self, token):
        try:
            del self.sessions[token]
        except:
            pass  # Silent failure

def validate_token(token):
    """Validate session token"""
    # Issue 17: Timing attack vulnerability (SECURITY)
    if token == ADMIN_PASSWORD:
        return True
    
    # Issue 18: No rate limiting (SECURITY)
    # Issue 19: No logging (CODE QUALITY)
    return False

def load_config(config_path):
    """Load configuration file"""
    # Issue 20: Path traversal vulnerability (SECURITY)
    # Issue 21: No error handling (CODE QUALITY)
    with open(config_path, 'r') as f:
        # Issue 22: eval() is dangerous - code execution (CRITICAL SECURITY)
        return eval(f.read())

# Issue 23: Global mutable state (CODE QUALITY)
CACHE = {}

def cache_user_data(user_id, data):
    """Cache user data - thread unsafe"""
    CACHE[user_id] = data  # No locking!

def get_cached_user(user_id):
    """Get cached user - no existence check"""
    return CACHE[user_id]  # KeyError if missing
