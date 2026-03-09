"""
Test file for code review skills testing
This file intentionally contains various issues for review testing
"""

import os
import sqlite3
import bcrypt
import threading

# Fixed: Use environment variables instead of hardcoded credentials
DB_PASSWORD = os.environ.get('DB_PASSWORD')
API_KEY = os.environ.get('API_KEY')

def connect_to_database():
    """Connect to database with proper input validation."""
    user_input = input("Enter username: ")
    
    # Fixed: Input validation
    if not user_input or len(user_input) > 100:
        raise ValueError("Invalid username")
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Fixed: Use parameterized query to prevent SQL injection
    cursor.execute("SELECT * FROM users WHERE username = ?", (user_input,))
    return cursor.fetchall()

def process_data(data, divisor):
    """Process data with proper error handling."""
    # Fixed: Add validation and error handling
    if divisor == 0:
        raise ValueError("Cannot divide by zero")
    try:
        result = data / divisor
        return result
    except Exception as e:
        print(f"Error processing data: {e}")
        raise

def get_user_data(user_id):
    """Get user data with input validation."""
    # Fixed: Input validation
    if not isinstance(user_id, int) or user_id < 0:
        raise ValueError("Invalid user_id")
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Fixed: Use parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

# Fixed: Use thread-safe configuration class instead of global mutable state
class Config:
    def __init__(self):
        self._config = {}
        self._lock = threading.Lock()
    
    def update(self, key, value):
        with self._lock:
            self._config[key] = value
    
    def get(self, key, default=None):
        with self._lock:
            return self._config.get(key, default)

global_config = Config()

class UserManager:
    def __init__(self):
        self.users = []
    
    def add_user(self, username, password):
        # Fixed: Hash password before storing
        if not username or not password:
            raise ValueError("Username and password are required")
        
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        self.users.append({
            "username": username,
            "password_hash": hashed_password
        })
    
    def get_user(self, username):
        for user in self.users:
            if user["username"] == username:
                return user
        return None
    
    def verify_password(self, username, password):
        """Verify password against stored hash."""
        user = self.get_user(username)
        if user and "password_hash" in user:
            return bcrypt.checkpw(password.encode(), user["password_hash"])
        return False

if __name__ == "__main__":
    # Testing the functions
    # connect_to_database()  # Commented out for safety
    global_config.update("debug", True)
