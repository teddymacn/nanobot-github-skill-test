"""
Test file for code review skills testing
This file intentionally contains various issues for review testing
"""

import os
import sqlite3

# Hardcoded credentials - BAD!
DB_PASSWORD = "super_secret_password123"
API_KEY = "sk-1234567890abcdef"

def connect_to_database():
    # SQL injection vulnerability
    user_input = input("Enter username: ")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()

def process_data(data):
    # No error handling
    result = data / 0  # Will always raise ZeroDivisionError
    return result

def get_user_data(user_id):
    # No input validation
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Another SQL injection
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

# Global mutable state - BAD!
global_config = {}

def update_config(key, value):
    global_config[key] = value  # Race condition potential

class UserManager:
    def __init__(self):
        self.users = []
    
    def add_user(self, username, password):
        # Storing plain text passwords - BAD!
        self.users.append({"username": username, "password": password})
    
    def get_user(self, username):
        for user in self.users:
            if user["username"] == username:
                return user
        return None

if __name__ == "__main__":
    # Testing the functions
    connect_to_database()
    update_config("debug", True)
