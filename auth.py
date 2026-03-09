#!/usr/bin/env python3
"""User authentication module - security issues fixed."""

import sqlite3
import os
import re
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
import bcrypt

# Configuration from environment variables (no hardcoded secrets)
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DATABASE_PATH = os.environ.get("DATABASE_PATH", "users.db")
SESSION_EXPIRY_HOURS = int(os.environ.get("SESSION_EXPIRY_HOURS", "24"))

# Password policy constants
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
PASSWORD_COMPLEXITY_REGEX = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]'
)

# Email validation regex
EMAIL_REGEX = re.compile(
    r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
)


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


class DatabaseError(Exception):
    """Raised when database operations fail."""
    pass


def _get_db_connection() -> sqlite3.Connection:
    """Create a database connection with proper settings."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        raise DatabaseError(f"Failed to connect to database: {e}")


def _hash_password(password: str) -> str:
    """Hash password using bcrypt (secure, slow hashing)."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def _verify_password(password: str, hashed: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except (ValueError, TypeError):
        return False


def _generate_session_token() -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_urlsafe(32)


def validate_email(email: str) -> bool:
    """Validate email format using regex."""
    if not email or len(email) > 254:
        return False
    return bool(EMAIL_REGEX.match(email))


def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validate password meets security requirements.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not password:
        return False, "Password is required"
    
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    
    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f"Password must not exceed {MAX_PASSWORD_LENGTH} characters"
    
    if not PASSWORD_COMPLEXITY_REGEX.match(password):
        return False, (
            "Password must contain at least one uppercase letter, one lowercase letter, "
            "one digit, and one special character (@$!%*?&)"
        )
    
    return True, ""


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate a user against the database.
    
    Uses parameterized queries to prevent SQL injection.
    """
    if not username or not password:
        raise ValidationError("Username and password are required")
    
    conn = None
    try:
        conn = _get_db_connection()
        cursor = conn.cursor()
        
        # Use parameterized query to prevent SQL injection
        cursor.execute(
            "SELECT id, username, password_hash, email, is_active, created_at "
            "FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        
        if not user:
            return None
        
        if not user['is_active']:
            return None
        
        if not _verify_password(password, user['password_hash']):
            return None
        
        return {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'created_at': user['created_at']
        }
    
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error during authentication: {e}")
    finally:
        if conn:
            conn.close()


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Get user by ID using parameterized query."""
    if not isinstance(user_id, int) or user_id <= 0:
        raise ValidationError("Invalid user ID")
    
    conn = None
    try:
        conn = _get_db_connection()
        cursor = conn.cursor()
        
        # Use parameterized query to prevent SQL injection
        cursor.execute(
            "SELECT id, username, email, is_active, created_at "
            "FROM users WHERE id = ?",
            (user_id,)
        )
        user = cursor.fetchone()
        
        if user:
            return {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'is_active': user['is_active'],
                'created_at': user['created_at']
            }
        return None
    
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error fetching user: {e}")
    finally:
        if conn:
            conn.close()


def create_user(username: str, password: str, email: str) -> Dict[str, Any]:
    """
    Create a new user with validated input and secure password hashing.
    """
    # Validate inputs
    if not username or len(username) < 3 or len(username) > 50:
        raise ValidationError("Username must be between 3 and 50 characters")
    
    is_valid, error_msg = validate_password(password)
    if not is_valid:
        raise ValidationError(error_msg)
    
    if not validate_email(email):
        raise ValidationError("Invalid email format")
    
    conn = None
    try:
        conn = _get_db_connection()
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        )
        if cursor.fetchone():
            raise ValidationError("Username already exists")
        
        # Check if email already exists
        cursor.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        )
        if cursor.fetchone():
            raise ValidationError("Email already registered")
        
        # Hash password securely with bcrypt
        password_hash = _hash_password(password)
        created_at = datetime.utcnow().isoformat()
        
        # Use parameterized query to prevent SQL injection
        cursor.execute(
            "INSERT INTO users (username, password_hash, email, is_active, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, email, True, created_at)
        )
        conn.commit()
        
        user_id = cursor.lastrowid
        
        return {
            'id': user_id,
            'username': username,
            'email': email,
            'created_at': created_at
        }
    
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        raise DatabaseError(f"Database error creating user: {e}")
    finally:
        if conn:
            conn.close()


class SessionManager:
    """Manage user sessions with secure token-based authentication."""
    
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
    
    def create_session(self, user_id: int, username: str) -> str:
        """Create a new session for an authenticated user."""
        token = _generate_session_token()
        expiry = datetime.utcnow() + timedelta(hours=SESSION_EXPIRY_HOURS)
        
        self.sessions[token] = {
            'user_id': user_id,
            'username': username,
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': expiry.isoformat()
        }
        
        return token
    
    def validate_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate a session token and return user info if valid."""
        if not token or token not in self.sessions:
            return None
        
        session = self.sessions[token]
        expiry = datetime.fromisoformat(session['expires_at'])
        
        if datetime.utcnow() > expiry:
            self.invalidate_session(token)
            return None
        
        return {
            'user_id': session['user_id'],
            'username': session['username']
        }
    
    def invalidate_session(self, token: str) -> bool:
        """Invalidate a session token."""
        if token in self.sessions:
            del self.sessions[token]
            return True
        return False
    
    def invalidate_all_user_sessions(self, user_id: int) -> int:
        """Invalidate all sessions for a user (e.g., on password change)."""
        count = 0
        tokens_to_remove = [
            token for token, session in self.sessions.items()
            if session['user_id'] == user_id
        ]
        for token in tokens_to_remove:
            del self.sessions[token]
            count += 1
        return count


class UserRepository:
    """Repository class for user database operations (Single Responsibility)."""
    
    def __init__(self, connection: sqlite3.Connection):
        self.conn = connection
    
    def find_by_username(self, username: str) -> Optional[sqlite3.Row]:
        """Find user by username."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        return cursor.fetchone()
    
    def find_by_email(self, email: str) -> Optional[sqlite3.Row]:
        """Find user by email."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        )
        return cursor.fetchone()
    
    def find_by_id(self, user_id: int) -> Optional[sqlite3.Row]:
        """Find user by ID."""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        )
        return cursor.fetchone()
    
    def create(self, username: str, password_hash: str, email: str, 
               is_active: bool = True) -> int:
        """Create a new user and return the ID."""
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, email, is_active, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, email, is_active, datetime.utcnow().isoformat())
        )
        self.conn.commit()
        return cursor.lastrowid
    
    def update_status(self, user_id: int, is_active: bool) -> bool:
        """Update user active status."""
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE users SET is_active = ? WHERE id = ?",
            (is_active, user_id)
        )
        self.conn.commit()
        return cursor.rowcount > 0
    
    def get_all(self, limit: int = 100, offset: int = 0) -> list:
        """Get all users with pagination to prevent performance issues."""
        if limit < 1 or limit > 1000:
            limit = 100
        if offset < 0:
            offset = 0
        
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, username, email, is_active, created_at "
            "FROM users ORDER BY id LIMIT ? OFFSET ?",
            (limit, offset)
        )
        return cursor.fetchall()


class UserService:
    """Service class for user business logic (Single Responsibility)."""
    
    def __init__(self):
        self.session_manager = SessionManager()
    
    def register(self, username: str, password: str, email: str) -> Dict[str, Any]:
        """Register a new user."""
        conn = _get_db_connection()
        try:
            repo = UserRepository(conn)
            
            # Validate and check for existing users
            if not username or len(username) < 3 or len(username) > 50:
                raise ValidationError("Username must be between 3 and 50 characters")
            
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                raise ValidationError(error_msg)
            
            if not validate_email(email):
                raise ValidationError("Invalid email format")
            
            if repo.find_by_username(username):
                raise ValidationError("Username already exists")
            
            if repo.find_by_email(email):
                raise ValidationError("Email already registered")
            
            # Create user with hashed password
            password_hash = _hash_password(password)
            user_id = repo.create(username, password_hash, email)
            
            return {
                'id': user_id,
                'username': username,
                'email': email
            }
        
        finally:
            conn.close()
    
    def login(self, username: str, password: str) -> str:
        """Authenticate user and create session."""
        user_data = authenticate_user(username, password)
        
        if not user_data:
            raise AuthenticationError("Invalid username or password")
        
        return self.session_manager.create_session(
            user_data['id'],
            user_data['username']
        )
    
    def logout(self, session_token: str) -> bool:
        """Logout user by invalidating session."""
        return self.session_manager.invalidate_session(session_token)
    
    def get_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        return get_user_by_id(user_id)
    
    def deactivate_user(self, user_id: int) -> bool:
        """Deactivate a user and invalidate all their sessions."""
        conn = _get_db_connection()
        try:
            repo = UserRepository(conn)
            result = repo.update_status(user_id, False)
            if result:
                self.session_manager.invalidate_all_user_sessions(user_id)
            return result
        finally:
            conn.close()
    
    def list_users(self, page: int = 1, per_page: int = 20) -> Dict[str, Any]:
        """List users with pagination."""
        if page < 1:
            page = 1
        if per_page < 1 or per_page > 100:
            per_page = 20
        
        offset = (page - 1) * per_page
        conn = _get_db_connection()
        try:
            repo = UserRepository(conn)
            users = repo.get_all(limit=per_page, offset=offset)
            
            return {
                'users': [
                    {
                        'id': u['id'],
                        'username': u['username'],
                        'email': u['email'],
                        'is_active': u['is_active'],
                        'created_at': u['created_at']
                    }
                    for u in users
                ],
                'page': page,
                'per_page': per_page
            }
        finally:
            conn.close()


# Convenience functions for backward compatibility
_user_service = UserService()

def register_user(username: str, password: str, email: str) -> Dict[str, Any]:
    """Register a new user (convenience function)."""
    return _user_service.register(username, password, email)

def login_user(username: str, password: str) -> str:
    """Login user and return session token (convenience function)."""
    return _user_service.login(username, password)

def logout_user(session_token: str) -> bool:
    """Logout user (convenience function)."""
    return _user_service.logout(session_token)
