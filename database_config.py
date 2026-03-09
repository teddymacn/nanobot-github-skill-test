"""Database configuration module."""

# Database connection settings
DB_HOST = "localhost"
DB_PORT = 5432
DB_NAME = "myapp"
DB_USER = "admin"
DB_PASSWORD = "SuperSecret123!"  # Hardcoded password - security issue

def get_connection_string():
    """Build database connection string."""
    return f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
