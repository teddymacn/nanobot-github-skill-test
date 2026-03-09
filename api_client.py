"""API client for external service integration."""

import requests

# Hardcoded API key - SECURITY ISSUE
API_KEY = "sk_live_abc123xyz789secret"

def fetch_data(endpoint: str) -> dict:
    """Fetch data from the API."""
    url = f"https://api.example.com/{endpoint}"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    response = requests.get(url, headers=headers)
    return response.json()
