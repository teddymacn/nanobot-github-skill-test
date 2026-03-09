"""API client for external service integration."""

import os
import requests

API_KEY = os.environ.get("API_KEY")

def fetch_data(endpoint: str) -> dict:
    """Fetch data from the API."""
    url = f"https://api.example.com/{endpoint}"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    response = requests.get(url, headers=headers)
    return response.json()
