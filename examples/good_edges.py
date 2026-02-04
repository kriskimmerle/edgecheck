"""Example file with proper edge case handling."""
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

import requests


# EC01: Optional parameter properly checked
def greet(name: Optional[str], greeting: str = "Hello"):
    if name is None:
        return f"{greeting}, stranger!"
    return f"{greeting}, {name.upper()}!"


def process(data: str | None, config: dict | None = None):
    if data is None:
        return []
    if config is None:
        config = {}
    return data.strip().split(",")


# EC02: Division with zero guard
def average(total: float, count: int) -> float:
    if count == 0:
        return 0.0
    return total / count


# EC03: Safe dict access
def get_user_email(users: dict, username: str):
    return users.get(username)


# EC04: next() with default
def first_match(items: list, predicate):
    return next((item for item in items if predicate(item)), None)


# EC05: HTTP with timeout
def fetch_data(url: str):
    response = requests.get(url, timeout=30)
    return response.json()


# EC06: Subprocess with check
def run_command(cmd: str):
    result = subprocess.run(cmd, shell=True, check=True)
    return result.stdout


# EC07: int() with try/except
def parse_age(age_str: str) -> int:
    try:
        return int(age_str)
    except ValueError:
        return 0


# EC08: if/elif with else
def categorize(score: int) -> str:
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    else:
        return "F"


# EC12: open() with guard
def read_config(path: str):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None


# EC13: Regex with error handling
def search_logs(pattern: str, log_text: str):
    try:
        return re.findall(pattern, log_text)
    except re.error:
        return []


# EC14: Consistent return paths
def find_user(users: list, name: str):
    for user in users:
        if user["name"] == name:
            return user
    return None  # Explicit None return


# EC17: split with length check
def get_domain(email: str):
    parts = email.split("@")
    if len(parts) != 2:
        return None
    return parts[1]


# EC19: json.loads with error handling
def parse_json(data: str):
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return None


# EC20: os.environ with .get()
def get_db_url():
    return os.environ.get("DATABASE_URL", "sqlite:///default.db")
