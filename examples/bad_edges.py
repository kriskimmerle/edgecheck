"""Example file with many missing edge case handlers — typical of AI-generated code."""
import json
import os
import re
import subprocess
from typing import Optional

import requests


# EC01: Optional parameter never checked for None
def greet(name: Optional[str], greeting: str = "Hello"):
    return f"{greeting}, {name.upper()}!"  # Will crash if name is None

def process(data: str | None, config: dict | None = None):
    # Uses data without None check
    return data.strip().split(",")  # Will crash if data is None


# EC02: Division without zero guard
def average(total: float, count: int) -> float:
    return total / count  # Will crash if count is 0

def split_evenly(items: list, groups: int):
    per_group = len(items) // groups  # ZeroDivisionError if groups is 0
    return [items[i:i+per_group] for i in range(0, len(items), per_group)]


# EC03: Unguarded dict key access
def get_user_email(users: dict, username: str):
    return users[username]  # KeyError if username not found

def process_config(config: dict):
    db_host = config["database"]["host"]  # Nested KeyError risk
    return db_host


# EC04: next() without default
def first_match(items: list, predicate):
    return next(item for item in items if predicate(item))  # StopIteration


# EC05: HTTP request without timeout
def fetch_data(url: str):
    response = requests.get(url)  # Can hang forever
    return response.json()

def post_data(url: str, data: dict):
    return requests.post(url, json=data)  # No timeout


# EC06: subprocess without check
def run_command(cmd: str):
    result = subprocess.run(cmd, shell=True)  # Ignores failure
    return result.stdout

def build_project():
    subprocess.call(["make", "build"])  # Ignores non-zero exit


# EC07: int/float conversion without try/except
def parse_age(age_str: str) -> int:
    return int(age_str)  # ValueError if not a number

def parse_price(price_str: str) -> float:
    return float(price_str)  # ValueError if not a number


# EC08: Long if/elif without else
def categorize(score: int) -> str:
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    # Missing else — what about score < 60?


# EC09: List index by variable
def get_nth(items: list, n: int):
    return items[n]  # IndexError if n >= len(items)


# EC10: Unpacking without length check
def parse_csv_line(line: str):
    name, age, email = line.split(",")
    return {"name": name, "age": age, "email": email}


# EC12: open() without existence guard
def read_config(path: str):
    with open(path) as f:
        return f.read()


# EC13: Regex with variable pattern
def search_logs(pattern: str, log_text: str):
    return re.findall(pattern, log_text)  # re.error if pattern is invalid


# EC14: Inconsistent return paths
def find_user(users: list, name: str):
    for user in users:
        if user["name"] == name:
            return user
    return  # Returns None — caller may not expect this


# EC17: str.split() with immediate index
def get_domain(email: str):
    return email.split("@")[1]  # IndexError if no @ in email

def get_extension(filename: str):
    return filename.split(".")[-1]  # May return whole filename if no dot


# EC19: json.loads without error handling
def parse_json(data: str):
    return json.loads(data)  # JSONDecodeError


# EC20: os.environ direct access
def get_db_url():
    return os.environ["DATABASE_URL"]  # KeyError if not set
