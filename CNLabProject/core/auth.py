import json
import hashlib
import os

CONFIG_PATH = "config/settings.json"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def setup_password():
    if not os.path.exists(CONFIG_PATH):
        pwd = input("Set password: ")
        data = {
            "password": hash_password(pwd),
            "blocked_sites": []
        }
        with open(CONFIG_PATH, "w") as f:
            json.dump(data, f)

def verify_password():

    pwd = input("Enter password: ")

    with open(CONFIG_PATH, "r") as f:
        data = json.load(f)

    if "password" not in data:
        print("Password not set!")
        return False

    return hash_password(pwd) == data["password"]