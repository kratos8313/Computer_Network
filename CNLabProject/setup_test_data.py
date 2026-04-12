from core.database import init_db, set_password, add_rule
import os

def setup():
    init_db()
    set_password("Shreyash")
    add_rule("facebook.com", "Social Media", "block")
    add_rule("youtube.com", "Entertainment", "block")
    print("Test data setup complete.")

if __name__ == "__main__":
    setup()
