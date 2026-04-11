from core.auth import setup_password, verify_password
from core.blocker import save_sites, load_sites, unblock_all
from core.controller import start_system, stop_system

def menu():
    while True:
        print("\n1. Add site")
        print("2. Start system (Proxy + Block)")
        print("3. Stop (password required)")
        print("4. Exit")

        choice = input("Choice: ")

        if choice == "1":
            site = input("Enter domain: ")
            sites = load_sites()
            sites.append(site)
            save_sites(sites)

        elif choice == "2":
            start_system()

        elif choice == "3":
            if verify_password():
                stop_system()
                unblock_all()
                print("Stopped successfully")
            else:
                print("Wrong password")

        elif choice == "4":
            break


if __name__ == "__main__":
    setup_password()
    menu()