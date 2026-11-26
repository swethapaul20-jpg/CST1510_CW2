from pathlib import Path
import bcrypt

USERS_FILE = Path(__file__).parent / "DATA" / "users.txt"


def hash_password(plain_password: str) -> str:
    """Turn a plain-text password into a salted bcrypt hash string."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Check a plain-text password against a stored bcrypt hash."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        stored_hash.encode("utf-8"),
    )


def load_users(filepath: Path = USERS_FILE) -> dict[str, str]:
    """Load username -> password_hash from DATA/users.txt."""
    users = {}
    if not filepath.exists():
        return users

    for line in filepath.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        username, password_hash = line.split(":", 1)
        users[username.strip()] = password_hash.strip()
    return users


def register_user(username: str, plain_password: str, filepath: Path = USERS_FILE) -> bool:
    """Register a new user if the username does not already exist."""
    username = username.strip()
    if not username or not plain_password:
        print("Username and password cannot be empty.")
        return False

    users = load_users(filepath)
    if username in users:
        print(f"User '{username}' already exists.")
        return False

    filepath.parent.mkdir(parents=True, exist_ok=True)
    hashed = hash_password(plain_password)
    with filepath.open("a", encoding="utf-8") as file:
        file.write(f"{username}:{hashed}\n")

    print(f"Registered user '{username}' in {filepath}.")
    return True


def login_user(username: str, plain_password: str, filepath: Path = USERS_FILE) -> bool:
    """Verify a user's login credentials."""
    users = load_users(filepath)
    stored_hash = users.get(username.strip())
    if stored_hash is None:
        print("Invalid username or password.")
        return False

    if verify_password(plain_password, stored_hash):
        print(f"Welcome back, {username.strip()}!")
        return True

    print("Invalid username or password.")
    return False


def main() -> None:
    while True:
        print("\n--- Week 9 Auth Menu ---")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            username = input("Enter new username: ").strip()
            password = input("Enter password: ").strip()
            register_user(username, password)
        elif choice == "2":
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            login_user(username, password)
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()