"""
    Database class for managing user objects.
    Should be replaced with SQL database.
"""

from User import User

class Database:
    """
    Manages a collection of users with operations for adding, retrieving, and
    listing stored users.

    This class represents a database abstraction where each user is uniquely
    identified by their hashed email. It provides functionality for adding new
    users, retrieving specific users using their hashed email, checking if a
    user exists in the database, and listing all stored users. Internally, it
    stores user objects in a dictionary with the hashed email as the key.
    """

    def __init__(self):
        self.users = {}

    def add_user(self, user: User) -> bool:
        self.users[user.email_hashed] = user
        return True

    def update_user(self, user: User):
        self.users[user.email_hashed] = user

    def get_user(self, email_hashed: str) -> User:
        return self.users.get(email_hashed)

    def get_all_users(self) -> dict:
        return self.users

    def is_user_in_database(self, email_hashed: str) -> bool:
        return email_hashed in self.users

    def list_database(self):
        line = "─" * 120
        print(f"\n{line}\n{'📘 DATABASE':^120}\n{line}")
        for i, user in enumerate(self.users.values()):
            print("\n" if i > 0 else "", end="")
            print(user)
        print(line + "\n")
