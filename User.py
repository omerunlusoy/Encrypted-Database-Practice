"""
    User class as a database object.
"""

class User:
    """
    Represents a user entity in the system.

    Encapsulates details about a user such as email and user identifiers,
    both in hashed and encrypted formats, along with password information.
    Manages a static counter for keeping track of the total number of users.

    Attributes:
        USER_NUMBER (int): A static variable tracking the number of users
            instantiated.
    """

    # Static (Class) variable
    USER_NUMBER = 0

    def __init__(self, email_hashed: str, email_encrypted: str, user_id_encrypted: str, password_hashed: str, metadata: str = ""):
        # PRIMARY KEY: email_hashed
        self.email_hashed = email_hashed
        self.email_encrypted = email_encrypted
        self.user_id_encrypted = user_id_encrypted
        self.password_hashed = password_hashed
        self.metadata = metadata
        User.USER_NUMBER += 1

    def __str__(self) -> str:
        return (
            f"🔑 {'email_hashed:':<20}{self.email_hashed}\n"
            f"   {'user_id_encrypted:':<20}{self.user_id_encrypted}\n"
            f"   {'email_encrypted:':<20}{self.email_encrypted}\n"
            f"   {'password_hashed:':<20}{self.password_hashed}\n"
            f"   {'metadata:':<20}{self.metadata}"
        )
