"""
    Python script demonstrating a simple password manager with AES-256 encryption, Argon2id, and HMAC hashing.
    Object: Person
    Database: [Person] List
    Encryption standard: AES256
    Password Hash Function: Argon2id (Good for password storage)
    Email Hash Function: HMAC (Good for hash comparison)
"""
import importlib
import importlib.metadata

from User import User
from SQLite_Database import Database


class Server_Unencrypted:
    """
    Server manages user authentication and secure storage of user data.

    This class provides methods to handle user registration, login attempts, and management of
    user data stored in a database. It employs AES-256 encryption for securing sensitive data,
    Argon2id hashing for password protection, and HMAC hashing for unique user identification.
    The class interacts with a `Database` object for persistent data storage and retrieval.
    It supports listing users in the database with an optional decryption for administrators.

    Attributes:
        database (Database): The database instance used for storing and retrieving user data.
    """

    def __init__(self, db_path: str = 'user_database_unencrypted.sqlite3', reset_database: bool = False, verbose: bool = False):
        self.database = Database(db_path, reset=reset_database)
        self.verbose = verbose

    def register(self, email: str, password: str) -> bool:
        email_hashed = email
        if self.database.is_user_in_database(email_hashed):
            if self.verbose:
                print("E-mail is already in the database!")
            return False
        metadata = [
            Server_Unencrypted.__get_package_versions()
        ]
        metadata = ';'.join(metadata)
        user_ = User(email_hashed, email, str(User.USER_NUMBER), password, metadata)
        return self.database.add_user(user_)

    def login_attempt(self, email, password) -> bool:
        user = self.get_user(email)
        if user is not None:
            if user.password_hashed == password:
                return True
        return False

    def change_password(self, email: str, password: str) -> bool:
        user = self.get_user(email)
        if user is not None:
            user.password_hashed = password
            self.database.update_user(user)
            return True
        return False

    def change_email(self, email: str, new_email: str, password: str) -> bool:
        # make sure the email is in the database
        user = self.get_user(email)
        if user is not None:
            self.database.delete_user(user.email_hashed)
            return self.register(new_email, password)
        return False

    def get_user(self, email: str) -> User | None:
        email_hashed = email
        if not self.database.is_user_in_database(email_hashed):
            if self.verbose:
                print("E-mail is not in the database!")
            return None
        return self.database.get_user(email_hashed)

    def update_user(self, email: str, user: User) -> bool:
        if self.get_user(email) is not None:
            self.database.update_user(user)
            return True
        return False

    def delete_user(self, email: str) -> bool:
        user = self.get_user(email)
        if user is not None:
            self.database.delete_user(user.email_hashed)
            return True
        return False

    def list_database(self) -> None:
        self.database.list_database()

    def delete_database(self) -> None:
        self.database.delete_database()
        self.database.close()
        if self.verbose:
            print("Database deleted successfully!")

    @staticmethod
    def __get_package_versions() -> str:
        # 1) Define which modules you care about and, where needed, the
        #    corresponding PyPI distribution name for importlib.metadata.
        MODULES = {
            "hmac": "hmac",
            "hashlib": "hashlib",
            "sqlite3": "sqlite3",
            "os": "os",
            "base64": "base64",
            "argon2": "argon2-cffi",
            "Crypto.Cipher.AES": "pycryptodome",
            "Crypto.Protocol.KDF": "pycryptodome",
            "typing": "typing",
        }
        lines = []
        for mod_path, dist_name in MODULES.items():
            # Attempt to get the version from the distribution
            try:
                ver = importlib.metadata.version(dist_name)
            except importlib.metadata.PackageNotFoundError:
                # Fall back to importing the module and checking __version__
                try:
                    m = importlib.import_module(mod_path)
                    ver = getattr(m, "__version__", "built‑in or unknown")
                except ImportError:
                    ver = "not installed"
            lines.append(f"{mod_path}: {ver}")
        return "Python packages: (" + ", ".join(lines) + ")"
