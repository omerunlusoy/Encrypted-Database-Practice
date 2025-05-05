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

from KEYS import Keys
from User import User
from SQLite_Database import Database

from AES256 import AES256
from Argon2id import Argon2id
from HMAC import HMAC

class Server:
    """
    Server manages user authentication and secure storage of user data.

    This class provides methods to handle user registration, login attempts, and management of
    user data stored in a database. It employs AES-256 encryption for securing sensitive data,
    Argon2id hashing for password protection, and HMAC hashing for unique user identification.
    The class interacts with a `Database` object for persistent data storage and retrieval.
    It supports listing users in the database with an optional decryption for administrators.

    Attributes:
        database (Database): The database instance used for storing and retrieving user data.
        aes_cipher (AES256): Cipher instance for encrypting and decrypting sensitive user data.
        argon_hasher (Argon2id): Hasher instance for password hashing.
        hmac_hasher (HMAC): Hasher instance for creating unique hashes for user identification.
    """

    def __init__(self, db_path: str = 'user_database.sqlite3', reset_database: bool = False, verbose: bool = False):
        self.database = Database(db_path, reset=reset_database)
        self.aes_cipher = AES256(Keys.AES_KEY)
        self.argon_hasher = Argon2id(Keys.ARGON_PEPPER)
        self.hmac_hasher = HMAC(Keys.HMAC_KEY)
        self.verbose = verbose

    def register(self, email: str, password: str) -> bool:
        email_hashed_ = self.hmac_hasher.hash(email)
        if self.database.is_user_in_database(email_hashed_):
            if self.verbose:
                print("E-mail is already in the database!")
            return False
        metadata_ = self.get_metadata()
        user_ = User(email_hashed_, self.aes_cipher.encrypt(email), self.aes_cipher.encrypt(str(User.USER_NUMBER)), self.argon_hasher.hash(password, email_hashed_), metadata_)
        return self.database.add_user(user_)

    def login_attempt(self, email, password) -> bool:
        email_hashed = self.hmac_hasher.hash(email)
        user = self.get_user(email)
        if user is not None:
            attempt = self.argon_hasher.verify(user.password_hashed, password, email_hashed)
            if attempt:
                if self.argon_hasher.needs_rehash(user.password_hashed):
                    user.password_hashed = self.argon_hasher.hash(password, email_hashed)
                    user.metadata = self.get_metadata()
                    self.database.update_user(user)
            return attempt
        return False

    def change_password(self, email: str, password: str) -> bool:
        user = self.get_user(email)
        if user is not None:
            user.password_hashed = self.argon_hasher.hash(password, user.email_hashed)
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

    def get_user(self, email: str = None, email_hashed: str = None) -> User | None:
        if email is not None:
            email_hashed_ = self.hmac_hasher.hash(email)
        elif email_hashed is not None:
            email_hashed_ = email_hashed
        else:
            return None
        if not self.database.is_user_in_database(email_hashed_):
            if self.verbose:
                print("E-mail is not in the database!")
            return None
        return self.database.get_user(email_hashed_)

    def update_user(self, user: User) -> bool:
        if self.get_user(user.email_hashed) is not None:
            self.database.update_user(user)
            return True
        return False

    def delete_user(self, email: str) -> bool:
        user = self.get_user(email)
        if user is not None:
            self.database.delete_user(user.email_hashed)
            return True
        return False

    def list_database(self, decrypt=False) -> None:
        if decrypt:
            database_users = self.database.get_all_users()
            line = "─" * 120
            print(f"\n{line}\n{'DATABASE (decrypted)':^120}\n{line}")
            for i_, user_ in enumerate(database_users.values()):
                print("\n" if i_ > 0 else "", end="")
                print(self.__decrypt_user(user_))
            print(line + "\n")
        else:
            self.database.list_database()

    def delete_database(self) -> None:
        self.database.delete_database()
        self.database.close()
        if self.verbose:
            print("Database deleted successfully!")

    def __decrypt_user(self, user_: User) -> str:
        return (
                f"🔑 {'email_hashed:':<20}{user_.email_hashed}\n"
                f"   {'user_id_encrypted:':<20}{self.aes_cipher.decrypt(user_.user_id_encrypted)}\n"
                f"   {'email_encrypted:':<20}{self.aes_cipher.decrypt(user_.email_encrypted)}\n"
                f"   {'password_hashed:':<20}{user_.password_hashed}\n"
                f"   {'metadata:':<20}{user_.metadata}"
            )

    def get_metadata(self) -> str:
        metadata = [
            self.aes_cipher.get_metadata(),
            self.argon_hasher.get_metadata(),
            self.hmac_hasher.get_metadata(),
            Server.__get_package_versions()
        ]
        return ';'.join(metadata)

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

print(Server().get_metadata())
