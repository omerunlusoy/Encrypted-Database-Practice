"""
    SQLite3 Database for managing user objects.
"""

import sqlite3
from typing import Optional, Dict
import os

from User import User


class Database:
    """
    SQLite3-backed database for User objects.

    Methods:
      - add_user
      - update_user
      - get_user
      - get_all_users
      - is_user_in_database
      - list_database (print)
    """

    def __init__(self, db_path: str = 'user_database.sqlite3', reset: bool = False):
        """
        Initialize connection to SQLite database and ensure users table exists.
        :param db_path: Path to SQLite file or ':memory:' for in-memory DB.
        """
        self.db_path = db_path
        self.conn = None
        if reset:
            self.delete_database()
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_table()

    def _create_table(self):
        create_sql = '''
        CREATE TABLE IF NOT EXISTS users (
            email_hashed TEXT PRIMARY KEY,
            email_encrypted TEXT NOT NULL,
            user_id_encrypted TEXT NOT NULL,
            password_hashed TEXT NOT NULL,
            metadata TEXT
        );
        '''
        self.conn.execute(create_sql)
        self.conn.commit()

    def add_user(self, user: User) -> bool:
        """Insert a new user record. Returns True if successful, False on constraint error."""
        sql = '''
        INSERT INTO users (email_hashed, email_encrypted, user_id_encrypted, password_hashed, metadata)
        VALUES (?, ?, ?, ?, ?)
        '''
        try:
            self.conn.execute(sql, (
                user.email_hashed,
                user.email_encrypted,
                user.user_id_encrypted,
                user.password_hashed,
                user.metadata
            ))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def update_user(self, user: User) -> None:
        """Update existing user record (by primary key)."""
        sql = '''
        UPDATE users SET
            email_encrypted = ?,
            user_id_encrypted = ?,
            password_hashed = ?,
            metadata = ?
        WHERE email_hashed = ?
        '''
        self.conn.execute(sql, (
            user.email_encrypted,
            user.user_id_encrypted,
            user.password_hashed,
            user.metadata,
            user.email_hashed
        ))
        self.conn.commit()

    def delete_user(self, email_hashed: str) -> bool:
        """Delete a user record by primary key. Returns True if a row was deleted."""
        sql = 'DELETE FROM users WHERE email_hashed = ?'
        cur = self.conn.execute(sql, (email_hashed,))
        self.conn.commit()
        return cur.rowcount > 0

    def get_user(self, email_hashed: str) -> Optional[User]:
        """Retrieve a User by email_hashed, or None if not found."""
        sql = 'SELECT * FROM users WHERE email_hashed = ?'
        cur = self.conn.execute(sql, (email_hashed,))
        row = cur.fetchone()
        if row:
            return User(
                email_hashed=row['email_hashed'],
                email_encrypted=row['email_encrypted'],
                user_id_encrypted=row['user_id_encrypted'],
                password_hashed=row['password_hashed'],
                metadata=row['metadata'] or ''
            )
        return None

    def get_all_users(self) -> Dict[str, User]:
        """Return a dict of email_hashed -> User for all records."""
        sql = 'SELECT * FROM users'
        cur = self.conn.execute(sql)
        result = {}
        for row in cur.fetchall():
            user = User(
                email_hashed=row['email_hashed'],
                email_encrypted=row['email_encrypted'],
                user_id_encrypted=row['user_id_encrypted'],
                password_hashed=row['password_hashed'],
                metadata=row['metadata'] or ''
            )
            result[user.email_hashed] = user
        return result

    def is_user_in_database(self, email_hashed: str) -> bool:
        """Return True if a user with the given email_hashed exists."""
        sql = 'SELECT 1 FROM users WHERE email_hashed = ?'
        cur = self.conn.execute(sql, (email_hashed,))
        return cur.fetchone() is not None

    def list_database(self) -> None:
        """Print all user records in a formatted table-like view."""
        users = self.get_all_users().values()
        line = '─' * 80
        print(f"\n{line}\n{'DATABASE':^80}\n{line}")
        for i, user in enumerate(users):
            if i > 0:
                print()
            print(user)
        print(line + '\n')

    def delete_database(self) -> None:
        """Close and delete the underlying database file (if not in-memory)."""
        self.close()
        if self.db_path != ':memory:' and os.path.exists(self.db_path):
            os.remove(self.db_path)

    def close(self) -> None:
        """Close the database connection."""
        if self.conn is not None:
            self.conn.close()
