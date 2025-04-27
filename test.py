import pytest
from importlib import reload

# Adjust these imports to match your project structure
import KEYS
import SQLite_Database
import AES256
import Argon2id
import HMAC
from Server import Server  # replace with actual module name

@ pytest.fixture(autouse=True)
def set_dummy_keys(monkeypatch):
    """
    Provide consistent dummy keys for testing.
    """
    monkeypatch.setattr(KEYS.Keys, 'AES_KEY', '0'*32)
    monkeypatch.setattr(KEYS.Keys, 'ARGON_PEPPER', 'pepper_test')
    monkeypatch.setattr(KEYS.Keys, 'HMAC_KEY', 'hmac_test')

@ pytest.fixture
def server():
    """
    Create a fresh Server instance for each test, using an in-memory DB.
    """
    # Reload modules to reset class-level state
    reload(SQLite_Database)
    reload(AES256)
    reload(Argon2id)
    reload(HMAC)

    srv = Server()
    yield srv
    # Cleanup database file if created
    try:
        srv.database.delete_database()
    except Exception:
        pass
    srv.database.close()


def test_register_and_prevent_duplicates(server):
    # First registration should succeed
    assert server.register('alice@example.com', 'password123')
    # Duplicate registration should fail
    assert not server.register('alice@example.com', 'password123')


def test_login_success_and_failure(server):
    server.register('bob@example.com', 's3cr3t')
    # Correct password
    assert server.login_attempt('bob@example.com', 's3cr3t')
    # Incorrect password
    assert not server.login_attempt('bob@example.com', 'wrong')


def test_change_password_flow(server):
    server.register('carol@example.com', 'oldpass')
    # Change to new password
    assert server.change_password('carol@example.com', 'newpass')
    # Old password no longer works
    assert not server.login_attempt('carol@example.com', 'oldpass')
    # New password works
    assert server.login_attempt('carol@example.com', 'newpass')


def test_change_email_flow(server):
    server.register('dave@example.com', 'dav3pw')
    # Change email address
    assert server.change_email('dave@example.com', 'dave2@example.com', 'dav3pw')
    # Old email should no longer be in database
    assert server.get_user('dave@example.com') is None
    # New email should be present
    assert server.get_user('dave2@example.com') is not None
    # Attempt with non-existent email fails
    assert not server.change_email('nonexistent@example.com', 'x@example.com', 'pw')


def test_delete_user_flow(server):
    server.register('eve@example.com', 'ev3pw')
    # Delete existing user
    assert server.delete_user('eve@example.com')
    # Further delete attempts should fail
    assert not server.delete_user('eve@example.com')
    # Deleting non-existent user returns False
    assert not server.delete_user('noone@example.com')


def test_list_database_output(monkeypatch, capsys, server):
    server.register('frank@example.com', 'frankpw')
    server.register('grace@example.com', 'gracepw')
    # Capture non-decrypted listing
    server.list_database(decrypt=False)
    out = capsys.readouterr().out
    assert '📘 DATABASE' in out
    # Capture decrypted listing
    server.list_database(decrypt=True)
    out2 = capsys.readouterr().out
    assert 'password_hashed:' in out2


def test_server_integration(server):
    # Full flow: register, login, change password, delete
    assert server.register('heidi@example.com', 'heidipw')
    assert server.login_attempt('heidi@example.com', 'heidipw')
    assert server.change_password('heidi@example.com', 'heidipw2')
    assert server.login_attempt('heidi@example.com', 'heidipw2')
    assert server.delete_user('heidi@example.com')
    assert server.get_user('heidi@example.com') is None
