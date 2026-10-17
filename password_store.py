import os
import sqlite3
import hashlib
import hmac
import secrets
from datetime import datetime, timezone


DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "passwords.sqlite3")
DEFAULT_ALGORITHM = "sha256"
DEFAULT_ITERATIONS = 200_000
SALT_BYTES = 16
DERIVED_KEY_BYTES = 32


def _connect(db_path: str) -> sqlite3.Connection:
	conn = sqlite3.connect(db_path)
	conn.execute("PRAGMA foreign_keys = ON;")
	conn.row_factory = sqlite3.Row
	return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
	"""Create the users table if it does not exist."""
	with _connect(db_path) as conn:
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS users (
				username TEXT PRIMARY KEY,
				password_hash BLOB NOT NULL,
				salt BLOB NOT NULL,
				iterations INTEGER NOT NULL,
				algorithm TEXT NOT NULL,
				created_at TEXT NOT NULL
			);
			"""
		)
		conn.commit()


def _derive_key(password: str, salt: bytes, iterations: int, algorithm: str) -> bytes:
	return hashlib.pbkdf2_hmac(algorithm, password.encode("utf-8"), salt, iterations, dklen=DERIVED_KEY_BYTES)


def _now_iso() -> str:
	return datetime.now(timezone.utc).isoformat()


def create_user(
	username: str,
	password: str,
	db_path: str = DEFAULT_DB_PATH,
	*,
	iterations: int = DEFAULT_ITERATIONS,
	algorithm: str = DEFAULT_ALGORITHM,
) -> None:
	"""Create a new user with a securely hashed password.

	Raises ValueError if the user already exists or inputs are invalid.
	"""
	if not username or not isinstance(username, str):
		raise ValueError("username must be a non-empty string")
	if not password or not isinstance(password, str):
		raise ValueError("password must be a non-empty string")
	if iterations < 100_000:
		raise ValueError("iterations should be at least 100,000 for security")
	if algorithm not in ("sha256", "sha512"):
		raise ValueError("algorithm must be 'sha256' or 'sha512'")

	init_db(db_path)
	salt = secrets.token_bytes(SALT_BYTES)
	derived = _derive_key(password, salt, iterations, algorithm)

	with _connect(db_path) as conn:
		cur = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,))
		if cur.fetchone() is not None:
			raise ValueError("user already exists")
		conn.execute(
			"INSERT INTO users (username, password_hash, salt, iterations, algorithm, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			(username, derived, salt, iterations, algorithm, _now_iso()),
		)
		conn.commit()


def verify_user(username: str, password: str, db_path: str = DEFAULT_DB_PATH) -> bool:
	"""Verify a user's password. Returns True if valid, else False."""
	if not username or not isinstance(username, str):
		return False
	if not password or not isinstance(password, str):
		return False

	init_db(db_path)
	with _connect(db_path) as conn:
		cur = conn.execute(
			"SELECT password_hash, salt, iterations, algorithm FROM users WHERE username = ?",
			(username,),
		)
		row = cur.fetchone()
		if row is None:
			return False
		candidate = _derive_key(password, row["salt"], int(row["iterations"]), row["algorithm"])
		return hmac.compare_digest(candidate, row["password_hash"])  # constant-time


def change_password(
	username: str,
	old_password: str,
	new_password: str,
	db_path: str = DEFAULT_DB_PATH,
	*,
	iterations: int = DEFAULT_ITERATIONS,
	algorithm: str = DEFAULT_ALGORITHM,
) -> bool:
	"""Change user's password after verifying the current one. Returns True if changed."""
	if not verify_user(username, old_password, db_path):
		return False
	if not new_password or not isinstance(new_password, str):
		raise ValueError("new_password must be a non-empty string")
	if iterations < 100_000:
		raise ValueError("iterations should be at least 100,000 for security")
	if algorithm not in ("sha256", "sha512"):
		raise ValueError("algorithm must be 'sha256' or 'sha512'")

	salt = secrets.token_bytes(SALT_BYTES)
	derived = _derive_key(new_password, salt, iterations, algorithm)
	with _connect(db_path) as conn:
		updated = conn.execute(
			"UPDATE users SET password_hash = ?, salt = ?, iterations = ?, algorithm = ? WHERE username = ?",
			(derived, salt, iterations, algorithm, username),
		)
		conn.commit()
		return updated.rowcount == 1


def delete_user(username: str, db_path: str = DEFAULT_DB_PATH) -> bool:
	"""Delete a user. Returns True if a row was deleted."""
	with _connect(db_path) as conn:
		deleted = conn.execute("DELETE FROM users WHERE username = ?", (username,))
		conn.commit()
		return deleted.rowcount == 1


# --- Minimal usage example ---
#
# from password_store import init_db, create_user, verify_user, change_password
#
# init_db()  # creates passwords.sqlite3 alongside this file if not present
# create_user("alice", "S3curePa$$w0rd!")
# assert verify_user("alice", "S3curePa$$w0rd!") is True
# assert verify_user("alice", "wrong") is False
# change_password("alice", "S3curePa$$w0rd!", "EvenB3tter!")
# assert verify_user("alice", "EvenB3tter!") is True

"""wdewdw
seds

jbn
"""


