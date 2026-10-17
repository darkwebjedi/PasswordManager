import argparse
import sys
from getpass import getpass

from password_store import (
	init_db,
	create_user,
	verify_user,
	change_password,
	delete_user,
)


def cmd_init(args: argparse.Namespace) -> int:
	init_db()
	print("Database initialized.")
	return 0


def cmd_create(args: argparse.Namespace) -> int:
	username = args.username
	password = args.password or getpass("New password: ")
	confirm = args.password or getpass("Confirm password: ")
	if password != confirm:
		print("Passwords do not match.", file=sys.stderr)
		return 1
	try:
		create_user(username, password)
		print(f"User '{username}' created.")
		return 0
	except Exception as exc:  # deliberate broad to surface message to CLI
		print(f"Error: {exc}", file=sys.stderr)
		return 1


def cmd_verify(args: argparse.Namespace) -> int:
	username = args.username
	password = args.password or getpass("Password: ")
	if verify_user(username, password):
		print("OK: credentials valid")
		return 0
	else:
		print("Invalid credentials", file=sys.stderr)
		return 2


def cmd_change(args: argparse.Namespace) -> int:
	username = args.username
	old_password = args.old or getpass("Current password: ")
	new_password = args.new or getpass("New password: ")
	confirm = args.new or getpass("Confirm new password: ")
	if new_password != confirm:
		print("New passwords do not match.", file=sys.stderr)
		return 1
	try:
		if change_password(username, old_password, new_password):
			print("Password changed.")
			return 0
		print("Invalid current password", file=sys.stderr)
		return 2
	except Exception as exc:
		print(f"Error: {exc}", file=sys.stderr)
		return 1


def cmd_delete(args: argparse.Namespace) -> int:
	username = args.username
	if args.yes:
		confirmed = True
	else:
		answer = input(f"Delete user '{username}'? Type 'yes' to confirm: ")
		confirmed = answer.strip().lower() == "yes"
	if not confirmed:
		print("Cancelled.")
		return 0
	if delete_user(username):
		print("User deleted.")
		return 0
	else:
		print("User not found.", file=sys.stderr)
		return 3


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(prog="password-store", description="Simple password storage CLI")
	sub = parser.add_subparsers(dest="command", required=True)

	# init
	sp = sub.add_parser("init", help="Initialize the database")
	sp.set_defaults(func=cmd_init)

	# create
	sp = sub.add_parser("create", help="Create a user")
	sp.add_argument("username", help="Username to create")
	sp.add_argument("--password", help="Password (avoid passing via CLI; uses prompt if omitted)")
	sp.set_defaults(func=cmd_create)

	# verify
	sp = sub.add_parser("verify", help="Verify a user's password")
	sp.add_argument("username", help="Username to verify")
	sp.add_argument("--password", help="Password (avoid passing via CLI; uses prompt if omitted)")
	sp.set_defaults(func=cmd_verify)

	# change
	sp = sub.add_parser("change", help="Change a user's password")
	sp.add_argument("username", help="Username to change")
	sp.add_argument("--old", help="Current password (prompt if omitted)")
	sp.add_argument("--new", help="New password (prompt if omitted)")
	sp.set_defaults(func=cmd_change)

	# delete
	sp = sub.add_parser("delete", help="Delete a user")
	sp.add_argument("username", help="Username to delete")
	sp.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
	sp.set_defaults(func=cmd_delete)

	return parser


def main(argv: list[str] | None = None) -> int:
	parser = build_parser()
	args = parser.parse_args(argv)
	return args.func(args)


if __name__ == "__main__":
	sys.exit(main())


