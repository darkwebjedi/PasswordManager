# Secure CLI Password Store & Authentication System

A lightweight, zero-dependency command-line authentication and user management tool written in Python. This project was developed during my first year of university to explore core cybersecurity principles, cryptographic storage standards, relational database interaction, and CLI interface design.

## 🔒 Security Highlights

Rather than storing plaintext credentials or raw hashes, this project applies defense-in-depth principles:

* **Key Derivation (PBKDF2):** Utilizes `hashlib.pbkdf2_hmac` with SHA-256 (or SHA-512) to derive cryptographic keys.

* **Per-User Salting:** Employs Python's `secrets` module to generate a unique 16-byte cryptographically secure salt for every password entry.

* **Key Stretching:** Enforces a minimum work factor of at least 100,000 iterations (default: 200,000) to mitigate brute-force and dictionary attacks.

* **Timing-Attack Resistance:** Validates authentication using `hmac.compare_digest` for constant-time comparisons, preventing side-channel timing leaks.

* **Secure Input Handling:** Hides user credentials during terminal input using `getpass` to prevent shoulder-surfing and avoid logging passwords in shell histories.

## ✨ Features

* **Full User Lifecycle:** Create accounts, verify credentials, change passwords securely, and delete users.

* **Relational Storage:** Stores metadata including salts, algorithms, iteration counts, and UTC timestamps using SQLite.

* **Interactive Prompts & Flags:** Includes interactive prompts for password confirmation, with support for CLI arguments and confirmation bypass flags (`--yes`).

* **Zero External Dependencies:** Built entirely with standard library modules.

## 📁 Project Structure

```
.
├── cli.py             # Command-line interface built with argparse
├── password_store.py  # Core authentication, hashing, and SQLite storage logic
├── main.py            # Quick standalone password generator utility
└── passwords.sqlite3  # SQLite database storing hashed credentials (auto-generated)

```

## 🚀 Getting Started

### Prerequisites

* Python 3.8+ (no third-party packages required)

### Installation

Clone the repository to your local machine:

```
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name

```

## 🛠️ Usage

### 1. Initialize the Database

Creates the `users` table in `passwords.sqlite3` if it does not already exist:

```
python cli.py init

```

### 2. Create a User

Prompt for a username and secure password confirmation:

```
python cli.py create <username>

```

### 3. Verify Credentials

Authenticate an existing user:

```
python cli.py verify <username>

```

### 4. Change Password

Change an existing password (requires the current password for verification):

```
python cli.py change <username>

```

### 5. Delete a User

Remove an account with a safety confirmation prompt:

```
python cli.py delete <username>

```

To skip the interactive confirmation prompt:

```
python cli.py delete <username> --yes

```

## 💻 Programmatic Usage

You can import and integrate the authentication logic directly into other Python modules:

```
from password_store import create_user, verify_user, change_password

# Register a user
create_user("alice", "SuperSecretP@ssword123")

# Check credentials
if verify_user("alice", "SuperSecretP@ssword123"):
    print("Authentication successful!")

# Update password
change_password("alice", "SuperSecretP@ssword123", "EvenStrongerP@ssword!")

```

## 🛠️ Tech Stack

* **Language:** Python 3

* **Database:** SQLite3

* **Standard Libraries:** `hashlib`, `hmac`, `secrets`, `argparse`, `getpass`, `sqlite3`
